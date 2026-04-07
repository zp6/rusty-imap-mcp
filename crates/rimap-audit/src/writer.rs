//! Exclusively-locked, append-only JSONL writer. See design spec §10 "File
//! handling & locking".
//!
//! ## Invariants
//! - One `AuditWriter` holds `LOCK_EX` on its active file for its entire
//!   lifetime. The lock is released implicitly on drop (OS cleanup — no
//!   explicit `unlock()` call required).
//! - `try_lock_exclusive` is non-blocking; a second writer against the same
//!   path fails immediately with [`AuditError::Locked`].
//! - Per-record writes go through a buffered writer, flushed after each
//!   record. `fsync` is only issued on `process_*` / `auth` records
//!   (Task 16 wires that).

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs4::fs_std::FileExt;

use crate::error::AuditError;

/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
}

/// Append-only JSONL writer. Construct via [`AuditWriter::open`]. Cheaply
/// cloneable — the underlying `File` and `BufWriter` live behind an
/// `Arc<Mutex<_>>`, so all clones write through the same lock.
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    pub(crate) bytes_written: u64,
}

impl AuditWriter {
    /// Open or create the audit file at `opts.path`, acquire an exclusive
    /// non-blocking lock, and return the writer.
    ///
    /// # Errors
    /// - [`AuditError::ParentDir`] if the parent directory cannot be created.
    /// - [`AuditError::Open`] on I/O failure during `OpenOptions::open`.
    /// - [`AuditError::Locked`] if another process already holds the lock.
    pub fn open(opts: &AuditOptions) -> Result<Self, AuditError> {
        if let Some(parent) = opts.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                path: opts.path.clone(),
                source,
            })?;
            set_parent_mode_0700(parent);
        }
        let file = crate::fs_ext::writer_open_options()
            .open(&opts.path)
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?;
        // Defense in depth: re-assert mode in case the file existed pre-open
        // with wider perms. When the file is newly created, `writer_open_options`
        // already sets 0600 atomically; this is a no-op in that case.
        set_file_mode_0600(&file);

        match FileExt::try_lock_exclusive(&file) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AuditError::Locked {
                    path: opts.path.clone(),
                });
            }
            Err(source) => {
                return Err(AuditError::Open {
                    path: opts.path.clone(),
                    source,
                });
            }
        }

        let bytes_written = file
            .metadata()
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?
            .len();

        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
            })),
        })
    }

    /// The active audit file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rotation threshold in bytes. `0` disables rotation.
    #[must_use]
    pub fn rotate_bytes(&self) -> u64 {
        self.rotate_bytes
    }

    /// Serialize `record` as one JSONL line, append it to the active file,
    /// flush the buffer, and fsync on `process_*` / `auth` / `config` kinds.
    ///
    /// # Errors
    /// - [`AuditError::Serialize`] on JSON failure.
    /// - [`AuditError::Write`] on I/O failure during `write_all` / `flush`.
    /// - [`AuditError::Fsync`] on `fsync` failure.
    pub fn write_record(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        let mut bytes = serde_json::to_vec(record).map_err(AuditError::Serialize)?;
        bytes.push(b'\n');

        let mut guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })?;

        // Rotation check happens inside the same critical section as the write.
        // This prevents two clones of AuditWriter from both observing "needs
        // rotation" and racing on the rename.
        if self.rotate_bytes > 0 && guard.bytes_written >= self.rotate_bytes {
            let (new_buf, new_len) = crate::rotation::rotate_file(&self.path)?;
            guard.buf = new_buf;
            guard.bytes_written = new_len;
            tracing::info!(path = %self.path.display(), "audit file rotated");
        }

        do_write_locked(&mut guard, &bytes, &self.path)?;

        if needs_fsync(&record.payload) {
            guard
                .buf
                .get_ref()
                .sync_data()
                .map_err(|source| AuditError::Fsync {
                    path: self.path.clone(),
                    source,
                })?;
        }

        Ok(())
    }

    /// Total bytes written through this writer since `open` (including bytes
    /// already present at open time). Used by rotation logic.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.inner
            .lock()
            .map(|g| g.bytes_written)
            .unwrap_or_default()
    }

    /// Returns the current on-disk length of the active file. Used by tests.
    ///
    /// # Errors
    /// I/O error from `metadata()`.
    pub fn on_disk_len(&self) -> Result<u64, AuditError> {
        let guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })?;
        let meta = guard
            .buf
            .get_ref()
            .metadata()
            .map_err(|source| AuditError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(meta.len())
    }
}

/// Write `bytes` to `guard.buf`, flush, and update `bytes_written`.
fn do_write_locked(guard: &mut Inner, bytes: &[u8], path: &Path) -> Result<(), AuditError> {
    use std::io::Write;

    guard
        .buf
        .write_all(bytes)
        .map_err(|source| AuditError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    guard.buf.flush().map_err(|source| AuditError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    let written =
        u64::try_from(bytes.len()).unwrap_or_else(|_| unreachable!("bytes.len() fits in u64"));
    guard.bytes_written = guard.bytes_written.saturating_add(written);
    Ok(())
}

fn needs_fsync(payload: &crate::record::Payload) -> bool {
    use crate::record::Payload;
    match payload {
        Payload::ProcessStart(_)
        | Payload::ProcessEnd(_)
        | Payload::Auth(_)
        | Payload::Config(_) => true,
        Payload::ToolStart(_) | Payload::ToolEnd(_) => false,
    }
}

#[cfg(unix)]
pub(crate) fn set_file_mode_0600(file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        if let Err(err) = file.set_permissions(perms) {
            tracing::warn!(error = %err, "failed to set audit file mode 0600");
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn set_file_mode_0600(_file: &File) {}

#[cfg(unix)]
fn set_parent_mode_0700(parent: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(parent) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        if let Err(err) = std::fs::set_permissions(parent, perms) {
            tracing::warn!(error = %err, "failed to set audit parent dir mode 0700");
        }
    }
}

#[cfg(not(unix))]
fn set_parent_mode_0700(_parent: &Path) {}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    use crate::error::AuditError;
    use crate::writer::{AuditOptions, AuditWriter};

    #[test]
    fn open_creates_file_and_acquires_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        assert_eq!(writer.path(), path);
        assert!(path.exists());
    }

    #[test]
    fn second_open_against_same_path_fails_with_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _first = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let err = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { path: p } => assert_eq!(p, path),
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn drop_releases_the_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let _first = AuditWriter::open(&AuditOptions {
                path: path.clone(),
                rotate_bytes: 0,
            })
            .unwrap();
        }
        // After drop, a second open succeeds.
        let _second = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
    }

    #[test]
    fn open_creates_missing_parent_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");
        let _writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn write_record_appends_one_jsonl_line() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();

        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };
        writer.write_record(&rec).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn write_record_tracks_bytes_written() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }
        assert_eq!(writer.bytes_written(), writer.on_disk_len().unwrap());
    }

    #[test]
    fn rotation_creates_new_file_and_preserves_contents() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        let mut rotated = 0;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("audit.jsonl.") {
                rotated += 1;
            }
        }
        assert!(
            rotated >= 1,
            "expected at least one rotated file, got {rotated}"
        );

        let mut all = String::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("audit.jsonl")
            {
                all.push_str(&std::fs::read_to_string(&p).unwrap());
            }
        }
        let seqs: std::collections::BTreeSet<u64> = all
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("seq").and_then(serde_json::Value::as_u64))
            .collect();
        assert_eq!(seqs, (1_u64..=5).collect::<std::collections::BTreeSet<_>>(),);
        assert_eq!(
            seqs.len(),
            5,
            "expected exactly 5 distinct seqs across all files"
        );
        assert!(path.exists(), "active file still exists after rotation");
    }

    #[test]
    fn after_rotation_the_lock_still_blocks_new_writers() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        let err = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { .. } => {}
            other => panic!("expected Locked after rotation, got {other:?}"),
        }
    }
}
