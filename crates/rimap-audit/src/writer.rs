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
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Number of rotated sibling files to keep on disk after a rotation.
    /// `0` means "keep none — delete every rotated sibling immediately
    /// after rotation". The default at the config layer is 5.
    pub rotate_keep: u32,
    /// Optional time-based retention in seconds. When set, rotated siblings
    /// older than `now - retention_seconds` are pruned during rotation,
    /// in addition to the count-based `rotate_keep` cap.
    pub retention_seconds: Option<u64>,
    /// If `true`, write/flush/fsync failures inside `write_record` are
    /// logged via `tracing::error!` and converted to `Ok(())` so the
    /// surrounding tool call still succeeds. The default is `false`
    /// (a write failure fails the tool call). Operators who explicitly
    /// accept losing audit records on storage failures opt in via this
    /// flag — see the audit security model docs for the trade-off.
    pub fail_open: bool,
    /// First `Seq` value this writer will allocate. Callers compute this from
    /// `read_trailing_state(path).last_seq.map(Seq::next).unwrap_or(Seq::FIRST)`
    /// before calling `open`.
    pub initial_seq: crate::ids::Seq,
}

/// Append-only JSONL writer. Construct via [`AuditWriter::open`]. Cheaply
/// cloneable — the underlying `File` and `BufWriter` live behind an
/// `Arc<Mutex<_>>`, so all clones write through the same lock.
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    rotate_keep: u32,
    retention_seconds: Option<u64>,
    fail_open: bool,
    process_id: crate::ids::ProcessId,
    suppressed_failures: Arc<AtomicU64>,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    pub(crate) bytes_written: u64,
    /// Next `Seq` value to hand out via `allocate_seq`.
    pub(crate) next_seq: crate::ids::Seq,
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
            rotate_keep: opts.rotate_keep,
            retention_seconds: opts.retention_seconds,
            fail_open: opts.fail_open,
            process_id: crate::ids::ProcessId::new_now(),
            suppressed_failures: Arc::new(AtomicU64::new(0)),
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
                next_seq: opts.initial_seq,
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

    /// The process ID this writer was opened with. Stable for the lifetime
    /// of the writer.
    #[must_use]
    pub fn process_id(&self) -> crate::ids::ProcessId {
        self.process_id
    }

    /// Allocate the next monotonic `Seq` value. Locks the inner mutex
    /// briefly; never crosses an `.await`.
    ///
    /// ## Ordering contract
    ///
    /// `allocate_seq` and `write_record` each acquire the inner lock
    /// independently. Two concurrent `log_auth` / `log_process_start`
    /// callers can therefore produce a file where physical line order
    /// disagrees with `seq` order (allocation races with the write).
    ///
    /// Readers of the audit log MUST sort by the `seq` field rather
    /// than relying on line order. `read_trailing_state` and the Sprint 3
    /// consumers (`Connection::ensure_connected`, `rimap-server::audit_init`)
    /// are all single-writer through a serializing outer mutex, so the
    /// inversion does not occur in practice today. The contract is
    /// documented here so a future multi-writer call site cannot silently
    /// break downstream readers.
    ///
    /// # Errors
    /// Returns `AuditError::Write` if the internal mutex is poisoned.
    #[must_use = "the seq value should be stored in the audit record"]
    pub fn allocate_seq(&self) -> Result<crate::ids::Seq, AuditError> {
        let mut guard = self.lock_inner()?;
        let seq = guard.next_seq;
        guard.next_seq = seq.next();
        Ok(seq)
    }

    /// Acquire the inner mutex, translating poisoning into a typed
    /// `AuditError::Write`. The poisoned-path message is deliberately
    /// generic — the mutex guards both the sequence counter and the
    /// write buffer, so "poisoned" is the only meaningful signal.
    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, Inner>, AuditError> {
        self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })
    }

    /// Allocate a seq, build an `AuditRecord` wrapping `payload`, stamp it
    /// with the writer's `process_id` and `Timestamp::now()`, and write it
    /// as a single JSONL line. All `log_*` methods route through this helper
    /// so the allocate-build-write skeleton lives in one place.
    fn emit(&self, payload: crate::record::Payload) -> Result<crate::ids::Seq, AuditError> {
        let seq = self.allocate_seq()?;
        let record = crate::record::AuditRecord {
            seq,
            ts: crate::ids::Timestamp::now(),
            process_id: self.process_id,
            payload,
        };
        self.write_record(&record)?;
        Ok(seq)
    }

    /// Build an `auth` record from `payload`, allocate a seq, and write it.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_auth(&self, payload: crate::record::Auth) -> Result<crate::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::Auth(payload))
    }

    /// Serialize `record` as one JSONL line, append it to the active file,
    /// flush the buffer, and fsync on `process_*` / `auth` / `config` kinds.
    ///
    /// If `fail_open` is `true`, write/flush/fsync failures are logged via
    /// `tracing::error!` and converted to `Ok(())`. Serialization errors are
    /// programmer errors and never suppressed regardless of `fail_open`.
    /// Suppressed failures are counted via [`Self::suppressed_failures`].
    ///
    /// # Blocking
    ///
    /// This function performs synchronous filesystem I/O: at minimum a
    /// `write_all` + `flush` + (conditionally) `fsync`, and on rotation
    /// additionally `rename`, `open`, `try_lock_exclusive`, `read_dir`,
    /// `symlink_metadata`, and `remove_file`. Callers in an async context
    /// MUST invoke this inside `tokio::task::spawn_blocking` to avoid
    /// stalling the runtime executor. The existing production call sites
    /// (`Connection::emit_auth` and future tool-audit emitters) route
    /// through `spawn_blocking` for this reason. (RUST-ASYNC-04)
    ///
    /// # Errors
    /// - [`AuditError::Serialize`] on JSON failure (never suppressed).
    /// - [`AuditError::Write`] / [`AuditError::Fsync`] / [`AuditError::Rotate`]
    ///   when `fail_open == false`.
    pub fn write_record(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        match self.write_record_inner(record) {
            Ok(()) => Ok(()),
            Err(AuditError::Serialize(e)) => {
                // Serialization failures are programmer errors, not storage
                // failures. Never suppressed regardless of fail_open.
                Err(AuditError::Serialize(e))
            }
            Err(err) if self.fail_open => {
                // Emit only the stable error code, not the full Display
                // chain which would duplicate the audit path (already in
                // the explicit `path` field below) and any filesystem
                // layout contained in an underlying io::Error. Operators
                // who want the full Display can enable TRACE-level
                // logging where `write_record_inner` records it.
                // (LOCAL-ERR-05)
                tracing::error!(
                    path = %self.path.display(),
                    error_code = %err.code(),
                    "audit write failed; fail_open=true so suppressing and continuing",
                );
                self.suppressed_failures.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn write_record_inner(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        let mut bytes = serde_json::to_vec(record).map_err(AuditError::Serialize)?;
        bytes.push(b'\n');

        let mut guard = self.lock_inner()?;

        // Rotation check happens inside the same critical section as the write.
        // This prevents two clones of AuditWriter from both observing "needs
        // rotation" and racing on the rename.
        if self.rotate_bytes > 0 && guard.bytes_written >= self.rotate_bytes {
            let (new_buf, new_len) =
                crate::rotation::rotate_file(&self.path, self.rotate_keep, self.retention_seconds)?;
            guard.buf = new_buf;
            guard.bytes_written = new_len;
            tracing::info!(path = %self.path.display(), "audit file rotated");
        }

        write_under_lock(&mut guard, &bytes, &self.path)?;

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

    /// Number of write/flush/fsync failures suppressed by `fail_open = true`
    /// since this writer was opened. Accumulated via `Relaxed` atomic
    /// increments inside `write_record`.
    ///
    /// ## Not yet wired into `process_end`
    ///
    /// The intent is for the shutdown `process_end` record to read this
    /// counter and persist it as `audit_write_failures_suppressed` so
    /// operators running `fail_open = true` can see how many records
    /// were dropped in the process's lifetime. That wiring depends on
    /// the audit lifecycle glue (`process_start`/`process_end` emission)
    /// tracked in issue #8 and is not yet in place. Today this accessor
    /// is available for ad-hoc inspection and tests; the persistent
    /// audit trail will follow when #8 lands.
    #[must_use]
    pub fn suppressed_failures(&self) -> u64 {
        self.suppressed_failures.load(Ordering::Relaxed)
    }

    /// Total bytes written through this writer since `open` (including bytes
    /// already present at open time). Used by rotation logic.
    ///
    /// # Errors
    /// Returns `AuditError::Write` if the internal mutex is poisoned.
    pub fn bytes_written(&self) -> Result<u64, AuditError> {
        let guard = self.lock_inner()?;
        Ok(guard.bytes_written)
    }

    /// Returns the current on-disk length of the active file. Used by tests.
    ///
    /// # Errors
    /// I/O error from `metadata()`.
    pub fn on_disk_len(&self) -> Result<u64, AuditError> {
        let guard = self.lock_inner()?;
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

impl AuditWriter {
    /// Build a `tool_start` record, allocate a seq, and write it. Returns
    /// the allocated `seq` — the caller should retain this value and pass
    /// it back to [`AuditWriter::log_tool_end`] as `start_seq` so the two
    /// records can be paired.
    ///
    /// `tool_start` is NOT fsynced per existing policy; see the private `needs_fsync` helper.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_tool_start(
        &self,
        tool: rimap_core::tool::ToolName,
        account: Option<&str>,
        posture_effective: &str,
        arguments_redacted: serde_json::Value,
        arguments_hash_sha256: String,
    ) -> Result<crate::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::ToolStart(
            crate::record::ToolStart {
                account: account.map(str::to_string),
                tool: tool.as_str().to_string(),
                posture_effective: posture_effective.to_string(),
                arguments_redacted,
                arguments_hash_sha256,
            },
        ))
    }

    /// Build a `tool_end` record, allocate a seq, and write it. `start_seq`
    /// must be the seq returned by the paired [`AuditWriter::log_tool_start`].
    ///
    /// `tool_end` is NOT fsynced per existing policy; see the private `needs_fsync` helper.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    #[expect(clippy::too_many_arguments, reason = "record schema is fixed")]
    pub fn log_tool_end(
        &self,
        start_seq: crate::ids::Seq,
        tool: rimap_core::tool::ToolName,
        account: Option<&str>,
        status: crate::record::ToolStatus,
        error_code: Option<rimap_core::ErrorCode>,
        duration_ms: u64,
        result_summary: crate::record::ResultSummary,
        provenance: crate::record::Provenance,
    ) -> Result<crate::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::ToolEnd(crate::record::ToolEnd {
            account: account.map(str::to_string),
            start_seq,
            tool: tool.as_str().to_string(),
            status,
            error_code: error_code.map(|c| c.as_str().to_string()),
            duration_ms,
            result_summary,
            provenance,
        }))
    }

    /// Build a `process_end` record, allocate a seq, and write it.
    /// Stamps the record with the writer's stable `process_id` and
    /// `Timestamp::now()`. Returns the allocated `seq` on success.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_process_end(
        &self,
        reason: crate::record::ProcessEndReason,
        total_tool_calls: u64,
    ) -> Result<crate::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::ProcessEnd(
            crate::record::ProcessEnd {
                reason,
                total_tool_calls,
            },
        ))
    }
}

/// Inputs to [`AuditWriter::log_process_start`]. Caller computes the
/// inode-tamper signal by passing the trailing state from
/// [`crate::self_check::read_trailing_state`] (run before `open`) and the
/// current inode (run after `open`, via [`crate::self_check::current_inode`]).
#[derive(Debug, Clone)]
pub struct ProcessStartInputs {
    /// `CARGO_PKG_VERSION` of the running binary.
    pub version: String,
    /// Git commit SHA at build time. Empty string until `vergen` lands in
    /// Sprint 5.
    pub git_commit: String,
    /// Effective base posture at startup (single-account mode).
    /// Typed at the construction seam to keep the on-disk string form
    /// in sync with the [`rimap_core::Posture`] taxonomy.
    pub posture: Option<rimap_core::Posture>,
    /// Per-account summaries (multi-account mode).
    pub accounts: Option<Vec<crate::record::AccountSummary>>,
    /// Absolute path of the loaded config file.
    pub config_path: std::path::PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Trailing state read from the audit file BEFORE this writer was opened.
    pub trailing: crate::self_check::TrailingState,
    /// Inode of the audit file as observed AFTER this writer was opened
    /// (call `crate::self_check::current_inode` on the path).
    pub current_inode: u64,
}

impl AuditWriter {
    /// Build a `process_start` record from `inputs` and the writer's own
    /// `process_id`, allocate a seq, and write it. Computes the
    /// `audit_file_inode_changed` tamper signal from
    /// `inputs.trailing.last_recorded_inode` vs `inputs.current_inode`.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_process_start(
        &self,
        inputs: ProcessStartInputs,
    ) -> Result<crate::ids::Seq, AuditError> {
        let inode_changed = inputs
            .trailing
            .last_recorded_inode
            .is_some_and(|prior| prior != inputs.current_inode);
        let payload = crate::record::ProcessStart {
            version: inputs.version,
            git_commit: inputs.git_commit,
            posture: inputs.posture.map(|p| p.as_str().to_string()),
            accounts: inputs.accounts,
            config_path: inputs.config_path,
            config_hash_sha256: inputs.config_hash_sha256,
            previous_last_seq: inputs.trailing.last_seq,
            previous_process_id: inputs.trailing.last_process_id,
            previous_file_inode: inputs.current_inode,
            audit_file_inode_changed: inode_changed,
        };
        self.emit(crate::record::Payload::ProcessStart(payload))
    }
}

/// Write `bytes` to `guard.buf`, flush, and update `bytes_written`.
fn write_under_lock(guard: &mut Inner, bytes: &[u8], path: &Path) -> Result<(), AuditError> {
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
    // bytes.len() is usize; on 64-bit targets this always fits in u64.
    // On hypothetical 128-bit targets, saturate rather than panic.
    let written = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();
        let err = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
                rotate_keep: 0,
                retention_seconds: None,
                fail_open: false,
                initial_seq: crate::ids::Seq::FIRST,
            })
            .unwrap();
        }
        // After drop, a second open succeeds.
        let _second = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
        assert_eq!(
            writer.bytes_written().unwrap(),
            writer.on_disk_len().unwrap()
        );
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
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
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
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { .. } => {}
            other => panic!("expected Locked after rotation, got {other:?}"),
        }
    }

    #[test]
    fn writer_holds_a_stable_process_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();
        let pid_a = writer.process_id();
        let pid_b = writer.process_id();
        assert_eq!(pid_a, pid_b);
    }

    #[test]
    fn writer_allocates_sequential_seqs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();
        let s1 = writer.allocate_seq().unwrap();
        let s2 = writer.allocate_seq().unwrap();
        let s3 = writer.allocate_seq().unwrap();
        assert_eq!(s1, crate::ids::Seq::FIRST);
        assert_eq!(s2, crate::ids::Seq(2));
        assert_eq!(s3, crate::ids::Seq(3));
    }

    #[test]
    fn writer_resumes_seq_from_initial_seq_option() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq(42),
        })
        .unwrap();
        assert_eq!(writer.allocate_seq().unwrap(), crate::ids::Seq(42));
        assert_eq!(writer.allocate_seq().unwrap(), crate::ids::Seq(43));
    }

    #[test]
    fn log_auth_writes_one_record_with_allocated_seq() {
        use crate::record::{Auth, AuthResult};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();

        let seq = writer
            .log_auth(Auth {
                account: None,
                result: AuthResult::Success,
                host: "127.0.0.1".to_string(),
                port: 993,
                username: "alice@example.test".to_string(),
                tls_fingerprint_sha256: Some("ab".repeat(32)),
                fingerprint_match: Some(true),
                error_code: None,
            })
            .unwrap();

        assert_eq!(seq, crate::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["fingerprint_match"], true);
    }

    #[test]
    fn log_auth_uses_writer_process_id_for_every_record() {
        use crate::record::{Auth, AuthResult};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();
        let pid = writer.process_id();

        let make = || Auth {
            account: None,
            result: AuthResult::Failure,
            host: "h".into(),
            port: 1,
            username: "u".into(),
            tls_fingerprint_sha256: None,
            fingerprint_match: None,
            error_code: Some("ERR_TLS".into()),
        };
        writer.log_auth(make()).unwrap();
        writer.log_auth(make()).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["process_id"], pid.to_string());
        assert_eq!(lines[1]["process_id"], pid.to_string());
        assert_eq!(lines[0]["seq"], 1);
        assert_eq!(lines[1]["seq"], 2);
    }

    #[test]
    fn log_process_start_populates_chain_of_history_fields() {
        use crate::self_check::TrailingState;
        use crate::writer::ProcessStartInputs;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();

        let prior_pid = crate::ids::ProcessId::new_now();
        let inputs = ProcessStartInputs {
            version: "0.0.0".to_string(),
            git_commit: String::new(),
            posture: Some(rimap_core::Posture::DraftSafe),
            accounts: None,
            config_path: std::path::PathBuf::from("/tmp/config.toml"),
            config_hash_sha256: "ab".repeat(32),
            trailing: TrailingState {
                last_seq: Some(crate::ids::Seq(99)),
                last_process_id: Some(prior_pid),
                last_recorded_inode: Some(7777),
            },
            current_inode: 8888,
        };
        let seq = writer.log_process_start(inputs).unwrap();
        assert_eq!(seq, crate::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], "process_start");
        assert_eq!(v["previous_last_seq"], 99);
        assert_eq!(v["previous_process_id"], prior_pid.to_string());
        assert_eq!(v["previous_file_inode"], 8888);
        assert_eq!(v["audit_file_inode_changed"], true);
    }

    #[test]
    fn log_process_end_writes_valid_record() {
        use crate::record::ProcessEndReason;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();

        let seq = writer.log_process_end(ProcessEndReason::Eof, 42).unwrap();
        assert_eq!(seq, crate::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert_eq!(v["reason"], "eof");
        assert_eq!(v["total_tool_calls"], 42);
    }

    #[test]
    fn log_process_end_uses_writer_process_id() {
        use crate::record::ProcessEndReason;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();
        let pid = writer.process_id();

        writer
            .log_process_end(ProcessEndReason::SignalTerm, 7)
            .unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["process_id"], pid.to_string());
        assert_eq!(v["reason"], "signal_term");
    }

    #[test]
    fn log_process_start_marks_inode_unchanged_when_matching() {
        use crate::self_check::TrailingState;
        use crate::writer::ProcessStartInputs;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::ids::Seq::FIRST,
        })
        .unwrap();

        let inputs = ProcessStartInputs {
            version: "0.0.0".to_string(),
            git_commit: String::new(),
            posture: Some(rimap_core::Posture::DraftSafe),
            accounts: None,
            config_path: std::path::PathBuf::from("/tmp/c.toml"),
            config_hash_sha256: "00".repeat(32),
            trailing: TrailingState {
                last_seq: None,
                last_process_id: None,
                last_recorded_inode: Some(4242),
            },
            current_inode: 4242,
        };
        writer.log_process_start(inputs).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["audit_file_inode_changed"], false);
    }
}
