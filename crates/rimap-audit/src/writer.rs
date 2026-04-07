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

use std::fs::{File, OpenOptions};
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
    // Used by write_record (Task 16) and rotate (Task 17).
    #[expect(dead_code, reason = "used by write_record added in Task 16")]
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    // Used by write_record (Task 16) and rotate (Task 17).
    #[expect(dead_code, reason = "used by write_record added in Task 16")]
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    #[expect(dead_code, reason = "used by write_record added in Task 16")]
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
        if let Some(parent) = opts.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                    path: opts.path.clone(),
                    source,
                })?;
                set_parent_mode_0700(parent);
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&opts.path)
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?;
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
}

#[cfg(unix)]
fn set_file_mode_0600(file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = file.set_permissions(perms);
    }
}

#[cfg(not(unix))]
fn set_file_mode_0600(_file: &File) {}

#[cfg(unix)]
fn set_parent_mode_0700(parent: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(parent) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(parent, perms);
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
}
