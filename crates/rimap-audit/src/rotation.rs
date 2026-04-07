//! Rotation-under-lock logic. See design spec §10 "File handling & locking".

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use time::OffsetDateTime;

use crate::error::AuditError;

/// Compute the rotation destination path: `<active>.<rfc3339-timestamp>`.
/// Example: `audit.jsonl.2026-04-07T14-22-01.000Z`.
#[must_use]
pub fn rotated_path(active: &Path, now: OffsetDateTime) -> PathBuf {
    let stamp = format!(
        "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    );
    let mut name = active.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(stamp);
    active.with_file_name(name)
}

/// Resolve a non-colliding rotation destination, trying the millisecond-stamped
/// path first and appending `-1`, `-2`, … on collision. Returns the first path
/// that does not yet exist.
///
/// Two rotations within the same millisecond — possible on fast hardware with
/// a small `rotate_bytes` — would otherwise clobber each other because
/// `std::fs::rename` overwrites the destination on Unix. The collision counter
/// makes the rename safe regardless of timestamp resolution.
fn unique_rotated_path(active: &Path, now: OffsetDateTime) -> PathBuf {
    let base = rotated_path(active, now);
    if !base.exists() {
        return base;
    }
    let base_name = base.file_name().unwrap_or_default().to_os_string();
    for counter in 1_u32..=u32::MAX {
        let mut candidate_name = base_name.clone();
        candidate_name.push(format!("-{counter}"));
        let candidate = base.with_file_name(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    // u32::MAX rotations within one millisecond is implausible; fall back to
    // the base name (overwriting) rather than panicking.
    base
}

/// Perform the rename + new-file dance. Returns the freshly-locked `File`
/// for the new active path (with an empty `BufWriter` wrapping it).
///
/// # Errors
/// Any I/O error during `rename`, `open`, or `try_lock_exclusive` surfaces as
/// [`AuditError::Rotate`] with a descriptive `reason`.
pub fn rotate_file(active: &Path) -> Result<(BufWriter<File>, u64), AuditError> {
    let dst = unique_rotated_path(active, OffsetDateTime::now_utc());
    std::fs::rename(active, &dst).map_err(|source| AuditError::Rotate {
        path: active.to_path_buf(),
        reason: format!("rename to {}: {source}", dst.display()),
    })?;

    let new_file = crate::fs_ext::writer_open_options()
        .open(active)
        .map_err(|source| AuditError::Rotate {
            path: active.to_path_buf(),
            reason: format!("open fresh file: {source}"),
        })?;

    crate::writer::set_file_mode_0600(&new_file);

    // Race window: between `open` and `try_lock_exclusive` a concurrent
    // AuditWriter::open on the same path could grab the fresh inode's lock
    // first, in which case our try_lock_exclusive returns Ok(false) and we
    // surface AuditError::Rotate. This is the documented failure mode and is
    // expected to be rare (only relevant if a supervisor restarts the server
    // mid-rotation).
    match FileExt::try_lock_exclusive(&new_file) {
        Ok(true) => {}
        Ok(false) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: "fresh file unexpectedly locked by another process".to_string(),
            });
        }
        Err(e) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: format!("lock fresh file: {e}"),
            });
        }
    }

    Ok((BufWriter::new(new_file), 0))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;
    use time::macros::datetime;

    use crate::rotation::{rotated_path, unique_rotated_path};

    #[test]
    fn rotated_path_appends_utc_stamp() {
        let active = Path::new("/tmp/audit.jsonl");
        let now = datetime!(2026-04-07 14:22:01.234 UTC);
        let r = rotated_path(active, now);
        assert_eq!(
            r.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z",
        );
    }

    #[test]
    fn unique_rotated_path_appends_counter_when_base_exists() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        let now = datetime!(2026-04-07 14:22:01.234 UTC);

        // Pre-create the base rotated path so the first call has to skip it.
        let base = rotated_path(&active, now);
        std::fs::write(&base, b"existing").unwrap();

        let p1 = unique_rotated_path(&active, now);
        assert_eq!(
            p1.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z-1",
        );

        // Pre-create -1 too; next call should pick -2.
        std::fs::write(&p1, b"existing").unwrap();
        let p2 = unique_rotated_path(&active, now);
        assert_eq!(
            p2.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z-2",
        );
    }
}
