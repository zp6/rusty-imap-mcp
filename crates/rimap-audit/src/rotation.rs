//! Rotation-under-lock logic. See design spec §10 "File handling & locking".

use std::fs::{File, OpenOptions};
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

/// Perform the rename + new-file dance. Returns the freshly-locked `File`
/// for the new active path (with an empty `BufWriter` wrapping it).
///
/// # Errors
/// Any I/O error during `rename`, `open`, or `try_lock_exclusive` surfaces as
/// [`AuditError::Rotate`] with a descriptive `reason`.
pub fn rotate_file(active: &Path) -> Result<(BufWriter<File>, u64), AuditError> {
    let dst = rotated_path(active, OffsetDateTime::now_utc());
    std::fs::rename(active, &dst).map_err(|source| AuditError::Rotate {
        path: active.to_path_buf(),
        reason: format!("rename to {}: {source}", dst.display()),
    })?;

    let new_file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(active)
        .map_err(|source| AuditError::Rotate {
            path: active.to_path_buf(),
            reason: format!("open fresh file: {source}"),
        })?;

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

    use time::macros::datetime;

    use crate::rotation::rotated_path;

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
}
