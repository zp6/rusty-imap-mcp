//! Exclude audit directories from macOS Time Machine backups.
//!
//! On macOS, calls `tmutil addexclusion -p <path>`. No-op on other
//! platforms. Best-effort: logs a warning on failure.

use std::path::Path;

/// Exclude `path` from Time Machine backups (macOS only).
/// Best-effort: logs a warning on failure, never propagates errors.
pub fn exclude_from_backup(path: &Path) {
    #[cfg(target_os = "macos")]
    exclude_macos(path);

    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

#[cfg(target_os = "macos")]
fn exclude_macos(path: &Path) {
    match std::process::Command::new("/usr/bin/tmutil")
        .args(["addexclusion", "-p"])
        .arg(path)
        .output()
    {
        Ok(output) if output.status.success() => {
            tracing::debug!(
                path = %path.display(),
                "excluded audit directory from Time Machine backups",
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                path = %path.display(),
                status = %output.status,
                stderr = %stderr.trim(),
                "tmutil addexclusion failed; audit directory \
                 may appear in Time Machine backups",
            );
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to run tmutil; audit directory \
                 may appear in Time Machine backups",
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn exclude_from_backup_does_not_panic() {
        exclude_from_backup(Path::new("/nonexistent/path"));
    }

    #[test]
    fn exclude_from_backup_handles_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        exclude_from_backup(tmp.path());
    }
}
