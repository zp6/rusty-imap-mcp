//! Resolve and open the daemon log file the service path redirects
//! `tracing` events to.

#![cfg(windows)]

use std::path::PathBuf;

/// Subdirectory under the resolved local-app-data root.
const APP_SUBDIR: &str = "rusty-imap-mcp";

/// File name for daemon trace output.
const LOG_FILE_NAME: &str = "daemon.log";

/// Resolve the log directory for the current user under
/// `%LOCALAPPDATA%`. Errors if the env var is unset or the resulting
/// path is invalid.
fn resolve_log_dir() -> std::io::Result<PathBuf> {
    #[cfg(test)]
    if let Ok(override_path) = std::env::var("RIMAP_TRACING_SINK_OVERRIDE") {
        return Ok(PathBuf::from(override_path).join(APP_SUBDIR));
    }
    let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "LOCALAPPDATA environment variable is not set",
        )
    })?;
    Ok(PathBuf::from(local).join(APP_SUBDIR))
}

/// Resolve the full path of `daemon.log` without creating anything.
pub(crate) fn log_file_path() -> std::io::Result<PathBuf> {
    Ok(resolve_log_dir()?.join(LOG_FILE_NAME))
}

/// Ensure the log directory exists and open `daemon.log` append-only,
/// non-inheritable. Returns the open file handle.
pub(crate) fn open_log_file() -> std::io::Result<std::fs::File> {
    let path = log_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write as _;

    #[test]
    fn open_log_file_creates_parent_and_opens_appendable() {
        let tmp = tempfile::tempdir().unwrap();
        let path_owned = tmp.path().to_path_buf();
        temp_env::with_var(
            "RIMAP_TRACING_SINK_OVERRIDE",
            Some(path_owned.as_os_str()),
            || {
                let mut f = super::open_log_file().unwrap();
                f.write_all(b"hello\n").unwrap();
                drop(f);
                let mut f2 = super::open_log_file().unwrap();
                f2.write_all(b"world\n").unwrap();
                drop(f2);
                let final_path = path_owned
                    .join(super::APP_SUBDIR)
                    .join(super::LOG_FILE_NAME);
                let bytes = std::fs::read(&final_path).unwrap();
                assert_eq!(bytes, b"hello\nworld\n");
            },
        );
    }

    #[test]
    fn log_file_path_uses_override() {
        let tmp = tempfile::tempdir().unwrap();
        let path_owned = tmp.path().to_path_buf();
        temp_env::with_var(
            "RIMAP_TRACING_SINK_OVERRIDE",
            Some(path_owned.as_os_str()),
            || {
                let p = super::log_file_path().unwrap();
                assert!(p.starts_with(&path_owned));
                assert!(p.ends_with(super::LOG_FILE_NAME));
            },
        );
    }
}
