//! Resolve the daemon's socket / named-pipe path per platform.
//!
//! Linux: `$XDG_RUNTIME_DIR/rusty-imap-mcp/daemon.sock` (if `XDG_RUNTIME_DIR`
//! is set) or `$TMPDIR/rusty-imap-mcp-<uid>/daemon.sock` (fallback).
//! macOS: always `$TMPDIR/rusty-imap-mcp-<uid>/daemon.sock`.
//! Windows: `\\.\pipe\rusty-imap-mcp-<user>`.

use std::path::PathBuf;

/// Opaque resolved endpoint — a filesystem path on Unix, a pipe name on
/// Windows. Kept opaque so callers cannot accidentally treat a pipe name
/// as a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPath(String);

impl EndpointPath {
    /// Canonical string form — a filesystem path on Unix, a pipe name
    /// (starting with `\\.\pipe\`) on Windows.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Filesystem path form. On Windows, returns `None` because a pipe
    /// name is not a filesystem path.
    #[must_use]
    pub fn as_path_buf(&self) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            Some(PathBuf::from(&self.0))
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

#[cfg(unix)]
mod unix_resolver {
    use super::EndpointPath;
    use std::path::{Path, PathBuf};

    /// Resolve the socket path for the current user.
    ///
    /// Always succeeds: prefers `$XDG_RUNTIME_DIR` when set, absolute,
    /// and matching the freedesktop ownership + mode contract (owner =
    /// current uid, mode = 0700, not a symlink). Otherwise falls back
    /// to `$TMPDIR/rusty-imap-mcp-<uid>` (defaulting to `/tmp`).
    #[must_use]
    pub fn resolve() -> EndpointPath {
        if let Some(dir) = xdg_runtime_dir() {
            return EndpointPath(
                dir.join("rusty-imap-mcp")
                    .join("daemon.sock")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        let dir = tmp_fallback();
        EndpointPath(dir.join("daemon.sock").to_string_lossy().into_owned())
    }

    fn xdg_runtime_dir() -> Option<PathBuf> {
        let raw = std::env::var_os("XDG_RUNTIME_DIR")?;
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return None;
        }
        let our_uid = rustix::process::geteuid().as_raw();
        match verify_runtime_dir(&path, our_uid) {
            Ok(()) => Some(path),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "XDG_RUNTIME_DIR rejected; falling back to per-user tempdir",
                );
                None
            }
        }
    }

    /// Verify that `dir` satisfies the freedesktop `XDG_RUNTIME_DIR`
    /// contract: not a symlink, owned by `our_uid`, mode 0700.
    pub(super) fn verify_runtime_dir(dir: &Path, our_uid: u32) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let meta = std::fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("XDG_RUNTIME_DIR {} is a symlink", dir.display()),
            ));
        }
        if meta.uid() != our_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "XDG_RUNTIME_DIR {} is owned by uid {}, not {}",
                    dir.display(),
                    meta.uid(),
                    our_uid,
                ),
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "XDG_RUNTIME_DIR {} has mode {mode:o}, require 0700",
                    dir.display(),
                ),
            ));
        }
        Ok(())
    }

    fn tmp_fallback() -> PathBuf {
        let uid = rustix::process::geteuid().as_raw();
        let tmp = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        tmp.join(format!("rusty-imap-mcp-{uid}"))
    }
}

#[cfg(windows)]
mod windows_resolver {
    use super::EndpointPath;

    /// Resolution error.
    #[derive(Debug, thiserror::Error)]
    pub enum ResolveError {
        /// Could not determine the current user name.
        #[error("could not determine current user: USERNAME env unset")]
        NoUserName,
    }

    /// Resolve the named-pipe name for the current user.
    ///
    /// # Errors
    /// Returns an error if the `USERNAME` environment variable is unset.
    pub fn resolve() -> Result<EndpointPath, ResolveError> {
        let user = current_user_name().ok_or(ResolveError::NoUserName)?;
        Ok(EndpointPath(format!(r"\\.\pipe\rusty-imap-mcp-{user}")))
    }

    fn current_user_name() -> Option<String> {
        std::env::var("USERNAME").ok()
    }
}

#[cfg(unix)]
pub use unix_resolver::resolve;
#[cfg(windows)]
pub use windows_resolver::{ResolveError, resolve};

#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::unix_resolver::verify_runtime_dir;
    use super::*;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    #[test]
    fn uses_xdg_runtime_dir_when_set() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir_str = dir.path().to_string_lossy().into_owned();
        let expected = format!("{dir_str}/rusty-imap-mcp/daemon.sock");
        temp_env::with_var("XDG_RUNTIME_DIR", Some(&dir_str), || {
            let ep = resolve();
            assert_eq!(ep.as_str(), expected);
        });
    }

    #[test]
    fn falls_back_when_xdg_runtime_dir_has_wrong_mode() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir_str = dir.path().to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("XDG_RUNTIME_DIR", Some(dir_str.as_str())),
                ("TMPDIR", Some("/alt-tmp")),
            ],
            || {
                let ep = resolve();
                assert!(ep.as_str().starts_with("/alt-tmp/rusty-imap-mcp-"));
                assert!(ep.as_str().ends_with("/daemon.sock"));
            },
        );
    }

    #[test]
    fn falls_back_to_tmpdir_when_xdg_unset() {
        temp_env::with_vars(
            [("XDG_RUNTIME_DIR", None), ("TMPDIR", Some("/alt-tmp"))],
            || {
                let ep = resolve();
                assert!(ep.as_str().starts_with("/alt-tmp/rusty-imap-mcp-"));
                assert!(ep.as_str().ends_with("/daemon.sock"));
            },
        );
    }

    #[test]
    fn rejects_xdg_runtime_dir_owned_by_other_uid() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let wrong_uid = rustix::process::geteuid().as_raw().wrapping_add(1);
        let err = verify_runtime_dir(dir.path(), wrong_uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_xdg_runtime_dir_wrong_mode() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let our_uid = rustix::process::geteuid().as_raw();
        let err = verify_runtime_dir(dir.path(), our_uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn accepts_xdg_runtime_dir_0700_and_ours() {
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let our_uid = rustix::process::geteuid().as_raw();
        verify_runtime_dir(dir.path(), our_uid).unwrap();
    }

    #[test]
    fn rejects_symlinked_xdg_runtime_dir() {
        let base = TempDir::new().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let our_uid = rustix::process::geteuid().as_raw();
        let err = verify_runtime_dir(&link, our_uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
