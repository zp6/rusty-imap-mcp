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
    use std::path::PathBuf;

    /// Resolve the socket path for the current user.
    ///
    /// Always succeeds: prefers `$XDG_RUNTIME_DIR` when set and absolute,
    /// otherwise falls back to `$TMPDIR/<uid>` (defaulting to `/tmp`).
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
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
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
mod tests {
    use super::*;

    #[test]
    fn uses_xdg_runtime_dir_when_set() {
        temp_env::with_var("XDG_RUNTIME_DIR", Some("/run/user/1000"), || {
            let ep = resolve();
            assert_eq!(ep.as_str(), "/run/user/1000/rusty-imap-mcp/daemon.sock");
        });
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
}
