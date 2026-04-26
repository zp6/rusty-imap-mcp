//! Daemon socket-directory preparation — thin wrapper over
//! [`rimap_core::fs::ensure_tight_dir`].
//!
//! The production primitive lives in `rimap-core::fs` so the audit writer
//! can share it. This module retains its crate-local name for the one
//! daemon caller (`main.rs`) and continues to host the socket-flavoured
//! integration tests that exercise the full code path through rustix.

#![cfg(unix)]

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// Ensure the daemon socket's parent directory exists, is owned by the
/// running user, and is mode 0700 — delegating to the shared helper.
///
/// # Errors
/// Propagates every error from [`rimap_core::fs::ensure_tight_dir`].
pub fn prepare_socket_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
    rimap_core::fs::ensure_tight_dir(dir, our_uid)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    //! The integration tests here exercise the same code paths as the
    //! `rimap_core::fs::tests` unit tests; both are kept because the
    //! socket-setup caller is a security-sensitive code path and bisecting
    //! a future regression is easier when both test suites are green.

    use super::prepare_socket_dir;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    fn our_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn creates_dir_when_absent() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("r/sock-dir");
        prepare_socket_dir(&target, our_uid()).unwrap();
        assert!(target.is_dir());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn rejects_symlinked_dir() {
        let base = TempDir::new().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = prepare_socket_dir(&link, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_too_permissive_dir() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("slack");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_socket_dir(&target, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("0700"));
    }
}
