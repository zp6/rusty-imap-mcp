//! Prepare the daemon's socket parent directory with tight permissions.

#![cfg(unix)]

use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

/// Ensure `dir` exists, is owned by `our_uid`, is mode 0700, and is
/// not a symlink. Creates the directory (mode 0700) if missing.
///
/// Refuses to operate on a symlinked directory, a wrong-owner directory,
/// or a too-permissive directory — these signal a hostile or compromised
/// filesystem state and should fail loudly rather than be "fixed" silently.
///
/// # Errors
/// Returns `PermissionDenied` if the directory is a symlink, owned by a
/// different UID, or has mode other than 0700. Returns `NotADirectory`
/// if the path exists but is not a directory. Returns the underlying
/// I/O error from `create_dir_all` / `set_permissions` on bootstrap.
pub fn prepare_socket_dir(dir: &Path, our_uid: u32) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("socket directory {} is a symlink", dir.display()),
                ));
            }
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("socket parent {} is not a directory", dir.display()),
                ));
            }
            if meta.uid() != our_uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "socket directory {} is owned by uid {}, not {}",
                        dir.display(),
                        meta.uid(),
                        our_uid
                    ),
                ));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "socket directory {} has mode {:o}, require 0700",
                        dir.display(),
                        mode
                    ),
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
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
    fn accepts_existing_dir_that_is_already_0700_and_ours() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("ok");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        prepare_socket_dir(&target, our_uid()).unwrap();
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
}
