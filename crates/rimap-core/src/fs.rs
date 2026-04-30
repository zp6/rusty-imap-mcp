//! Filesystem primitives shared across `rimap-*` crates.
//!
//! Currently hosts [`ensure_tight_dir`], the TOCTOU-safe "create or verify
//! that this directory is mode 0700 and owned by us, refusing symlinks" op
//! used by the daemon socket-directory bootstrap and the audit writer's
//! parent-directory tightening.

#![cfg(unix)]

use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, mkdirat, open, openat, statat};
use rustix::io::Errno;

/// Flags used for every directory handle this module holds.
///
/// `O_NOFOLLOW` refuses a symlinked leaf, `O_DIRECTORY` refuses a non-directory,
/// `O_CLOEXEC` stops the fd leaking across `exec`. On platforms that support it
/// we additionally pass `O_PATH` to signal that we only need the fd as an anchor
/// for subsequent `*at` syscalls — we never read or write it directly. On
/// platforms without `O_PATH` (notably macOS and the BSDs other than FreeBSD)
/// the fd is opened for read instead; the security invariants enforced by
/// [`verify_dir`] are unchanged.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "redox",
))]
const DIR_OFLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "redox",
)))]
const DIR_OFLAGS: OFlags = OFlags::DIRECTORY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Ensure `dir` exists, is owned by `our_uid`, is mode 0700, and is not a
/// symlink. Creates the directory (mode 0700) if missing.
///
/// The leaf is opened with `openat(parent_fd, name, O_NOFOLLOW | O_DIRECTORY
/// | O_CLOEXEC)` (plus `O_PATH` on platforms that support it) so that a hostile
/// swap of an ancestor between syscalls cannot smuggle the caller onto a
/// different directory. The returned
/// [`OwnedFd`] pins the verified directory — callers that perform follow-up
/// syscalls inside `dir` should keep the fd alive and use `*at` syscalls
/// against it rather than re-walking the path. Callers that need only the
/// invariant can drop the fd immediately.
///
/// Refuses to operate on a symlinked directory, a wrong-owner directory, or a
/// too-permissive directory — these signal a hostile or compromised filesystem
/// state and should fail loudly rather than be "fixed" silently.
///
/// # Errors
/// Returns `PermissionDenied` if the directory (or its leaf component) is a
/// symlink, is owned by a different UID, or has mode other than 0700. A
/// directory with any of setuid, setgid, or sticky bits set is rejected for
/// the same reason — remove those bits (e.g. `chmod 0700`) to proceed.
/// Returns `NotADirectory` if the path exists but is not a directory. Returns
/// the underlying I/O error from `create_dir_all` / `mkdirat` on bootstrap.
pub fn ensure_tight_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
    let (parent, name) = split_parent_and_name(dir)?;

    let parent_fd = open_parent(parent)?;

    match openat(&parent_fd, name, DIR_OFLAGS, Mode::empty()) {
        Ok(fd) => verify_dir(&fd, dir, our_uid).map(|()| fd),
        // `O_NOFOLLOW | O_DIRECTORY` on a symlink-to-directory returns either
        // `ELOOP` or `ENOTDIR` depending on kernel path-walk order; treat both
        // as "leaf is a symlink" and refuse.
        Err(Errno::LOOP | Errno::NOTDIR) if leaf_is_symlink(&parent_fd, name) => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("directory {} is a symlink", dir.display()),
            ))
        }
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("parent of {} is not a directory", dir.display()),
        )),
        Err(Errno::NOENT) => {
            if let Err(e) = mkdirat(&parent_fd, name, Mode::from_raw_mode(0o700))
                && e != Errno::EXIST
            {
                return Err(io::Error::from_raw_os_error(e.raw_os_error()));
            }
            let fd = openat(&parent_fd, name, DIR_OFLAGS, Mode::empty())
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
            verify_dir(&fd, dir, our_uid).map(|()| fd)
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

fn leaf_is_symlink(parent_fd: &OwnedFd, name: &OsStr) -> bool {
    statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|s| FileType::from_raw_mode(s.st_mode) == FileType::Symlink)
        .unwrap_or(false)
}

fn split_parent_and_name(dir: &Path) -> io::Result<(&Path, &OsStr)> {
    let parent = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("directory {} has no parent", dir.display()),
        )
    })?;
    let name = dir.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("directory {} has no file name", dir.display()),
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok((parent, name))
}

fn open_parent(parent: &Path) -> io::Result<OwnedFd> {
    match open(parent, DIR_OFLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP | Errno::NOTDIR) if path_is_symlink(parent) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("parent {} is a symlink", parent.display()),
        )),
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("parent {} is not a directory", parent.display()),
        )),
        Err(Errno::NOENT) => {
            std::fs::create_dir_all(parent)?;
            open(parent, DIR_OFLAGS, Mode::empty())
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

fn path_is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn verify_dir(fd: &OwnedFd, dir: &Path, our_uid: u32) -> io::Result<()> {
    let stat = fstat(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    let stat_uid = uid_to_u32(stat.st_uid);
    if stat_uid != our_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} is owned by uid {}, not {}",
                dir.display(),
                stat_uid,
                our_uid
            ),
        ));
    }
    let perm_bits = Mode::from_raw_mode(stat.st_mode)
        & (Mode::RWXU | Mode::RWXG | Mode::RWXO | Mode::SUID | Mode::SGID | Mode::SVTX);
    if perm_bits != Mode::RWXU {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} has mode {:o}, require 0700",
                dir.display(),
                perm_bits.as_raw_mode()
            ),
        ));
    }
    Ok(())
}

fn uid_to_u32<T: TryInto<u32>>(uid: T) -> u32 {
    uid.try_into().unwrap_or(u32::MAX)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::ensure_tight_dir;
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
        ensure_tight_dir(&target, our_uid()).unwrap();
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
        ensure_tight_dir(&target, our_uid()).unwrap();
    }

    #[test]
    fn rejects_too_permissive_dir() {
        let base = TempDir::new().unwrap();
        let target = base.path().join("slack");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_tight_dir(&target, our_uid()).unwrap_err();
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
        let err = ensure_tight_dir(&link, our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_symlinked_ancestor() {
        let base = TempDir::new().unwrap();
        let real_parent = base.path().join("real");
        std::fs::create_dir_all(real_parent.join("ok")).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            real_parent.join("ok"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real_parent, &link).unwrap();
        let err = ensure_tight_dir(&link.join("ok"), our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_wrong_owner_reports_uid_in_message() {
        // Cannot actually chown to a different UID without root, so we
        // assert the rejection message contains the uid we asked for by
        // passing our_uid + 1 (the dir is ours). This forces the wrong-uid
        // branch deterministically.
        let base = TempDir::new().unwrap();
        let target = base.path().join("mine");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bogus_uid = our_uid().wrapping_add(1);
        let err = ensure_tight_dir(&target, bogus_uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains(&bogus_uid.to_string()),
            "expected uid {bogus_uid} in error message: {err}",
        );
    }
}
