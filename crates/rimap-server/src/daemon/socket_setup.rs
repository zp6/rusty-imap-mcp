//! Prepare the daemon's socket parent directory with tight permissions.

#![cfg(unix)]

use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{Mode, OFlags, fstat, mkdirat, open, openat};
use rustix::io::Errno;

/// Open flags used for every directory handle we hold. `O_NOFOLLOW` refuses a
/// symlinked leaf, `O_DIRECTORY` refuses a non-directory, `O_CLOEXEC` stops the
/// fd leaking across exec, `O_PATH` means we only need the fd as an anchor for
/// subsequent `*at` syscalls — we never read or write it directly.
const DIR_OFLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Ensure `dir` exists, is owned by `our_uid`, is mode 0700, and is not a
/// symlink. Creates the directory (mode 0700) if missing.
///
/// The leaf is opened with `openat(parent_fd, name, O_NOFOLLOW | O_DIRECTORY
/// | O_CLOEXEC | O_PATH)` so that a hostile swap of an ancestor between
/// syscalls cannot smuggle us onto a different directory. The returned
/// `OwnedFd` pins the verified directory — callers should keep it alive and
/// use `*at` syscalls against it rather than re-walking the path.
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
pub fn prepare_socket_dir(dir: &Path, our_uid: u32) -> io::Result<OwnedFd> {
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
                format!("socket directory {} is a symlink", dir.display()),
            ))
        }
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("socket parent {} is not a directory", dir.display()),
        )),
        Err(Errno::NOENT) => {
            // `EEXIST` means a concurrent starter won the mkdir; the directory
            // now exists, so fall through to the re-openat below. The
            // subsequent fstat + uid/mode check will verify the winning
            // creator set the mode correctly — if they didn't, we fail closed.
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

/// Distinguish "leaf is a symlink" from other `ENOTDIR` causes so we can give
/// the caller an accurate error kind. We use `fstatat` with
/// `AT_SYMLINK_NOFOLLOW` to inspect the leaf without traversing it.
fn leaf_is_symlink(parent_fd: &OwnedFd, name: &OsStr) -> bool {
    use rustix::fs::{AtFlags, FileType, statat};
    statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|s| FileType::from_raw_mode(s.st_mode) == FileType::Symlink)
        .unwrap_or(false)
}

/// Split `dir` into a (parent, leaf) pair. Rejects paths that have no parent
/// (e.g. "/" or a bare filename with no directory component) because those
/// cannot be opened via the parent-fd-pinned flow.
fn split_parent_and_name(dir: &Path) -> io::Result<(&Path, &OsStr)> {
    let parent = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("socket directory {} has no parent", dir.display()),
        )
    })?;
    let name = dir.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("socket directory {} has no file name", dir.display()),
        )
    })?;
    // `dir.parent()` returns "" for a bare filename like "foo"; coerce to "."
    // so `open(parent)` actually resolves CWD.
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok((parent, name))
}

/// Open `parent` as a directory fd. `O_NOFOLLOW` refuses a symlinked last
/// component of the parent path, catching the "ancestor swap" attack where a
/// symlink is spliced in above the target dir. Falls back to `create_dir_all`
/// if the parent chain is missing — the ancestors are expected to be
/// system-managed (e.g. `XDG_RUNTIME_DIR`) so bootstrapping them is
/// acceptable; the symlink-safety guarantee applies to the leaf we return.
///
/// Note: `O_NOFOLLOW` only protects the final component. Earlier components
/// of `parent` are resolved by the kernel and may still traverse symlinks —
/// that is acceptable here because the ancestors are trusted system paths.
fn open_parent(parent: &Path) -> io::Result<OwnedFd> {
    match open(parent, DIR_OFLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP | Errno::NOTDIR) if path_is_symlink(parent) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("socket parent {} is a symlink", parent.display()),
        )),
        Err(Errno::NOTDIR) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("socket parent {} is not a directory", parent.display()),
        )),
        Err(Errno::NOENT) => {
            std::fs::create_dir_all(parent)?;
            open(parent, DIR_OFLAGS, Mode::empty())
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

/// Check whether `path` is itself a symlink (via `lstat`). Used only to pick
/// the right error kind — the open has already failed, so this is not a
/// TOCTOU window.
fn path_is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Enforce ownership + mode invariants against a directory fd. Using `fstat`
/// on the already-opened fd removes any TOCTOU gap against the path walk.
fn verify_dir(fd: &OwnedFd, dir: &Path, our_uid: u32) -> io::Result<()> {
    let stat = fstat(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    // `st_uid` is `u32` on Linux but `uid_t` on other Unixes; the rustix
    // `as_raw_mode` / bitflag round-trip is the platform-agnostic path.
    let stat_uid = uid_to_u32(stat.st_uid);
    if stat_uid != our_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket directory {} is owned by uid {}, not {}",
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
                "socket directory {} has mode {:o}, require 0700",
                dir.display(),
                perm_bits.as_raw_mode()
            ),
        ));
    }
    Ok(())
}

/// Normalize a `stat.st_uid` value (`uid_t` on some targets, `u32` on Linux)
/// to `u32` without triggering `useless_conversion`. `uid_t` is unsigned on
/// every Unix target rustix supports, so truncation cannot happen in practice.
fn uid_to_u32<T: TryInto<u32>>(uid: T) -> u32 {
    uid.try_into().unwrap_or(u32::MAX)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
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
        // Asking us to "prepare" link/ok must refuse because an ancestor is a symlink.
        let err = prepare_socket_dir(&link.join("ok"), our_uid()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
