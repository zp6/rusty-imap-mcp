//! File-open helpers with defense-in-depth Unix flags.
//!
//! Every audit-file open in the crate must go through these helpers so that
//! symlink-following and umask-widening races are blocked atomically. On
//! Unix, opens carry `O_NOFOLLOW` (refuse to traverse a symlink at the final
//! path component) and writer opens additionally set mode `0o600` at create
//! time so the file never briefly exists with the umask-default mode. On
//! non-Unix the helpers degrade to plain `OpenOptions`.

use std::fs::OpenOptions;

/// Returns an `OpenOptions` configured for writing the audit file:
/// `read+append+create`, with atomic mode 0600 and `O_NOFOLLOW` on Unix.
#[must_use]
pub(crate) fn writer_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true).append(true).create(true);
    apply_unix_write_flags(&mut opts);
    opts
}

/// Returns an `OpenOptions` configured for reading the audit file (no create).
/// `O_NOFOLLOW` on Unix prevents symlink attacks during shared opens.
#[must_use]
pub(crate) fn reader_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_unix_read_flags(&mut opts);
    opts
}

#[cfg(unix)]
fn apply_unix_write_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
    opts.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(unix)]
fn apply_unix_read_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn apply_unix_write_flags(_opts: &mut OpenOptions) {}

#[cfg(not(unix))]
fn apply_unix_read_flags(_opts: &mut OpenOptions) {}

#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    /// Pin `apply_unix_write_flags` and `apply_unix_read_flags` against the
    /// `with ()` mutations: opening a symlink whose target exists must
    /// fail with `ELOOP` because both helpers set `O_NOFOLLOW`. Without
    /// the flag, the open would succeed and traverse the symlink.
    #[test]
    fn writer_open_options_rejects_symlinks_via_o_nofollow() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"existing").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = super::writer_open_options()
            .open(&link)
            .expect_err("O_NOFOLLOW must reject opening a symlink");
        // O_NOFOLLOW makes the kernel return ELOOP when the final
        // path component is a symlink. Match by raw_os_error so the
        // assertion does not depend on `io::ErrorKind::FilesystemLoop`
        // (only stable since 1.83) — the underlying syscall errno is
        // the stable contract.
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP, got kind={:?} raw={:?}",
            err.kind(),
            err.raw_os_error(),
        );
    }

    #[test]
    fn reader_open_options_rejects_symlinks_via_o_nofollow() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"existing").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = super::reader_open_options()
            .open(&link)
            .expect_err("O_NOFOLLOW must reject opening a symlink");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP, got kind={:?} raw={:?}",
            err.kind(),
            err.raw_os_error(),
        );
    }

    /// Pin the atomic 0o600 mode side of `apply_unix_write_flags`: the
    /// freshly-created file must be 0o600 *before* any post-open
    /// reassertion. Use a tempdir whose umask is otherwise wide and
    /// confirm the create-time mode.
    #[test]
    fn writer_open_options_creates_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("fresh.jsonl");
        let f = super::writer_open_options().open(&path).unwrap();
        // Drop without invoking any other helper so the only mode setter
        // exercised is `apply_unix_write_flags`.
        drop(f);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "writer_open_options must create the file at 0o600",
        );
    }
}
