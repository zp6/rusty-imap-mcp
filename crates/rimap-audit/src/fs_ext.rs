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
