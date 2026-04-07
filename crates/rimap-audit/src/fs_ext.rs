//! File-open helpers with defense-in-depth Unix flags.
//!
//! Every audit-file open in the crate must go through these helpers so that
//! symlink-following and umask-widening races are blocked atomically.

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

/// Apply atomic-mode and `O_NOFOLLOW` for writer opens on Linux.
#[cfg(target_os = "linux")]
fn apply_unix_write_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
    // `O_NOFOLLOW` (0x20000 on Linux): refuse to open symlinks, blocking
    // attacks that pre-create audit.jsonl → ~/.ssh/authorized_keys.
    // Mode 0o600 is set atomically at create time, eliminating the
    // post-open chmod window present in the previous implementation.
    opts.custom_flags(0x0002_0000);
}

/// Apply atomic-mode and `O_NOFOLLOW` for writer opens on macOS.
#[cfg(target_os = "macos")]
fn apply_unix_write_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
    // `O_NOFOLLOW` (0x0100 on macOS): same protection as the Linux variant.
    opts.custom_flags(0x0000_0100);
}

/// No-op fallback for non-Linux/macOS Unix (FreeBSD etc. use different values;
/// rather than risk passing a wrong constant, skip `O_NOFOLLOW` on unknown Unix).
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn apply_unix_write_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn apply_unix_write_flags(_opts: &mut OpenOptions) {}

/// Apply `O_NOFOLLOW` for reader opens on Linux.
#[cfg(target_os = "linux")]
fn apply_unix_read_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(0x0002_0000);
}

/// Apply `O_NOFOLLOW` for reader opens on macOS.
#[cfg(target_os = "macos")]
fn apply_unix_read_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(0x0000_0100);
}

/// No-op fallback for other Unix.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn apply_unix_read_flags(_opts: &mut OpenOptions) {}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn apply_unix_read_flags(_opts: &mut OpenOptions) {}
