//! Process-level hardening applied at daemon startup.
//!
//! Disables coredumps and sets `PR_SET_DUMPABLE=0` on Linux so that the
//! long-lived daemon — which holds decrypted IMAP credentials across
//! many sessions — cannot leak memory contents via a crash dump or a
//! `/proc/self/mem` / `ptrace` attach from a same-UID attacker.
//!
//! Called once at daemon entry (`daemon_main`). Failure is fatal:
//! a daemon that falls through to default coredump behaviour would be
//! a regression of review finding I4.

#![cfg(unix)]

use std::io;

/// Disable coredumps and set process non-dumpable.
///
/// # Errors
///
/// Returns the underlying `io::Error` if `setrlimit` or (on Linux)
/// `prctl(PR_SET_DUMPABLE, 0)` fails. Callers should propagate this
/// as fatal; a daemon that cannot harden its process must not start.
pub fn lock_down_process() -> io::Result<()> {
    // RLIMIT_CORE = 0 — kernel refuses to write a core dump.
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;

    // PR_SET_DUMPABLE=0 — blocks core dump, ptrace attach from same UID,
    // and /proc/self/mem reads. Linux-only; rustix exposes it under
    // `rustix::process::set_dumpable_behavior` gated by the `process`
    // feature (already enabled by this crate).
    #[cfg(target_os = "linux")]
    {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    }

    Ok(())
}
