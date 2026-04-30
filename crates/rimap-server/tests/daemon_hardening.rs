//! Verify coredump lockdown leaves the process with mode 0/dumpable=0.
//!
//! This test mutates process-global state (`RLIMIT_CORE` and `PR_SET_DUMPABLE`).
//! It lives in its own integration-test binary so the mutation does not bleed
//! into unrelated tests. The mutation is otherwise benign: no test in this
//! crate expects coredumps or relies on `PR_GET_DUMPABLE == 1`.

#![cfg(target_os = "linux")]
#![expect(clippy::unwrap_used, reason = "tests")]

#[test]
fn daemon_sets_dumpable_to_zero() {
    rimap_server::daemon::hardening::lock_down_process().unwrap();

    let behavior = rustix::process::dumpable_behavior().unwrap();
    assert!(
        matches!(behavior, rustix::process::DumpableBehavior::NotDumpable),
        "expected DumpableBehavior::NotDumpable after lock_down_process, got {behavior:?}",
    );

    let rlim = rustix::process::getrlimit(rustix::process::Resource::Core);
    assert_eq!(rlim.current, Some(0), "current RLIMIT_CORE should be 0");
    assert_eq!(rlim.maximum, Some(0), "max RLIMIT_CORE should be 0");
}
