//! Integration test: graceful shutdown drains active sessions within the 5s deadline.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{TestDaemon, test_daemon_state};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;

/// Tempdir whose mode is forced to 0700 — `AuditWriter::open` rejects looser
/// modes after #147 and `tempfile::TempDir::new()` may inherit the system
/// `umask` (often 0755).
fn tight_tempdir() -> TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on tempdir");
    dir
}

/// Verifies that SIGTERM (simulated via `shutdown.notify_one`) stops the accept
/// loop and drains in-flight sessions within the 5s deadline configured in
/// `run::drain_sessions`.
///
/// Two raw clients connect but never send any bytes, so their `serve_server`
/// tasks remain blocked on reads. The daemon must abort them and exit cleanly
/// within the drain window.
#[tokio::test]
async fn shutdown_drains_active_sessions_within_deadline() {
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(&audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Open two client connections so there are two in-flight sessions.
    // These don't speak MCP — `serve_server` will stay blocked waiting for
    // input until the daemon's drain deadline aborts the tasks.
    let mut c1 = UnixStream::connect(&socket_path).await.expect("connect c1");
    let mut c2 = UnixStream::connect(&socket_path).await.expect("connect c2");

    // Wait for the daemon to observe both connections and spawn session
    // tasks (verified via two session_start records in the audit log).
    daemon.wait_for_session_start(2).await;

    // Trigger shutdown and measure wall-clock time until the daemon exits.
    // `shutdown()` reads the audit log just before dropping the TempDir, so
    // we get access to all records emitted up to (and including) session_end.
    let start = std::time::Instant::now();
    let shutdown_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), daemon.shutdown()).await;
    let elapsed = start.elapsed();

    assert!(
        shutdown_result.is_ok(),
        "daemon.shutdown() did not complete within 10s"
    );

    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "expected drain within ~5s (daemon drain deadline); took {elapsed:?}"
    );

    // Close client sockets (they may already be RST by the daemon's JoinSet abort).
    let _ = c1.shutdown().await;
    let _ = c2.shutdown().await;

    // Inspect the audit log returned by shutdown().
    let audit = shutdown_result.expect("already asserted Ok above");

    let session_starts = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#))
        .count();

    // session_start is emitted synchronously before the session task is
    // spawned, so both records are always present.
    assert!(
        session_starts >= 2,
        "expected at least 2 session_start records (one per client); got {session_starts}:\n{audit}"
    );

    // After the fix (#137), drain_sessions synthesizes session_end records for
    // aborted sessions. Every start must now have a matching end.
    let session_ends = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .count();
    assert_eq!(
        session_starts, session_ends,
        "every session_start must have a matching session_end after #137 fix; \
         starts={session_starts} ends={session_ends}\naudit log:\n{audit}"
    );
}

/// Regression test for #137: every active session emits a
/// `session_end(reason="daemon_shutdown")` record when the daemon
/// shuts down, including those aborted mid-flight by the `JoinSet`
/// drain. Before the fix, aborted futures never reached
/// `emit_session_end` and the audit log was missing those records.
#[tokio::test]
async fn shutdown_synthesizes_session_end_for_aborted_sessions() {
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(&audit_path);
    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Open two sessions and write nothing through them. The shim-layer
    // serve_server.waiting() is parked on a stalled stdin read; we don't
    // need to send any MCP frames — what matters is that the session is
    // ALIVE in the daemon's JoinSet at shutdown time.
    let s1 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("connect 1");
    let s2 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("connect 2");

    // Wait for the accept loop to spawn both per-session futures and
    // call `live.insert` for each — observable via two session_start
    // records reaching the audit log. Far more reliable than a fixed
    // sleep on a loaded CI runner.
    daemon.wait_for_session_start(2).await;

    // Trigger shutdown. The drain has 5s to clean-close, then JoinSet
    // aborts. Sessions that never completed handshake will be aborted —
    // exactly the path #137 fixes.
    let audit_log = daemon.shutdown().await;
    drop(s1);
    drop(s2);

    // Count `session_end(reason="daemon_shutdown")` records.
    let shutdown_ends = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_end""#))
        .filter(|line| line.contains(r#""reason":"daemon_shutdown""#))
        .count();
    assert_eq!(
        shutdown_ends, 2,
        "expected 2 session_end(daemon_shutdown) records, got {shutdown_ends}; \
         audit log was:\n{audit_log}",
    );

    // Total session_end count must equal session_start count — no orphan
    // start records and no over-count.
    let starts = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_start""#))
        .count();
    let ends = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_end""#))
        .count();
    assert_eq!(
        starts, ends,
        "session_start ({starts}) must pair with session_end ({ends}); \
         audit log was:\n{audit_log}",
    );
}
