//! Integration test: graceful shutdown drains active sessions within the 5s deadline.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{TestDaemon, test_daemon_state};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;

/// Verifies that SIGTERM (simulated via `shutdown.notify_one`) stops the accept
/// loop and drains in-flight sessions within the 5s deadline configured in
/// `run::drain_sessions`.
///
/// Two raw clients connect but never send any bytes, so their `serve_server`
/// tasks remain blocked on reads. The daemon must abort them and exit cleanly
/// within the drain window.
#[tokio::test]
async fn shutdown_drains_active_sessions_within_deadline() {
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(tempdir.path(), &audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Open two client connections so there are two in-flight sessions.
    // These don't speak MCP — `serve_server` will stay blocked waiting for
    // input until the daemon's drain deadline aborts the tasks.
    let mut c1 = UnixStream::connect(&socket_path).await.expect("connect c1");
    let mut c2 = UnixStream::connect(&socket_path).await.expect("connect c2");

    // Allow the daemon to observe both connections and spawn session tasks.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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

    // session_end is only emitted if the session task runs to completion.
    // When the drain deadline expires, `JoinSet::shutdown().await` aborts
    // remaining tasks — those futures are dropped mid-flight without reaching
    // `emit_session_end`. So session_end count may be 0, 1, or 2 depending on
    // timing; we do not assert a minimum here. The timing assertion above
    // (elapsed < 6 s) is the meaningful correctness check for the abort path.
}
