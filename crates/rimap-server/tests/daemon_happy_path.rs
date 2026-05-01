//! Happy-path integration tests for the daemon accept loop and session lifecycle.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{TestDaemon, count_audit_kind, test_daemon_state};
use tempfile::TempDir;

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

#[tokio::test]
async fn daemon_spawns_and_shuts_down_cleanly() {
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(&audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;
    // Both of these are true immediately: AuditWriter::open creates the file at
    // construction time, and UnixSocketListener::bind creates the socket.
    assert!(socket_path.exists(), "socket file should be bound");
    assert!(audit_path.exists(), "audit file should exist");

    let _audit = daemon.shutdown().await;
}

#[tokio::test]
async fn client_connects_and_sees_clean_session_lifecycle() {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::UnixStream;

    // Idempotent across the test binary; zero-cost when RUST_LOG is unset.
    // Set RUST_LOG=rimap_server=trace,rimap_audit=trace and pass --nocapture
    // to surface daemon-side activity. See issue #188 for the diagnostic
    // procedure.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();

    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(&audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Connect as a raw client — we're not speaking MCP, just proving the
    // accept loop works and session_start/session_end get emitted.
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
    // Wait for the daemon to record session_start before closing the
    // client. macOS races the daemon's accept-side syscalls against an
    // already-EOF'd peer; without this barrier the daemon never emits
    // session_start. See issue #188 and the comment in
    // tests/common/daemon_harness.rs near `wait_for_audit_at`.
    daemon.wait_for_session_start(1).await;
    // Write nothing. Immediately close the write half so the daemon sees EOF.
    stream.shutdown().await.expect("shutdown client write half");
    drop(stream);

    // Wait for the session_end record to land instead of guessing how
    // long the daemon needs to observe EOF.
    let audit = daemon
        .wait_for_audit(std::time::Duration::from_secs(2), |c| {
            count_audit_kind(c, "session_end") >= 1
        })
        .await;

    // Shut down the daemon (consumes it, tempdir cleaned up here).
    let _audit_after_shutdown = daemon.shutdown().await;

    let session_starts = count_audit_kind(&audit, "session_start");
    let session_ends = count_audit_kind(&audit, "session_end");
    assert!(
        session_starts >= 1,
        "expected at least one session_start, got:\n{audit}"
    );
    assert!(
        session_ends >= 1,
        "expected at least one session_end, got:\n{audit}"
    );
}
