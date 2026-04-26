//! Happy-path integration tests for the daemon accept loop and session lifecycle.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{TestDaemon, test_daemon_state};
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
    let state = test_daemon_state(tempdir.path(), &audit_path);

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

    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(tempdir.path(), &audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Connect as a raw client — we're not speaking MCP, just proving the
    // accept loop works and session_start/session_end get emitted.
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
    // Write nothing. Immediately close the write half so the daemon sees EOF.
    stream.shutdown().await.expect("shutdown client write half");
    // Give the daemon time to observe EOF and emit session_end.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(stream);

    // Read the audit log before shutdown — tempdir lives inside daemon and
    // would be dropped when shutdown() consumes the TestDaemon value.
    let audit = std::fs::read_to_string(&audit_path).expect("read audit");

    // Shut down the daemon (consumes it, tempdir cleaned up here).
    let _audit_after_shutdown = daemon.shutdown().await;

    let session_starts = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#))
        .count();
    let session_ends = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .count();
    assert!(
        session_starts >= 1,
        "expected at least one session_start, got:\n{audit}"
    );
    assert!(
        session_ends >= 1,
        "expected at least one session_end, got:\n{audit}"
    );
}
