//! Concurrency bound: when `max_concurrent_sessions = N`, the (N+1)th shim
//! connection is refused with a paired `session_start` +
//! `session_end(rejected)` in the audit log, and the stream is closed
//! immediately. The first session's permit is released when the session
//! future completes, so subsequent connects succeed again.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{
    TestDaemon, count_audit_kind, count_session_end_reason, test_daemon_state_with_limit,
    wait_for_audit_at, wait_for_session_start_at,
};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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

#[tokio::test]
async fn daemon_rejects_session_past_limit() {
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    // Bound at 1: the first connection holds the only permit; the
    // second must be rejected.
    let state = test_daemon_state_with_limit(&audit_path, 1);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // First shim-like client connects and keeps the connection open by
    // not closing its write half. This holds the session permit.
    let mut conn1 = UnixStream::connect(&socket_path).await.expect("connect 1");

    // Wait for conn1's session_start to land in the audit log so the
    // second connect races against a fully-acquired permit. Polling
    // beats a fixed sleep — passes immediately on fast machines, holds
    // up under CI scheduler jitter.
    daemon.wait_for_session_start(1).await;

    // Second client connects: the daemon accepts the TCP/Unix connection
    // (we can't refuse it at the socket layer without breaking the
    // accept loop), but then rejects it by closing the stream and
    // emitting session_end(rejected).
    let mut conn2 = UnixStream::connect(&socket_path).await.expect("connect 2");

    // Expect EOF on conn2 promptly — the daemon dropped its half after
    // the rejection audit pair was written.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), conn2.read(&mut buf))
        .await
        .expect("read timeout on rejected conn2")
        .expect("read on rejected conn2");
    assert_eq!(
        read, 0,
        "expected EOF on rejected connection, got {read} bytes"
    );

    // Wait for the rejection pair to be flushed before closing conn1.
    daemon
        .wait_for_audit(Duration::from_secs(2), |c| {
            count_session_end_reason(c, "rejected") >= 1
        })
        .await;

    // Close both connections cleanly so session_end(eof) for conn1 lands
    // before we snapshot the audit log.
    conn1.shutdown().await.expect("shutdown conn1 write");
    drop(conn1);
    drop(conn2);

    // Wait for both session_ends (conn1's eof + conn2's rejected).
    daemon
        .wait_for_audit(Duration::from_secs(2), |c| {
            count_audit_kind(c, "session_end") >= 2
        })
        .await;

    let audit = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = daemon.shutdown().await;

    let rejected_count = count_session_end_reason(&audit, "rejected");
    assert_eq!(
        rejected_count, 1,
        "expected exactly one session_end(rejected), full audit:\n{audit}"
    );

    // The rejection record must carry a last_error that mentions the
    // knob so operators can grep for it.
    let rejected_line = audit
        .lines()
        .find(|l| l.contains(r#""reason":"rejected""#))
        .expect("rejected line present");
    assert!(
        rejected_line.contains("max_concurrent_sessions"),
        "expected last_error mentioning max_concurrent_sessions, got: {rejected_line}"
    );

    // And every session_end(rejected) must have a matching session_start
    // (same session_id) so reviewers can pair the two.
    let rec: serde_json::Value = serde_json::from_str(rejected_line).expect("parse rejected");
    let rejected_sid = rec["session_id"].as_str().expect("session_id str");
    let start_matches = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#) && l.contains(rejected_sid))
        .count();
    assert_eq!(
        start_matches, 1,
        "expected exactly one session_start matching the rejected session_id {rejected_sid}",
    );
}

#[tokio::test]
async fn daemon_releases_permit_on_session_end() {
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
    // Limit = 1. First connection holds the permit, then closes. A
    // second connection afterwards must succeed (no rejection) because
    // the permit dropped with the first session future.
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state_with_limit(&audit_path, 1);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Round 1: connect, wait for session_start (see issue #188 — macOS
    // races accept-side syscalls against an already-EOF'd peer), close,
    // wait for session_end.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 1");
        wait_for_session_start_at(&audit_path, 1).await;
        c.shutdown().await.expect("shutdown 1");
        drop(c);
    }
    wait_for_audit_at(&audit_path, Duration::from_secs(2), |c| {
        count_audit_kind(c, "session_end") >= 1
    })
    .await;

    // Round 2: permit should be back; this connection must not be
    // rejected. Same wait-for-session_start barrier as round 1.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 2");
        wait_for_session_start_at(&audit_path, 2).await;
        c.shutdown().await.expect("shutdown 2");
        drop(c);
    }
    wait_for_audit_at(&audit_path, Duration::from_secs(2), |c| {
        count_audit_kind(c, "session_end") >= 2
    })
    .await;

    let audit = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = daemon.shutdown().await;

    let rejected_count = count_session_end_reason(&audit, "rejected");
    assert_eq!(
        rejected_count, 0,
        "expected no rejections when permits are released, full audit:\n{audit}"
    );
    let session_start_count = count_audit_kind(&audit, "session_start");
    assert!(
        session_start_count >= 2,
        "expected at least two session_starts, got {session_start_count}:\n{audit}",
    );
}
