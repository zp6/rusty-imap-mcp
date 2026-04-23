//! Concurrency bound: when `max_concurrent_sessions = N`, the (N+1)th shim
//! connection is refused with a paired `session_start` +
//! `session_end(rejected)` in the audit log, and the stream is closed
//! immediately. The first session's permit is released when the session
//! future completes, so subsequent connects succeed again.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::daemon_harness::{TestDaemon, test_daemon_state_with_limit};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

#[tokio::test]
async fn daemon_rejects_session_past_limit() {
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    // Bound at 1: the first connection holds the only permit; the
    // second must be rejected.
    let state = test_daemon_state_with_limit(tempdir.path(), &audit_path, 1);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // First shim-like client connects and keeps the connection open by
    // not closing its write half. This holds the session permit.
    let mut conn1 = UnixStream::connect(&socket_path).await.expect("connect 1");

    // Give the daemon a beat to emit session_start for conn1 and to
    // acquire the permit before we race conn2 in.
    tokio::time::sleep(Duration::from_millis(50)).await;

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

    // Hold conn1 open just long enough to be sure audit lines are flushed;
    // then close both and read the log.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Close both connections cleanly so session_end(eof) for conn1 lands
    // before we snapshot the audit log.
    conn1.shutdown().await.expect("shutdown conn1 write");
    drop(conn1);
    drop(conn2);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let audit = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = daemon.shutdown().await;

    let rejected_count = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#) && l.contains(r#""reason":"rejected""#))
        .count();
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
    // Limit = 1. First connection holds the permit, then closes. A
    // second connection afterwards must succeed (no rejection) because
    // the permit dropped with the first session future.
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state_with_limit(tempdir.path(), &audit_path, 1);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Round 1: connect, close, wait for session_end.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 1");
        c.shutdown().await.expect("shutdown 1");
        drop(c);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Round 2: permit should be back; this connection must not be
    // rejected.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 2");
        c.shutdown().await.expect("shutdown 2");
        drop(c);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let audit = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = daemon.shutdown().await;

    let rejected_count = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#) && l.contains(r#""reason":"rejected""#))
        .count();
    assert_eq!(
        rejected_count, 0,
        "expected no rejections when permits are released, full audit:\n{audit}"
    );
    let session_start_count = audit
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#))
        .count();
    assert!(
        session_start_count >= 2,
        "expected at least two session_starts, got {session_start_count}:\n{audit}",
    );
}
