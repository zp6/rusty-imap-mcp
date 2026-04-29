//! Graceful shutdown under load: open four sessions against a
//! Dovecot-backed daemon, trigger shutdown, assert the drain completes
//! within the 5s grace + headroom and every session produces a
//! `session_end` record.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;

use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn shutdown_drains_loaded_sessions_within_5s_plus_headroom() {
    let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
        return;
    };

    // Open four sessions, each holding a connection. We don't need to
    // run the rmcp protocol — the test only needs active per-session
    // futures in the daemon's JoinSet at shutdown time.
    let mut sessions = Vec::with_capacity(4);
    for _ in 0..4 {
        sessions.push(
            UnixStream::connect(&daemon.socket_path)
                .await
                .expect("connect"),
        );
    }

    // Let the accept loop install the per-session futures before we
    // request shutdown.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = daemon.shutdown().await;
    drop(sessions);

    assert!(
        result.drain_duration < Duration::from_secs(7),
        "drain took {:?}; expected <7s",
        result.drain_duration,
    );

    let session_ends = result
        .log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .count();
    assert!(
        session_ends >= 4,
        "expected at least 4 session_end records, got {session_ends}; log:\n{}",
        result.log,
    );
}
