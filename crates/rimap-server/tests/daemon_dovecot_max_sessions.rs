//! Max-sessions enforcement against a live Dovecot. Spawn the daemon
//! with `max_concurrent_sessions = 2`, open three sessions, assert the
//! third sees a paired `session_start` + `session_end(Rejected)` audit
//! pair — the accept-loop's paired-record invariant under live load.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;

use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn third_session_is_rejected_when_max_concurrent_is_two() {
    let Some(daemon) = DovecotDaemon::try_spawn(2).await else {
        return;
    };

    let _s1 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("s1 connect");
    let _s2 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("s2 connect");
    // Let the accept loop install s1 + s2 in its JoinSet so they
    // actually hold their semaphore permits before s3 races in.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // s3 hits the semaphore at zero — accept-loop emits the paired
    // start+end(Rejected) record and drops the stream.
    let s3 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("s3 connect");
    drop(s3);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = daemon.shutdown().await;
    let rejected_ends = result
        .log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .filter(|l| l.contains(r#""reason":"rejected""#))
        .count();
    assert_eq!(
        rejected_ends, 1,
        "expected exactly 1 session_end(rejected); got {rejected_ends}; log:\n{}",
        result.log,
    );
}
