//! Max-sessions enforcement against a live Dovecot. Spawn the daemon
//! with `max_concurrent_sessions = 2`, open three sessions, assert the
//! third sees a paired `session_start` + `session_end(Rejected)` audit
//! pair — the accept-loop's paired-record invariant under live load.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;

use tokio::net::UnixStream;

use common::daemon_harness::{
    count_session_end_reason, wait_for_audit_at, wait_for_session_start_at,
};
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
    // Wait for the accept loop to register s1 + s2 in its JoinSet
    // (observable via two session_start records) before s3 races in,
    // instead of guessing how long the accept path takes.
    wait_for_session_start_at(&daemon.audit_path, 2).await;

    // s3 hits the semaphore at zero — accept-loop emits the paired
    // start+end(Rejected) record and drops the stream.
    let s3 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("s3 connect");
    drop(s3);
    wait_for_audit_at(&daemon.audit_path, Duration::from_secs(2), |c| {
        count_session_end_reason(c, "rejected") >= 1
    })
    .await;

    let result = daemon.shutdown().await;
    let rejected_ends = count_session_end_reason(&result.log, "rejected");
    assert_eq!(
        rejected_ends, 1,
        "expected exactly 1 session_end(rejected); got {rejected_ends}; log:\n{}",
        result.log,
    );
}
