//! Scenario 4 of #136: peer-identity round-trip. Asserts the daemon's
//! audit record carries the test process's own UID in
//! `session_start.peer_identity`, validating that `SO_PEERCRED` fires
//! through to the audit layer end-to-end.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;

use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn session_start_records_our_uid_via_so_peercred() {
    let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
        return;
    };

    let _s = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("connect");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = daemon.shutdown().await;
    let our_uid = rustix::process::geteuid().as_raw();

    // The `session_start` record carries `peer_identity` as JSON of shape
    // `{"Unix":{"uid":N,"pid":M}}`. Match against our actual UID rather
    // than a hard-coded number.
    let starts_with_our_uid = result
        .log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#))
        .filter(|l| l.contains(&format!(r#""uid":{our_uid}"#)))
        .count();
    assert!(
        starts_with_our_uid >= 1,
        "expected session_start with peer uid {our_uid}; log:\n{}",
        result.log,
    );
}
