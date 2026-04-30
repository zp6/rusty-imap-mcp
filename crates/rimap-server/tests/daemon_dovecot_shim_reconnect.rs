//! Two daemon spawns at the same socket path drive two shim subprocess
//! invocations; asserts the two audit logs carry distinct `process_id`s.
//! This proves the daemon is a separate process and the shim re-resolves
//! to the new socket after the first daemon exits, without any CLI
//! surface for the path.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::path::Path;

use common::dovecot_daemon_harness::DovecotDaemon;
use common::shim_jsonrpc::{
    READ_TIMEOUT, make_runtime_dir, recv_frame, resolved_socket_path, send_frame,
    spawn_shim_and_initialize,
};

/// Drive one shim subprocess against `runtime_dir`'s XDG path:
/// initialize handshake + `tools/list`, then EOF stdin so the shim exits.
async fn run_shim_session(runtime_dir: &Path) {
    let (mut shim, mut stdin, mut reader) =
        spawn_shim_and_initialize(runtime_dir, "rimap-shim-reconnect-test").await;

    let list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    send_frame(&mut stdin, &list, "tools/list").await;
    let _ = recv_frame(&mut reader, "tools/list").await;

    drop(stdin);
    let _ = tokio::time::timeout(READ_TIMEOUT, shim.wait()).await;
}

/// Pull the `process_id` field out of the first audit record. Every
/// record's envelope carries the writer's stable `process_id`, so any
/// record will do. We pick `session_start` because the test exercise
/// always emits at least one of those.
fn first_process_id(log: &str) -> Option<String> {
    log.lines()
        .find(|l| l.contains(r#""kind":"session_start""#))
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["process_id"].as_str().map(str::to_owned))
}

#[tokio::test]
async fn shim_reconnects_to_new_daemon_after_restart() {
    let runtime_dir = make_runtime_dir();
    let socket_path = resolved_socket_path(runtime_dir.path());

    // Daemon 1.
    let Some(daemon1) = DovecotDaemon::try_spawn_at(64, socket_path.clone()).await else {
        return;
    };
    run_shim_session(runtime_dir.path()).await;
    let result1 = daemon1.shutdown().await;

    // Daemon 2 — same socket path, fresh state. The first listener
    // unlinked on drop, so the bind succeeds without stale-socket
    // recovery firing.
    let Some(daemon2) = DovecotDaemon::try_spawn_at(64, socket_path.clone()).await else {
        return;
    };
    run_shim_session(runtime_dir.path()).await;
    let result2 = daemon2.shutdown().await;

    let pid1 = first_process_id(&result1.log).expect("daemon1 logs a session_start");
    let pid2 = first_process_id(&result2.log).expect("daemon2 logs a session_start");
    assert_ne!(
        pid1, pid2,
        "expected distinct process_ids across daemon restart; got pid1={pid1} pid2={pid2}",
    );
}
