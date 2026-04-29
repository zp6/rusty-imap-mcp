//! Two daemon spawns at the same socket path drive two shim subprocess
//! invocations; asserts the two audit logs carry distinct `process_id`s.
//! This proves the daemon is a separate process and the shim re-resolves
//! to the new socket after the first daemon exits, without any CLI
//! surface for the path.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;

use common::dovecot_daemon_harness::DovecotDaemon;
use common::shim_jsonrpc::{READ_TIMEOUT, recv_frame, resolved_socket_path, send_frame};

/// Drive one shim subprocess against `runtime_dir`'s XDG path:
/// `initialize` + `notifications/initialized` + `tools/list`, then EOF
/// stdin so the shim exits. Returns once the shim has exited or the wait
/// timed out.
async fn run_shim_session(runtime_dir: &Path) {
    let shim_bin = assert_cmd::cargo::cargo_bin("rusty-imap-mcp");
    let mut shim = Command::new(&shim_bin)
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env_remove("TMPDIR")
        .arg("shim")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shim");
    let mut stdin = shim.stdin.take().expect("shim stdin");
    let stdout = shim.stdout.take().expect("shim stdout");
    let mut reader = BufReader::new(stdout).lines();

    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "rimap-shim-reconnect-test", "version": "0.0.1"}
        }
    });
    send_frame(&mut stdin, &init, "initialize").await;
    let _ = recv_frame(&mut reader, "initialize").await;

    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send_frame(&mut stdin, &initialized, "notifications/initialized").await;

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
    // Outer runtime dir hosts the resolver path. The shim's XDG resolver
    // lands at `<runtime_dir>/rusty-imap-mcp/daemon.sock`; both daemons
    // bind there in turn.
    let runtime_dir = TempDir::new().expect("runtime dir");
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on runtime dir");

    let socket_path = resolved_socket_path(runtime_dir.path());
    let socket_parent = socket_path.parent().expect("socket has parent");
    std::fs::create_dir_all(socket_parent).expect("create socket parent");
    std::fs::set_permissions(socket_parent, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on socket parent");

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
