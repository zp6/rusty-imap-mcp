//! Integration test: the shim byte-pipes a minimal MCP `initialize` +
//! `tools/list` exchange between stdin/stdout and the daemon socket.
//!
//! Companion to `shim_error_no_daemon.rs`, which covers the
//! absent-daemon failure path.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use rimap_core::tool::ToolName;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use common::daemon_harness::{TestDaemon, test_daemon_state};
use common::shim_jsonrpc::{READ_TIMEOUT, recv_frame, resolved_socket_path, send_frame};

/// Set up the freedesktop runtime dir layout and spawn the daemon at the
/// path the shim's resolver will land on.
///
/// Returns the outer `TempDir` (so the caller can keep it alive for the
/// duration of the test and pass its path as `XDG_RUNTIME_DIR` to the
/// shim subprocess), the resolved socket path, and the running `TestDaemon`.
async fn spawn_daemon_at_resolver_path() -> (TempDir, PathBuf, TestDaemon) {
    // 0700, owned by us — required by the resolver's `verify_runtime_dir`.
    // `TempDir::new` inherits the system umask, so chmod explicitly.
    let runtime_dir = TempDir::new().expect("runtime dir");
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on runtime dir");

    // `UnixSocketListener::bind` requires the parent dir to be 0700; create
    // it explicitly here (production goes through `prepare_socket_dir`).
    let socket_path = resolved_socket_path(runtime_dir.path());
    let socket_parent = socket_path.parent().expect("socket has a parent");
    std::fs::create_dir_all(socket_parent).expect("create socket parent dir");
    std::fs::set_permissions(socket_parent, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on socket parent");

    let audit_path = runtime_dir.path().join("audit.jsonl");
    let state = test_daemon_state(runtime_dir.path(), &audit_path);

    // `spawn_bare` consumes a `TempDir` for lifetime management; hand it a
    // separately-allocated inner tempdir so the outer `runtime_dir` (which
    // holds the audit file and the rusty-imap-mcp/ socket parent) stays in
    // scope until the test returns.
    let inner_tempdir = TempDir::new_in(runtime_dir.path()).expect("inner tempdir");
    let daemon =
        TestDaemon::spawn_bare(inner_tempdir, audit_path, socket_path.clone(), state).await;

    // `UnixSocketListener::bind` already chmods the bound socket to 0600
    // and verifies it post-bind, so the shim's `verify_socket_path` will
    // accept it without an extra chmod here.

    (runtime_dir, socket_path, daemon)
}

/// Spawn the real `rusty-imap-mcp shim` binary with `XDG_RUNTIME_DIR`
/// pointed at `runtime_dir`. Returns the child plus its stdin and a
/// line-oriented stdout reader.
fn spawn_shim(runtime_dir: &Path) -> (Child, ChildStdin, Lines<BufReader<ChildStdout>>) {
    let shim_bin = assert_cmd::cargo::cargo_bin("rusty-imap-mcp");
    let mut shim = Command::new(&shim_bin)
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env_remove("TMPDIR") // force the XDG branch on Linux
        .arg("shim")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherit stderr so cargo's per-test capture surfaces shim
        // diagnostics on failure. Capturing it here would discard the
        // signal unless we also spawned a reader task.
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shim");
    let stdin = shim.stdin.take().expect("shim stdin");
    let stdout = shim.stdout.take().expect("shim stdout");
    let reader = BufReader::new(stdout).lines();
    (shim, stdin, reader)
}

#[tokio::test]
async fn shim_pipes_initialize_and_tools_list_through_real_binary() {
    let (runtime_dir, _socket_path, daemon) = spawn_daemon_at_resolver_path().await;
    let (mut shim, mut stdin, mut reader) = spawn_shim(runtime_dir.path());

    // initialize
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "rimap-shim-e2e-test",
                "version": "0.0.1"
            }
        }
    });
    send_frame(&mut stdin, &init_request, "initialize").await;
    let init_resp = recv_frame(&mut reader, "initialize").await;
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert!(
        init_resp["result"]["protocolVersion"].is_string(),
        "initialize response must carry a protocolVersion: {init_resp}",
    );

    // notifications/initialized — required by MCP spec, no response expected.
    let initialized_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send_frame(&mut stdin, &initialized_notif, "notifications/initialized").await;

    // tools/list
    let list_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    send_frame(&mut stdin, &list_request, "tools/list").await;
    let list_resp = recv_frame(&mut reader, "tools/list").await;
    assert_eq!(list_resp["jsonrpc"], "2.0");
    assert_eq!(list_resp["id"], 2);

    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools must be array");
    let tool_names: std::collections::BTreeSet<_> = tools
        .iter()
        .filter_map(|t| t["name"].as_str().map(std::string::ToString::to_string))
        .collect();
    assert!(
        tool_names.contains(ToolName::UseAccount.as_str()),
        "tools/list must include {}; got: {tool_names:?}",
        ToolName::UseAccount.as_str(),
    );
    assert!(
        tool_names.contains(ToolName::ListAccounts.as_str()),
        "tools/list must include {}; got: {tool_names:?}",
        ToolName::ListAccounts.as_str(),
    );

    // EOF the shim — it should exit 0.
    drop(stdin);
    let exit = tokio::time::timeout(READ_TIMEOUT, shim.wait())
        .await
        .expect("shim wait timeout")
        .expect("shim wait");
    assert!(
        exit.success(),
        "shim must exit 0 after EOF on stdin, got: {exit:?}",
    );

    // The audit log records session_start + session_end for the shim's
    // connection; failing here would mean the daemon side of the pipe
    // never observed the session.
    let audit_log = daemon.shutdown().await;
    assert!(
        audit_log.contains(r#""kind":"session_start""#),
        "audit log must record the session; got:\n{audit_log}",
    );
    assert!(
        audit_log.contains(r#""kind":"session_end""#),
        "audit log must record the session_end; got:\n{audit_log}",
    );
}
