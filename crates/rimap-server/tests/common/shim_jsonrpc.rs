//! Shared helpers for tests that drive the `rusty-imap-mcp shim` binary
//! over its stdio pipes. Each helper is a thin wrapper that captures the
//! `initialize`/`tools/list` boilerplate so individual scenario tests
//! only own their assertions.

#![allow(dead_code)]
#![allow(
    clippy::panic,
    reason = "test helpers panic with diagnostic context on failure"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Per-read timeout for the shim's stdout. 15s gives debug-build cold
/// starts headroom on slow CI runners; the local-dev common case takes
/// well under a second.
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Build the socket path the production resolver returns when
/// `XDG_RUNTIME_DIR` is `runtime_dir` and `TMPDIR` is unset.
///
/// Mirrors `daemon::socket_path::resolve` (Linux XDG branch). Kept in
/// sync by hand: if the resolver's algorithm changes, this helper must
/// change too.
#[must_use]
pub fn resolved_socket_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("rusty-imap-mcp").join("daemon.sock")
}

/// Write a single JSON-RPC frame (one line + newline) to the shim's
/// stdin and flush.
pub async fn send_frame(stdin: &mut ChildStdin, value: &Value, what: &str) {
    let line = format!("{value}\n");
    stdin
        .write_all(line.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write {what}: {e}"));
    stdin
        .flush()
        .await
        .unwrap_or_else(|e| panic!("flush {what}: {e}"));
}

/// Read one JSON-RPC frame from the shim's stdout, fail if it doesn't
/// arrive within [`READ_TIMEOUT`], and return the parsed value.
pub async fn recv_frame(reader: &mut Lines<BufReader<ChildStdout>>, what: &str) -> Value {
    let line = tokio::time::timeout(READ_TIMEOUT, reader.next_line())
        .await
        .unwrap_or_else(|_| panic!("{what} response timed out after {READ_TIMEOUT:?}"))
        .unwrap_or_else(|e| panic!("{what} read error: {e}"))
        .unwrap_or_else(|| panic!("{what} EOF before response"));
    serde_json::from_str(&line)
        .unwrap_or_else(|e| panic!("{what} response is not valid JSON: {e}; line: {line}"))
}

/// Allocate a tempdir to use as `XDG_RUNTIME_DIR`, chmod it 0700, and
/// pre-create the `<runtime_dir>/rusty-imap-mcp/` parent so the daemon
/// socket can bind there. Returns the tempdir; callers pass `.path()`
/// into both [`DovecotDaemon::try_spawn_at`] and the shim's
/// `XDG_RUNTIME_DIR` env var.
#[must_use]
pub fn make_runtime_dir() -> TempDir {
    let runtime_dir = TempDir::new().unwrap_or_else(|e| panic!("runtime dir: {e}"));
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("chmod 0700 on runtime dir: {e}"));
    let socket_path = resolved_socket_path(runtime_dir.path());
    let Some(socket_parent) = socket_path.parent() else {
        panic!("resolved socket path has no parent");
    };
    std::fs::create_dir_all(socket_parent).unwrap_or_else(|e| panic!("create socket parent: {e}"));
    std::fs::set_permissions(socket_parent, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("chmod 0700 on socket parent: {e}"));
    runtime_dir
}

/// Spawn `rusty-imap-mcp shim` against `runtime_dir`, complete the MCP
/// `initialize` + `notifications/initialized` handshake, and return the
/// live child + pipe handles for the test to drive further requests.
///
/// `client_name` distinguishes the shim's `clientInfo.name` for log
/// triage when a test fails — pick something descriptive of the
/// scenario.
pub async fn spawn_shim_and_initialize(
    runtime_dir: &Path,
    client_name: &str,
) -> (Child, ChildStdin, Lines<BufReader<ChildStdout>>) {
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
        .unwrap_or_else(|e| panic!("spawn shim: {e}"));
    let mut stdin = shim.stdin.take().unwrap_or_else(|| panic!("shim stdin"));
    let stdout = shim.stdout.take().unwrap_or_else(|| panic!("shim stdout"));
    let mut reader = BufReader::new(stdout).lines();

    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "0.0.1"}
        }
    });
    send_frame(&mut stdin, &init, "initialize").await;
    let _ = recv_frame(&mut reader, "initialize").await;

    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    send_frame(&mut stdin, &initialized, "notifications/initialized").await;

    (shim, stdin, reader)
}
