//! Shared helpers for tests that drive the `rusty-imap-mcp shim` binary
//! over its stdio pipes. Each helper is a thin wrapper that captures the
//! `initialize`/`tools/list` boilerplate so individual scenario tests
//! only own their assertions.

#![allow(dead_code)]
#![allow(
    clippy::panic,
    reason = "test helpers panic with diagnostic context on failure"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncWriteExt as _, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout};

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
