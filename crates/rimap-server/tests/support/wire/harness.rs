//! Stdio JSON-RPC harness used by both Phase 1 (`mcp_wire_conformance.rs`)
//! and Phase 3 (`e2e_wire.rs`). Spawns the production `rusty-imap-mcp`
//! binary (compiled with the `test-support` feature via the dev-dependency
//! in Cargo.toml) and exchanges line-delimited JSON-RPC envelopes over stdin/stdout. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`
//! and the Phase 3 sibling spec for the design context.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use super::schema::assert_envelope_valid;

/// MCP protocol version pinned by this harness. Matches the
/// directory under `tests/fixtures/mcp-spec/` and the `LATEST` value
/// in `rmcp 1.5`. Update both when bumping.
pub const PINNED_PROTOCOL_VERSION: &str = "2025-11-25";

/// Vendored MCP spec schema, compiled in at build time so tests run
/// hermetically (no network, no filesystem dependency beyond the
/// crate source).
pub(crate) const MCP_SCHEMA_JSON: &str =
    include_str!("../../fixtures/mcp-spec/2025-11-25/schema.json");

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
// Under `cargo nextest run` with the full workspace suite (~1100 tests
// in parallel), the EOF-to-exit slice for `wire_clean_eof_shutdown_exits_zero`
// can exceed a tight 1 s budget on CPU-contended runners. 5 s remains
// tight enough to fail-fast on a real hang while absorbing scheduling
// jitter when other tests are spawning binaries / parsers concurrently.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns the spawned child plus its piped stdio.
pub struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Stderr drain buffer, updated by a background task.
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    // Hold the tempdir until the harness drops so the audit log path
    // remains valid for the lifetime of the spawned process.
    _tempdir: TempDir,
}

/// Maximum bytes retained in the stderr drain buffer. The head is the most
/// useful diagnostic, so we truncate rather than ring-buffer.
const STDERR_CAP: usize = 64 * 1024;

/// Snapshot the captured stderr for diagnostic messages.
fn stderr_snapshot(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    buf.lock()
        .map(|g| String::from_utf8_lossy(&g).into_owned())
        .unwrap_or_default()
}

/// Log stderr drain errors to test output. Justification: test diagnostics.
#[expect(clippy::print_stderr, reason = "test diagnostics")]
fn log_stderr_drain_error(e: &std::io::Error) {
    eprintln!("[harness] stderr drain error: {e}");
}

impl Harness {
    /// Spawn with the legacy zero-account config (Phase 1 default).
    /// Builds a multi-account TOML with `accounts = []`, an audit
    /// path under a fresh tempdir, and calls `spawn_with_config`.
    pub async fn spawn() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();
        let config = format!(
            r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");
        Self::spawn_with_config(&config_path, tempdir, &[]).await
    }

    /// Spawn the binary against a caller-supplied config. The
    /// `tempdir` is held by the returned `Harness` so its lifetime
    /// covers the child process's audit path.
    ///
    /// `extra_envs` is forwarded to the child verbatim. Phase 3 uses
    /// this to inject `RUSTY_IMAP_MCP_PASSWORD` (the env-var
    /// fallback for the keyring) without polluting the test
    /// process's env.
    #[expect(clippy::unused_async, reason = "uniform async surface")]
    pub async fn spawn_with_config(
        config_path: &std::path::Path,
        tempdir: TempDir,
        extra_envs: &[(&str, &str)],
    ) -> Self {
        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in extra_envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let stderr = child.stderr.take().expect("stderr");

        // Drain stderr into a shared buffer so the binary's tracing
        // output is included in panic messages on assertion failure.
        let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let stderr_clone = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            let mut reader = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Err(e) => {
                        log_stderr_drain_error(&e);
                        break;
                    }
                    Ok(n) => {
                        if let Ok(mut guard) = stderr_clone.lock() {
                            guard.extend_from_slice(&buf[..n]);
                            if guard.len() > STDERR_CAP {
                                guard.truncate(STDERR_CAP);
                            }
                        }
                    }
                }
            }
        });

        Self {
            child,
            stdin,
            stdout,
            stderr_buf,
            next_id: 0,
            _tempdir: tempdir,
        }
    }

    /// Snapshot the captured stderr for diagnostic messages.
    #[expect(
        dead_code,
        reason = "available for future diagnostic use; no test binary calls it yet"
    )]
    pub fn captured_stderr(&self) -> String {
        stderr_snapshot(&self.stderr_buf)
    }

    /// Send a JSON-RPC request and return the parsed response value.
    /// Panics on timeout, EOF before a response arrives, or non-JSON output.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");

        let mut buf = String::new();
        let stderr_handle = Arc::clone(&self.stderr_buf);
        let read = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "response within timeout for {method}; child stderr:\n{}",
                    stderr_snapshot(&stderr_handle)
                )
            })
            .unwrap_or_else(|e| {
                panic!(
                    "read response for {method}: {e}; child stderr:\n{}",
                    stderr_snapshot(&stderr_handle)
                )
            });
        assert!(read > 0, "stdout closed before responding to {method}");
        let response: Value = serde_json::from_str(buf.trim_end()).expect("parse response JSON");
        assert_eq!(response["id"], json!(id), "response id must match request");
        assert_envelope_valid(&response);
        response
    }

    /// Send a JSON-RPC notification (no `id`, no response expected).
    pub async fn notify(&mut self, method: &str, params: Value) {
        let envelope = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write notification");
        self.stdin.flush().await.expect("flush notification");
    }

    /// Assert no bytes arrive on stdout for the given duration.
    pub async fn assert_no_response_within(&mut self, dur: Duration) {
        let mut buf = String::new();
        let stderr_handle = Arc::clone(&self.stderr_buf);
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Err(_) => {} // timeout → no response, as expected
            Ok(Ok(0)) => panic!(
                "stdout closed unexpectedly; child stderr:\n{}",
                stderr_snapshot(&stderr_handle)
            ),
            Ok(Ok(_)) => panic!(
                "expected no response within {dur:?}, got: {buf:?}; child stderr:\n{}",
                stderr_snapshot(&stderr_handle)
            ),
            Ok(Err(e)) => panic!(
                "read error: {e}; child stderr:\n{}",
                stderr_snapshot(&stderr_handle)
            ),
        }
    }

    /// Send an MCP `initialize` request with the pinned protocol
    /// version and return the response.
    pub async fn initialize_handshake(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": ProtocolVersion::LATEST.as_str(),
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-conformance-harness",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
        .await
    }

    /// Send `notifications/initialized` after the handshake.
    pub async fn send_initialized(&mut self) {
        self.notify("notifications/initialized", json!({})).await;
    }

    /// Close stdin, await the child, and return its exit status.
    pub async fn shutdown_and_wait(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        let stderr_handle = Arc::clone(&self.stderr_buf);
        timeout(SHUTDOWN_TIMEOUT, self.child.wait())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "clean exit within timeout; child stderr:\n{}",
                    stderr_snapshot(&stderr_handle)
                )
            })
            .unwrap_or_else(|e| {
                panic!(
                    "wait: {e}; child stderr:\n{}",
                    stderr_snapshot(&stderr_handle)
                )
            })
    }
}
