//! Stdio JSON-RPC harness used by both Phase 1 (`mcp_wire_conformance.rs`)
//! and Phase 3 (`e2e_wire.rs`). Spawns the production `rusty-imap-mcp`
//! binary (compiled with the `test-support` feature via the dev-dependency
//! in Cargo.toml) and exchanges line-delimited JSON-RPC envelopes over stdin/stdout. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`
//! and the Phase 3 sibling spec for the design context.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    next_id: u64,
    /// Path to the file capturing the child's stderr. Read on assertion
    /// failure so the binary's `tracing::error!` output surfaces in the
    /// panic message instead of being silently lost. Using a `File`-backed
    /// stdio target (rather than an async drain) avoids the runtime
    /// contention that made the prior `Stdio::piped()` capture hang every
    /// wire test on the 2-second `REQUEST_TIMEOUT` (see commit 3a58304).
    stderr_log: PathBuf,
    // Hold the tempdir until the harness drops so the audit log path
    // remains valid for the lifetime of the spawned process.
    _tempdir: TempDir,
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
        let stderr_log = tempdir.path().join("rusty-imap-mcp.stderr.log");
        let stderr_file = File::create(&stderr_log).expect("create stderr log file");

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true);
        for (k, v) in extra_envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));

        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            stderr_log,
            _tempdir: tempdir,
        }
    }

    /// Read whatever the child has written to its stderr log so far.
    /// Used in assertion diagnostics; tolerates a missing or unreadable
    /// file (returns an empty string) so callers can rely on it inside
    /// panic messages.
    pub fn captured_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
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
        let read_result = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf)).await;
        let read = match read_result {
            Ok(io_result) => io_result.unwrap_or_else(|e| {
                panic!(
                    "read response error on {method}: {e}\n\
                     --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                )
            }),
            Err(elapsed) => panic!(
                "response to {method} did not arrive within {REQUEST_TIMEOUT:?} ({elapsed})\n\
                 --- captured child stderr ---\n{}",
                self.captured_stderr(),
            ),
        };
        assert!(
            read > 0,
            "stdout closed before responding to {method}\n\
             --- captured child stderr ---\n{}",
            self.captured_stderr(),
        );
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
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Err(_) => {} // timeout → no response, as expected
            Ok(Ok(0)) => panic!("stdout closed unexpectedly"),
            Ok(Ok(_)) => panic!("expected no response within {dur:?}, got: {buf:?}"),
            Ok(Err(e)) => panic!("read error: {e}"),
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
        timeout(SHUTDOWN_TIMEOUT, self.child.wait())
            .await
            .expect("clean exit within timeout")
            .expect("wait")
    }
}
