//! MCP wire-shape conformance harness (issue #263, Phase 1).
//!
//! Spawns the production `rusty-imap-mcp` binary with a tempdir
//! config that has zero accounts, drives a deterministic JSON-RPC
//! sequence over its stdio, and validates every response against
//! the vendored MCP spec schemas under
//! `tests/fixtures/mcp-spec/2025-11-25/`.
//!
//! Permanent regression net for two real wire-shape bugs:
//!  - #261: `initialize.result.capabilities` was serialized as `{}`.
//!  - `fix/tool-input-schema-object-type`: tools advertised
//!    `inputSchema: {}` with no `type` field.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// MCP protocol version pinned by this harness. Matches the
/// directory under `tests/fixtures/mcp-spec/` and the `LATEST` value
/// in `rmcp 1.5`. Update both when bumping.
const PINNED_PROTOCOL_VERSION: &str = "2025-11-25";

/// Vendored MCP spec schema, compiled in at build time so tests run
/// hermetically (no network, no filesystem dependency beyond the
/// crate source).
const MCP_SCHEMA_JSON: &str = include_str!("fixtures/mcp-spec/2025-11-25/schema.json");

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Owns the spawned child plus its piped stdio.
struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    // Hold the tempdir until the harness drops so the audit log path
    // remains valid for the lifetime of the spawned process.
    _tempdir: TempDir,
}

impl Harness {
    /// Spawn the binary with a zero-account tempdir config.
    #[expect(
        clippy::unused_async,
        reason = "harness API is uniformly async so tests await every constructor"
    )]
    async fn spawn() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();

        // Multi-account format with zero accounts. Task 1 lifted the
        // empty-accounts validator gate, so this is the canonical
        // zero-account shape the loader accepts.
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

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));

        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            _tempdir: tempdir,
        }
    }

    /// Send a JSON-RPC request and return the parsed response value.
    /// Panics on timeout, EOF before a response arrives, or non-JSON output.
    async fn request(&mut self, method: &str, params: Value) -> Value {
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
        let read = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf))
            .await
            .expect("response within timeout")
            .expect("read response");
        assert!(read > 0, "stdout closed before responding to {method}");
        let response: Value = serde_json::from_str(buf.trim_end()).expect("parse response JSON");
        assert_eq!(response["id"], json!(id), "response id must match request");
        response
    }

    /// Send a JSON-RPC notification (no `id`, no response expected).
    async fn notify(&mut self, method: &str, params: Value) {
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
    async fn assert_no_response_within(&mut self, dur: Duration) {
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
    async fn initialize_handshake(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": PINNED_PROTOCOL_VERSION,
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
    async fn send_initialized(&mut self) {
        self.notify("notifications/initialized", json!({})).await;
    }

    /// Close stdin, await the child, and return its exit status.
    async fn shutdown_and_wait(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        timeout(SHUTDOWN_TIMEOUT, self.child.wait())
            .await
            .expect("clean exit within timeout")
            .expect("wait")
    }
}

/// Compile (once) and return a validator for a top-level definition in
/// the vendored MCP schema. `fragment` is the key under
/// `definitions` / `$defs` (e.g. `"InitializeResult"`). Returns an
/// `Arc` so multiple parallel tests can share the compiled validator
/// without lifetime gymnastics.
fn validator_for(fragment: &'static str) -> Arc<jsonschema::Validator> {
    // All function-scoped items declared up front so cache and parsed
    // schema lifetimes are visible from the top of the body
    // (clippy::items_after_statements).
    type Cache = Mutex<HashMap<&'static str, Arc<jsonschema::Validator>>>;
    static PARSED: OnceLock<(Value, &'static str)> = OnceLock::new();
    static CACHE: OnceLock<Cache> = OnceLock::new();

    // Parse the vendored schema exactly once and detect the
    // definitions key (`$defs` for Draft 2020-12, `definitions` for
    // older dialects). The full Value and the detected key are
    // immutable for the lifetime of the test process.
    let parsed = PARSED.get_or_init(|| {
        let full: Value = serde_json::from_str(MCP_SCHEMA_JSON).expect("parse vendored MCP schema");
        let defs_key = if full.get("$defs").is_some() {
            "$defs"
        } else {
            "definitions"
        };
        (full, defs_key)
    });
    let full = &parsed.0;
    let defs_key: &'static str = parsed.1;

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Fast path: read under the lock, return if cached.
    {
        let guard = cache.lock().expect("validator cache mutex poisoned");
        if let Some(v) = guard.get(fragment) {
            return Arc::clone(v);
        }
    }

    // Slow path: compile the fragment validator WITHOUT holding the
    // cache lock, so parallel tests compiling different fragments
    // don't serialize.
    let wrapper = json!({
        "$ref": format!("#/{defs_key}/{fragment}"),
        defs_key: full.get(defs_key).cloned().unwrap_or(json!({})),
    });
    let new_validator =
        Arc::new(jsonschema::validator_for(&wrapper).expect("compile fragment validator"));

    // Insert. If a concurrent thread already inserted while we were
    // compiling, prefer the existing entry to keep the Arc stable.
    let mut guard = cache.lock().expect("validator cache mutex poisoned");
    let entry = guard
        .entry(fragment)
        .or_insert_with(|| Arc::clone(&new_validator));
    Arc::clone(entry)
}

/// Validate a value against a vendored fragment, panicking with the
/// list of errors on failure.
fn assert_valid(value: &Value, fragment: &'static str) {
    let v = validator_for(fragment);
    if !v.is_valid(value) {
        let errors: Vec<String> = v.iter_errors(value).map(|e| e.to_string()).collect();
        panic!(
            "schema validation failed for fragment {fragment}:\n  {}",
            errors.join("\n  ")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_smoke_initialize_returns_valid_envelope() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(response["jsonrpc"], json!("2.0"));
    assert!(
        response["result"].is_object(),
        "initialize response must have a result object, got {response}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialize_advertises_tools_capability() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;

    let result = &response["result"];
    assert_valid(result, "InitializeResult");

    assert_eq!(
        result["protocolVersion"],
        json!(PINNED_PROTOCOL_VERSION),
        "server must echo the pinned protocol version",
    );

    // Regression net for #261: the capabilities object must contain
    // a `tools` key on the wire. Permissive clients ignore the
    // absence; spec-strict clients (e.g. bobshell) refuse to call
    // tools/list.
    let capabilities = &result["capabilities"];
    assert!(
        capabilities.is_object(),
        "capabilities must be an object, got {capabilities}",
    );
    assert!(
        capabilities.get("tools").is_some(),
        "capabilities.tools must be present on the wire; got {capabilities}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_protocol_version_negotiation_matches_vendored_schema() {
    // Sends an initialize request with the LATEST version known to
    // the test, asks the server to echo it back. rmcp negotiates
    // min(client, server), so when the server bumps to a newer
    // LATEST this still succeeds — but if the server somehow
    // negotiates to an older version (e.g. the pinned string is
    // wrong) this test catches it. The fragment-validation tests
    // depend on this invariant.
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(
        response["result"]["protocolVersion"],
        json!(PINNED_PROTOCOL_VERSION),
        "harness pinned to {PINNED_PROTOCOL_VERSION} but server returned a \
         different value; either update PINNED_PROTOCOL_VERSION + the \
         tests/fixtures/mcp-spec/<version>/ directory, or fix the rmcp \
         negotiation regression. Full response: {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialized_notification_elicits_no_response() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
        .assert_no_response_within(Duration::from_millis(200))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_list_returns_object_schemas() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("tools/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListToolsResult");

    let tools = result["tools"].as_array().expect("tools must be an array");
    assert!(
        !tools.is_empty(),
        "tools/list must return at least the infrastructure tools"
    );

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"list_accounts"),
        "list_accounts must be advertised; got names {names:?}",
    );
    assert!(
        names.contains(&"use_account"),
        "use_account must be advertised; got names {names:?}",
    );

    // Regression net for fix/tool-input-schema-object-type: every
    // tool advertised on the wire must declare an object inputSchema.
    // Permissive MCP clients tolerate the absence; Zod-based clients
    // reject the tool.
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("<missing-name>");
        let schema = &tool["inputSchema"];
        assert!(
            schema.is_object(),
            "tool {name}: inputSchema must be an object, got {schema}",
        );
        assert_eq!(
            schema["type"],
            json!("object"),
            "tool {name}: inputSchema.type must be \"object\" (issue #263 regression net), got {schema}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_resources_list_is_empty_for_no_accounts() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("resources/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListResourcesResult");

    let resources = result["resources"]
        .as_array()
        .expect("resources must be an array");
    assert!(
        resources.is_empty(),
        "zero accounts must produce zero resources, got {resources:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_call_unknown_tool_returns_error_envelope() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "this_tool_does_not_exist",
                "arguments": {}
            }),
        )
        .await;

    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    // rmcp 1.5 emits INVALID_PARAMS (-32602) with message "tool not found"
    // for unknown tool names; see rmcp-1.5.0/src/handler/server/router/tool.rs.
    // If this code ever changes, update the assertion and document why
    // — silent drift in rmcp's error mapping is exactly what this test
    // is meant to surface.
    assert_eq!(
        response["error"]["code"],
        json!(-32602),
        "expected -32602 INVALID_PARAMS, got {response}",
    );
    assert!(
        response["error"]["message"].is_string(),
        "error.message must be a string, got {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_unknown_method_returns_minus_32601() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("rimap/no_such_method", json!({})).await;
    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    assert_eq!(
        response["error"]["code"],
        json!(-32601),
        "JSON-RPC method-not-found code, got {response}",
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "error.message must be non-empty, got {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_clean_eof_shutdown_exits_zero() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let status = harness.shutdown_and_wait().await;
    assert!(
        status.success(),
        "server must exit 0 on clean stdin EOF, got {status:?}",
    );
}
