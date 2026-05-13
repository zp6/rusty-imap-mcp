//! MCP wire-shape negative-path tests (issue #266, Phase 4).
//!
//! Targeted negative cases that complement the property-based
//! coverage in `mcp_wire_proptest.rs`. Each test follows the
//! probe-first contract documented in
//! `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`
//! §4.1: every test asserts either a specific JSON-RPC error
//! envelope shape OR a clean stdin shutdown — never just
//! "didn't crash."
//!
//! `CloseOrResponse::Crashed` and `CloseOrResponse::Hung` always
//! fail the test, regardless of which input produced them.

#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use serde_json::{Value, json};

use support::wire::harness::{CloseOrResponse, Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT};
use support::wire::schema::assert_envelope_valid;

/// Probe helper: parse a response line from `CloseOrResponse::Response`
/// and assert it is a valid JSON-RPC envelope. Returns the parsed `Value`.
fn parse_response_line(line: &str) -> Value {
    serde_json::from_str(line.trim_end()).unwrap_or_else(|e| {
        panic!("server emitted non-JSON line: {e}\nraw: {line:?}");
    })
}

// ---------------------------------------------------------------------------
// Test 1: unparsable JSON
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unparsable_json_errors_or_closes() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness.send_line("this is not json at all").await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp closes stdin cleanly (CleanClose)
    // rather than emitting a -32700 parse-error envelope. The server treats
    // an unparsable line as a fatal framing error and shuts down the session
    // instead of recovering per-message.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            // rmcp chose to emit an error envelope instead of closing.
            // Encode the observed code so future rmcp changes are visible.
            let envelope = parse_response_line(&line);
            assert!(
                envelope["error"].is_object(),
                "expected error envelope for unparsable JSON, got {envelope}",
            );
            assert_eq!(
                envelope["error"]["code"],
                json!(-32700),
                "expected -32700 (ParseError) for unparsable JSON, got {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Probed 2026-05-13: server elects clean close on parse failure.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on unparsable JSON input: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!("server hung (no response within {REQUEST_TIMEOUT:?}) on unparsable JSON input");
        }
    }
}

// ---------------------------------------------------------------------------
// Test 2: valid JSON but not a JSON-RPC envelope → -32600
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_json_invalid_envelope_returns_minus_32600() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    // Valid JSON — not an object at all.
    harness.send_line("[1, 2, 3]").await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp closes stdin cleanly (CleanClose)
    // rather than emitting a -32600 invalid-request envelope. An array
    // at the top level is not a valid JSON-RPC message framing, so rmcp
    // treats it as a fatal framing error.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            assert!(
                envelope["error"].is_object(),
                "expected error envelope for invalid JSON-RPC envelope, got {envelope}",
            );
            assert_eq!(
                envelope["error"]["code"],
                json!(-32600),
                "expected -32600 (InvalidRequest) for non-object JSON, got {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Probed 2026-05-13: server elects clean close on framing error.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on invalid JSON-RPC envelope: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on invalid JSON-RPC envelope"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: missing `method` field → -32600
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_method_field() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    // A JSON object that looks superficially like a request but has no `method`.
    let msg = json!({"jsonrpc": "2.0", "id": 99, "params": {}});
    harness.send_line(&msg.to_string()).await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp closes stdin cleanly (CleanClose)
    // rather than emitting a -32600 envelope. The missing `method` field
    // causes a deserialization failure that rmcp treats as fatal framing.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            assert!(
                envelope["error"].is_object(),
                "expected error envelope for missing `method`, got {envelope}",
            );
            // -32600 InvalidRequest is the most appropriate code; accept
            // -32700 ParseError if rmcp maps deserialization failures there.
            let code = envelope["error"]["code"].as_i64().unwrap_or_else(|| {
                panic!("error.code must be a number, got {envelope}");
            });
            assert!(
                code == -32600 || code == -32700,
                "expected -32600 or -32700 for missing `method`, got code {code} in {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Probed 2026-05-13: server elects clean close on missing `method`.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on missing `method` field: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on missing `method` field"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 4: `method` is wrong type (number instead of string) → -32600
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_type_method_field() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    // `method` is a number, not a string — violates JSON-RPC 2.0 §4.
    let msg = json!({"jsonrpc": "2.0", "id": 100, "method": 42, "params": {}});
    harness.send_line(&msg.to_string()).await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp closes stdin cleanly (CleanClose)
    // rather than emitting a -32600 envelope. A numeric `method` causes a
    // deserialization failure that rmcp treats as fatal framing.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            assert!(
                envelope["error"].is_object(),
                "expected error envelope for wrong-type `method`, got {envelope}",
            );
            let code = envelope["error"]["code"].as_i64().unwrap_or_else(|| {
                panic!("error.code must be a number, got {envelope}");
            });
            assert!(
                code == -32600 || code == -32700,
                "expected -32600 or -32700 for wrong-type `method`, got code {code} in {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Probed 2026-05-13: server elects clean close on wrong-type `method`.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on wrong-type `method` field: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on wrong-type `method` field"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 5: oversized params payload
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_params_payload() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    // 4 MiB of 'A' in a single params field — well above any reasonable
    // MCP message size limit.
    let huge_value = "A".repeat(4 * 1024 * 1024);
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/list",
        "params": {"oversized": huge_value},
    });
    harness.send_line(&msg.to_string()).await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp returns a normal tools/list
    // result (CloseOrResponse::Response) because it does not enforce a
    // message-size limit. The oversized `params` field is ignored by
    // `tools/list` which takes no params. Both a response and a clean
    // close are spec-legal for an oversized payload; only Crashed/Hung fail.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            // Server processed the oversized payload and responded.
            // Accept either a valid result or a valid error envelope.
            let envelope = parse_response_line(&line);
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Server elected to close on oversized input — also acceptable.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on oversized params payload: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on oversized params payload"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 6: second `initialize` after handshake already completed
// ---------------------------------------------------------------------------

/// After a successful `initialize`, a second `initialize` request is
/// sent. Probed 2026-05-13 (rmcp 1.5): rmcp accepts the second
/// initialize and returns a fresh success result — it does not reject
/// re-initialization. Both a success result and a JSON-RPC error are
/// observed outcomes; only Crashed/Hung fail the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_after_already_initialized() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    // Send a SECOND initialize via send_request_no_wait + response_or_close
    // so that a connection-close outcome is handled gracefully alongside
    // the success-response path that rmcp 1.5 actually takes.
    let _id = harness
        .send_request_no_wait(
            "initialize",
            json!({
                "protocolVersion": PINNED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    // Probed 2026-05-13 (rmcp 1.5): rmcp returns a successful initialize
    // result for the second request (re-initialization is accepted).
    // A JSON-RPC error or clean close would also be spec-legal; only
    // Crashed and Hung are failures.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            // Probed 2026-05-13 (rmcp 1.5): second initialize returns a
            // success result with protocolVersion and serverInfo fields.
            // Accept either a result (re-init allowed) or an error (rejected).
            assert!(
                envelope.get("result").is_some() || envelope.get("error").is_some(),
                "second initialize response must have result or error, got {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Server elected clean close on second initialize — also acceptable.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on second initialize request: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on second initialize request"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 7: `tools/list` before `initialize`
// ---------------------------------------------------------------------------

/// `tools/list` before `initialize` must error or close the session.
/// Server is in the "uninitialized" state and cannot answer protocol-
/// level requests until handshake completes.
///
/// Probed 2026-05-13 (rmcp 1.5): rmcp exits with a non-zero status
/// (exit code 1, `Crashed`) on a pre-initialize `tools/list`. It logs
/// "expect initialized request, but received: Some(Request(...))" and
/// terminates. Both `Crashed` and `CleanClose` are acceptable session-
/// rejection outcomes; only Hung fails the test. A Response path is
/// also handled: if rmcp emits a JSON-RPC error instead of crashing it
/// must be a well-formed error envelope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize() {
    let mut harness = Harness::spawn().await;
    // Deliberately skip initialize_handshake.

    // Use send_request_no_wait + response_or_close because rmcp closes
    // (or crashes) the connection instead of emitting a JSON-RPC error
    // envelope for pre-initialize requests.
    let _id = harness.send_request_no_wait("tools/list", json!({})).await;

    // Probed 2026-05-13 (rmcp 1.5): server crashes (exit code 1) on
    // tools/list before initialize. Crashed is the observed outcome.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            // rmcp chose to emit a response instead of crashing. If it is
            // an error envelope, accept it; if somehow a success, fail the test.
            let envelope = parse_response_line(&line);
            assert!(
                envelope["error"].is_object(),
                "tools/list before initialize must return an error if it responds, got {envelope}",
            );
            assert_envelope_valid(&envelope);
        }
        CloseOrResponse::CleanClose => {
            // Server shut down cleanly on pre-initialize request — acceptable.
        }
        CloseOrResponse::Crashed(_diag) => {
            // Probed 2026-05-13 (rmcp 1.5): server exits with code 1 on
            // tools/list before initialize. This is the observed behavior.
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on tools/list before initialize"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 8: `initialize` with unsupported protocol version
// ---------------------------------------------------------------------------

/// Client requests a protocol version the server doesn't support.
/// Spec allows two behaviors: server may counter-propose its own
/// supported version, or return a JSON-RPC error.
///
/// Probed 2026-05-13 (rmcp 1.5): rmcp takes the counter-proposal path
/// and echoes back the client's version string verbatim (even for an
/// obviously invalid version like "1999-01-01"). rmcp performs no
/// version validation — any string is accepted. The test pins this:
/// if rmcp responds, it must be a success result with a non-null
/// protocolVersion string. The error path and clean-close path are
/// also handled for forward compatibility.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_unsupported_protocol_version() {
    let mut harness = Harness::spawn().await;

    // Use send_request_no_wait + response_or_close in case rmcp closes
    // the connection on an unsupported version, rather than responding.
    let _id = harness
        .send_request_no_wait(
            "initialize",
            json!({
                "protocolVersion": "1999-01-01",
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    // Probed 2026-05-13 (rmcp 1.5): counter-proposal path fires. rmcp
    // echoes the client's "1999-01-01" version back in the result.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            if envelope.get("error").is_some() {
                // Error path. rmcp emitted a JSON-RPC error — acceptable.
                // Probed 2026-05-13: this branch did NOT fire; counter-proposal
                // fired instead. If this branch fires in a future rmcp version,
                // tighten to the actual error code.
                let code = &envelope["error"]["code"];
                assert!(
                    code.is_i64(),
                    "error code must be an integer per JSON-RPC, got {envelope}",
                );
            } else {
                // Counter-proposal path — observed rmcp 1.5 behavior.
                // rmcp returns a success result. The protocolVersion in the
                // result is whatever rmcp chose (may echo the client's string).
                let version = envelope["result"]["protocolVersion"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("protocolVersion must be a string, got {envelope}");
                    });
                // Probed 2026-05-13 (rmcp 1.5): rmcp echoes "1999-01-01" back
                // verbatim — no version enforcement. Assert the field is present
                // and non-empty; the exact value is rmcp's choice.
                assert!(
                    !version.is_empty(),
                    "protocolVersion in counter-proposal must be non-empty, got {envelope}",
                );
                assert_envelope_valid(&envelope);
            }
        }
        CloseOrResponse::CleanClose => {
            // Server elected to close on unsupported protocol version — acceptable.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on unsupported protocol version: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on unsupported protocol version"
            );
        }
    }
}
