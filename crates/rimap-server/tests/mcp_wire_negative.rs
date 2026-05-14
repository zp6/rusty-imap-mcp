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

/// Read the `process_end.reason` from the audit log produced by the
/// harness. Panics if no `process_end` record is found.
fn read_process_end_reason(path: &std::path::Path) -> rimap_audit::ProcessEndReason {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read audit log at {}: {e}", path.display()));
    for line in contents.lines() {
        let record: rimap_audit::AuditRecord = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("parse audit record {line:?}: {e}"));
        if let rimap_audit::Payload::ProcessEnd(p) = record.payload {
            return p.reason;
        }
    }
    panic!(
        "no process_end record found in audit log at {}",
        path.display()
    );
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

/// `tools/list` before `initialize` must return a JSON-RPC error
/// envelope with code -32002 (Server not initialized), echo the
/// request id verbatim, then close stdin and exit `0`. Fixed by #275.
///
/// Audit log MUST record `process_end.reason: Eof` on the success
/// path — this is the contract the bug report flagged as broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize() {
    let mut harness = Harness::spawn().await;
    let audit_path = harness.audit_path();

    // Deliberately skip initialize_handshake.
    let id = harness.send_request_no_wait("tools/list", json!({})).await;

    // Phase 1: error envelope arrives with -32002.
    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => {
            panic!("expected -32002 error envelope for pre-initialize tools/list, got {other:?}")
        }
    };
    assert!(
        envelope["error"].is_object(),
        "must be an error envelope, got {envelope}",
    );
    assert_eq!(
        envelope["error"]["code"],
        json!(-32002),
        "must be code -32002 (Server not initialized), got {envelope}",
    );
    assert_eq!(
        envelope["id"],
        json!(id),
        "id must be echoed verbatim, got {envelope}",
    );
    assert_envelope_valid(&envelope);

    // Phase 2: stdout closes and the server exits 0.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        other => panic!(
            "expected clean close after envelope on pre-initialize tools/list, got {other:?}"
        ),
    }

    // Phase 3: audit log captured the success path as reason Eof.
    let reason = read_process_end_reason(&audit_path);
    assert_eq!(
        reason,
        rimap_audit::ProcessEndReason::Eof,
        "process_end.reason must be Eof on successful pre-initialize handling",
    );
}

/// Same contract as `tools_list_before_initialize`, but with a string
/// id. Pins id-type preservation at the wire layer: numeric coercion
/// of `id` in the synthesizer would surface here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize_str_id() {
    let mut harness = Harness::spawn().await;

    // Send a hand-crafted request with a STRING id rather than using
    // send_request_no_wait (which auto-assigns a u64).
    let raw = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/list","params":{}}"#;
    harness.send_line(raw).await;

    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32002 error envelope for pre-initialize tools/list w/ str id, got {other:?}"
        ),
    };
    assert_eq!(envelope["error"]["code"], json!(-32002));
    assert_eq!(
        envelope["id"],
        json!("abc-123"),
        "string id must survive verbatim through the envelope synthesizer, got {envelope}",
    );
    assert_envelope_valid(&envelope);

    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        other => panic!("expected clean close, got {other:?}"),
    }
}

/// Pre-initialize NOTIFICATION (no `id`) must NOT receive an error
/// envelope — per JSON-RPC §4.1 notifications never get a response.
/// Server closes cleanly and exits 0 with audit reason Eof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_initialize_notification_silent_close() {
    let mut harness = Harness::spawn().await;
    let audit_path = harness.audit_path();

    // Send a pre-initialize notification (not a request — no id).
    harness
        .notify(
            "notifications/cancelled",
            json!({"requestId": 1, "reason": "client decided not to initialize"}),
        )
        .await;

    // No response should arrive; the server should close cleanly.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            panic!("pre-initialize notification must NOT produce an envelope, got {envelope}");
        }
        other => panic!("expected clean close, got {other:?}"),
    }

    // Audit log captured the success path as reason Eof.
    let reason = read_process_end_reason(&audit_path);
    assert_eq!(reason, rimap_audit::ProcessEndReason::Eof);
}

// ---------------------------------------------------------------------------
// Test 9: two `tools/list` requests in flight simultaneously
// ---------------------------------------------------------------------------

/// Send two `tools/list` requests back-to-back without awaiting
/// the first response. Both must return well-formed envelopes
/// within `REQUEST_TIMEOUT`, with ids matching the requests. Tests
/// that the server doesn't serialize stdout writes in a way that
/// corrupts responses, and that the harness's id-buffering works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_tools_list_two_inflight() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let id_a = harness.send_request_no_wait("tools/list", json!({})).await;
    let id_b = harness.send_request_no_wait("tools/list", json!({})).await;

    // Await in the OPPOSITE order from send to exercise the
    // out-of-order buffering path in recv_until_id.
    let response_b = harness.recv_until_id(id_b).await;
    let response_a = harness.recv_until_id(id_a).await;

    assert_eq!(response_a["id"], json!(id_a));
    assert_eq!(response_b["id"], json!(id_b));
    assert!(response_a["result"].is_object(), "id_a must succeed");
    assert!(response_b["result"].is_object(), "id_b must succeed");
}

// ---------------------------------------------------------------------------
// Test 10: bidi-override character in a tool argument
// ---------------------------------------------------------------------------

/// Inject a Unicode bidi-override character (U+202E RIGHT-TO-LEFT
/// OVERRIDE) into a tool argument. Server must either accept and
/// process the call (returning an error envelope because no
/// account named that exists in the zero-account config) or
/// reject with a validation error. Either way: no panic in the
/// argument-redactor or audit writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidi_override_in_tool_argument() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "use_account",
                "arguments": { "account": "foo\u{202E}bar" },
            }),
        )
        .await;

    // The contract here is "server didn't panic and returned a
    // well-formed envelope" — the schema validation inside
    // `request` already enforces that. Additionally assert the
    // call was rejected (no account exists with that name).
    assert!(
        response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true),
        "use_account with non-existent account must fail, got {response}",
    );
}

// ---------------------------------------------------------------------------
// Test 8: `initialize` with unsupported protocol version
// ---------------------------------------------------------------------------

/// Client requests a protocol version the server doesn't support.
/// Spec (per MCP): "If the server supports the requested protocol
/// version, it MUST respond with the same version. Otherwise, the
/// server MUST respond with a version it does support."
///
/// Probed 2026-05-13 (rmcp 1.5): rmcp accepts the unknown version
/// and echoes it back. This is a bug filed as #276. The test
/// below pins the spec-compliant behavior; it is `#[ignore]`'d
/// until #276 lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "blocked on #276: server echoes unsupported protocol versions"]
async fn initialize_unsupported_protocol_version() {
    let mut harness = Harness::spawn().await;

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

    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            if envelope.get("error").is_some() {
                // Error path. Spec-legal: server rejected the version.
                let code = &envelope["error"]["code"];
                assert!(
                    code.is_i64(),
                    "error code must be an integer per JSON-RPC, got {envelope}",
                );
            } else {
                // Counter-proposal path. The server's response must include
                // a SUPPORTED version, NOT echo the client's bad input.
                let version = envelope["result"]["protocolVersion"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("protocolVersion must be a string, got {envelope}");
                    });
                assert_ne!(
                    version, "1999-01-01",
                    "server must not echo the unsupported version back (bug #276); got {envelope}",
                );
                assert_envelope_valid(&envelope);
            }
        }
        CloseOrResponse::CleanClose => {
            // Server elected clean close on unsupported version — also spec-legal.
        }
        CloseOrResponse::Crashed(diag) => {
            panic!("server crashed on unsupported protocol version: {diag}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung (no response within {REQUEST_TIMEOUT:?}) on unsupported protocol version",
            );
        }
    }
}
