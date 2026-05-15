# JSON-RPC Envelope Validator (#277)

**Date:** 2026-05-15
**Issue:** [#277](https://github.com/randomparity/rusty-imap-mcp/issues/277)
**Discovered by:** Phase 4 property testing (#266) — `mcp_wire_proptest::prop_envelope_never_panics`
**Status:** Design approved; implementation pending
**Depends on:** PR #278 (the un-ignore of `prop_envelope_never_panics` lands in the same diff)

## Problem

A client sending a JSON envelope that fails JSON-RPC 2.0 shape validation
— e.g. `{"method":"a"}` (no `jsonrpc`, no `id`) — gets no response and the
connection does not close. The proptest harness times out after
`REQUEST_TIMEOUT` (2 s) and records a `Hung` outcome.

Either response shape — a JSON-RPC `-32600 Invalid Request` envelope or
a clean connection close — would satisfy the spec. Hanging does not.

## Root cause

rmcp 1.5's `JsonRpcMessageCodec::decode`
([`rmcp-1.5.0/src/transport/async_rw.rs:350-354`](https://docs.rs/rmcp/1.5.0/src/rmcp/transport/async_rw.rs.html))
calls `try_parse_with_compatibility` and silently drops the line whenever
that helper returns `Ok(None)`:

```rust
let item = match try_parse_with_compatibility(line, "decode")? {
    Some(item) => item,
    None => return Ok(None), // Skip non-standard message
};
```

`try_parse_with_compatibility`
(`async_rw.rs:245-279`) tries to deserialize as the typed message enum;
on failure it consults `should_ignore_notification`
(`async_rw.rs:223-243`):

```rust
let is_notification = json_value.get("id").is_none();
if is_notification && !is_standard_method(method) {
    return true; // silently ignore
}
```

For the shrunk failing case `{"method":"a"}`: typed deserialization
fails (no `jsonrpc` field), the value parses as a JSON object with a
string `method`, `id` is absent so `is_notification=true`, method `"a"`
isn't on rmcp's `is_standard_method` allowlist, and the helper returns
`true`. The codec returns `Ok(None)`, which `tokio_util::codec::Decoder`
interprets as "not enough data yet — call me again." `FramedRead`
treats this as backpressure and silently waits for the next line. The
dropped line never surfaces on the `Stream`, `service.waiting()` never
sees it, and no response is emitted. The client request id sits
unresolved forever — the observed hang.

The same path applies on EOF: `decode_eof`
(`async_rw.rs:373-393`) routes unparsable terminal lines through
`try_parse_with_compatibility` and returns `Ok(None)` on failure, so
EOF after a malformed line also produces no diagnostic.

The originating property —
`crates/rimap-server/tests/mcp_wire_proptest.rs:311`
(`prop_envelope_never_panics`) — is currently `#[ignore]`'d pending
this fix. The nightly fuzz workflow's per-property guard fails until
the property un-ignores.

### Two cases collapsed under #277

rmcp's silent-drop branch fires for two distinct input classes that
both manifest as `Hung` in the proptest harness:

1. **Invalid JSON-RPC 2.0 envelope** — e.g. `{"method":"a"}` (missing
   `jsonrpc`). The original #277 hang. The server-side fix is to
   respond `-32600` or `-32700` per the validation rules below.
2. **Valid JSON-RPC notification with non-standard method** — e.g.
   `{"jsonrpc":"2.0","method":"foo"}`. Per JSON-RPC 2.0 §4.1, the
   server "MUST NOT reply to a Notification." rmcp's silent-ignore is
   spec-compliant; the proptest's `Hung` outcome is the bug, not the
   server's silence. The fix here is in the property body, not the
   server.

The implementation must address both. The validator (below) closes
case 1; a small property-body change classifies case 2 as a non-fault
outcome.

## Desired behavior

For every line received on stdin after the initialize handshake
completes:

1. **Valid JSON-RPC 2.0 envelope** (request or notification): forward
   unchanged to rmcp.
2. **Empty or whitespace-only line**: skip silently. (Transport noise;
   not part of the JSON-RPC spec.)
3. **Invalid JSON**: emit `-32700 Parse error` envelope with `id: null`.
4. **Valid JSON failing shape checks** (missing `jsonrpc`, wrong
   `jsonrpc` value, missing/non-string `method`, malformed `id`,
   batches): emit `-32600 Invalid Request` envelope with `id` echoed
   if it's the right shape, else `null`.
5. **Session stays alive after rejection**: the next valid envelope on
   the wire continues to dispatch normally.

Pre-initialize handling is unchanged. The validator and the existing
`preinit.rs` are independent: `preinit` handles
`ServerInitializeError::ExpectedInitializeRequest` from rmcp (a
semantically-wrong-but-syntactically-valid first message); the validator
catches everything that rmcp's codec would otherwise silently drop, both
pre- and post-initialize.

### Why respond rather than close

Both are spec-legal. Responding is preferable because:

- **Diagnostic clarity** for real MCP clients with a transient bug — a
  `-32600` envelope tells them what's wrong; a connection close looks
  like an unrelated transport failure.
- **Property-test throughput**: `prop_envelope_never_panics` runs 1000
  cases per invocation. Closing the connection forces the harness to
  respawn the server between cases. Pinned tests in
  `mcp_wire_negative.rs` already prove session-keepalive after
  `-32602` rejections (#276); the same pattern extends here.
- **Consistency**: pre-init rejection (#275) emits `-32002`, version
  rejection (#276) emits `-32602`. Wire-shape rejection joining as
  `-32600` keeps the rejection surface uniform.

## Approach

Replace `rmcp::transport::io::stdio()` in
`crates/rimap-server/src/main.rs:140` with a validator that sandwiches
rmcp's transport via `tokio::io::duplex`:

```
                          ┌──────────── Arc<Mutex<Stdout>> ───────────┐
                          ↓ (rejections)                              ↓ (rmcp frames)
real stdin → [validator] ─┴─valid line─→ duplex_in.our_end            │
                                         duplex_in.rmcp_end → rmcp ───┤
                            duplex_out.our_end ← duplex_out.rmcp_end ←┘
                              ↓
                          [passthrough] ─────────────────────────→ real stdout
```

Two background tokio tasks live for the lifetime of the MCP session,
plus a shared `Arc<tokio::sync::Mutex<tokio::io::Stdout>>` that
serializes all writes to real `stdout` so the validator's rejection
envelopes and rmcp's frames never interleave mid-line:

- **Inbound validator** (`validate_inbound`): reads from real
  `tokio::io::stdin()` via `AsyncBufReadExt::read_until(b'\n', ...)`
  so the terminating `\n` is preserved verbatim. Runs shape
  validation on each line. Valid lines (including the trailing
  newline) are forwarded byte-for-byte to the inbound duplex;
  rmcp's codec sees exactly what the client sent. Invalid lines
  synthesize an error envelope and write it through the shared
  stdout mutex.
- **Outbound passthrough** (`passthrough_outbound`): reads
  newline-framed frames from the outbound duplex via
  `read_until(b'\n', ...)` and writes each complete frame through
  the shared stdout mutex. Line-framed (rather than `tokio::io::copy`)
  so the lock is acquired per complete envelope and never held
  across an await on rmcp's writer.

**Stdout serialization invariant:** all writes to real `stdout` go
through `Arc<Mutex<Stdout>>`; each lock acquisition writes exactly
one complete line (terminating `\n` included) plus a `flush()`, then
releases. Both tasks observe this contract.

EOF on real stdin → validator's `read_until` returns 0 → validator
drops its inbound duplex end → rmcp's `FramedRead` sees EOF on its
next poll → `service.waiting()` resolves cleanly. EOF on the
outbound duplex (rmcp dropped) → passthrough exits → tasks complete.
Broken pipe on real stdout propagates as `io::Error` from the locked
write; whichever task hit it logs and exits, the other follows when
its duplex peer drops.

rmcp's `IntoTransport` impl
(`rmcp/transport/async_rw.rs:22-31`) accepts any
`(R: AsyncRead, W: AsyncWrite)` pair. Our pair is two
`tokio::io::DuplexStream` ends — substitution requires zero changes to
rmcp.

### Validator entry point

```rust
// crates/rimap-server/src/mcp/wire_validator.rs

/// Return a transport-compatible (read, write) pair that pre-validates
/// JSON-RPC 2.0 envelopes on the inbound side. Invalid envelopes are
/// rejected directly to real stdout; valid envelopes are forwarded to
/// the returned read half. The write half is bridged to real stdout
/// unchanged.
///
/// Drop both returned streams to terminate the background tasks.
pub fn stdio_with_validation() -> (DuplexStream, DuplexStream) {
    let (inbound_our_end, inbound_rmcp_end) = tokio::io::duplex(BUF_SIZE);
    let (outbound_rmcp_end, outbound_our_end) = tokio::io::duplex(BUF_SIZE);

    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

    tokio::spawn(validate_inbound(
        tokio::io::stdin(),
        inbound_our_end,
        Arc::clone(&stdout),
    ));
    tokio::spawn(passthrough_outbound(outbound_our_end, stdout));

    (inbound_rmcp_end, outbound_rmcp_end)
}
```

`BUF_SIZE = 64 * 1024`. Generous enough that one well-formed envelope
fits in a single write; both directions are independent tasks so
inbound stalls cannot cause outbound deadlock.

`main.rs::run` swap:

```rust
- let transport = rmcp::transport::io::stdio();
+ let transport = rimap_server::mcp::wire_validator::stdio_with_validation();
```

`rmcp::serve_server(mcp_server, transport)` accepts the duplex pair
via `IntoTransport::<RoleServer, std::io::Error, TransportAdapterAsyncRW>::into_transport`.

### Validation rules

| Input shape | Decision | Wire response | Notes |
|---|---|---|---|
| Empty / whitespace-only line | Skip silently | (none) | Transport noise; rmcp tolerates the same today. |
| Bytes that are not valid JSON | Reject | `-32700 Parse error`, `id: null` | The id is unknowable — `null` per JSON-RPC §5. |
| Valid JSON, not an object (incl. JSON arrays — MCP forbids batches) | Reject | `-32600 Invalid Request`, `id: null` | rmcp 1.5 doesn't speak batches; we reject for forward-compat. |
| Object missing `jsonrpc` | Reject | `-32600`, `id: <echoed or null>` | The #277 minimal failing case. |
| Object with `jsonrpc` ≠ `"2.0"` | Reject | `-32600`, `id: <echoed or null>` | E.g. `"1.0"`, `2.0` (number), `"2.00"`. |
| Object missing `method` | Reject | `-32600`, `id: <echoed or null>` | A response or error message — not valid client input. |
| Object with non-string `method` | Reject | `-32600`, `id: <echoed or null>` | |
| Object with `id` field of disallowed type (object/array/boolean) | Reject | `-32600`, `id: null` | Per JSON-RPC §5: "if there was an error in detecting the id … it MUST be Null." |
| Everything else | Forward to rmcp | — | rmcp may still reject for MCP-specific reasons (unknown method, schema mismatch). |

The forward set is a strict subset of the JSON-RPC 2.0 envelope grammar.
Any envelope rmcp 1.5 accepts and that is also spec-compliant passes
through. The only behavior change vs today is: malformed inputs that
rmcp silently drops now get a `-32600`/`-32700` response.

### `id`-echo policy

Decision tree for the `id` field on a rejection envelope:

- Top-level `"id"` is a JSON string → echo as-is.
- Top-level `"id"` is a JSON number → echo as-is.
- Top-level `"id"` is JSON `null` → echo `null`.
- Top-level `"id"` is missing → `null`.
- Top-level `"id"` is any other shape (object, array, bool) → `null`.
- Input not parseable as JSON → `null`.

Matches `preinit.rs::synthesize_pre_init_error_envelope` and JSON-RPC §5
exactly.

## Error envelope shapes

**Invalid Request** (`-32600`):

```json
{
  "jsonrpc": "2.0",
  "id": <echoed-or-null>,
  "error": {
    "code": -32600,
    "message": "Invalid Request"
  }
}
```

**Parse error** (`-32700`):

```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32700,
    "message": "Parse error"
  }
}
```

No `data` field on either — JSON-RPC §5.1 makes it optional and the
envelope shape is self-describing. Pre-init envelopes (#275) and
version-rejection envelopes (#276) likewise omit `data` unless adding
machine-readable detail (supported-version array for #276); there is no
analogous structured detail for "your envelope was malformed."

Lines are emitted with a trailing `\n` and flushed, same as
`preinit.rs:emit_pre_init_error_envelope`.

## File layout

- **New:** `crates/rimap-server/src/mcp/wire_validator.rs`
  - `pub fn stdio_with_validation() -> (DuplexStream, DuplexStream)` —
    entry point used by `main.rs`.
  - `fn validate(line: &str) -> ValidationOutcome` — pure
    function, no I/O. Unit-testable in isolation.
  - `enum ValidationOutcome { Forward, Skip, Reject(ErrorEnvelope) }`
  - `fn synthesize_error_envelope(code: i32, message: &str, id: Option<Value>) -> String`
  - `async fn validate_inbound(...)` and `async fn passthrough_outbound(...)` —
    the two background tasks.
- **Modified:** `crates/rimap-server/src/main.rs:140` — swap the
  transport constructor as above. One-line change.
- **Modified:** `crates/rimap-server/src/mcp/mod.rs` — `pub mod wire_validator;`
- **Modified:** `crates/rimap-server/tests/mcp_wire_proptest.rs:310` —
  remove the `#[ignore]` from `prop_envelope_never_panics`, and amend
  the property body to recognize spec-legal notifications (see
  "Property body adjustment").
- **Modified:** `crates/rimap-server/tests/mcp_wire_negative.rs` — new
  pinned tests (see "Testing" below).
- **No changes to** `crates/rimap-server/src/mcp/preinit.rs` — its
  responsibility (intercepting `ServerInitializeError::ExpectedInitializeRequest`
  from rmcp) is orthogonal.

## Property body adjustment (case 2)

`prop_envelope_never_panics` currently treats `CloseOrResponse::Hung`
as a `panic!`. After the validator lands, the only remaining `Hung`
source is the spec-compliant silent-ignore path: valid JSON-RPC 2.0
notifications (`jsonrpc:"2.0"`, no `id`, non-standard `method`). The
property body must distinguish that case from a real hang:

```rust
let is_spec_legal_notification = envelope
    .get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
    && envelope.get("id").is_none()
    && envelope.get("method").and_then(|v| v.as_str()).is_some();

// ...
match outcome {
    CloseOrResponse::Response(line) => assert_envelope_valid(&parsed),
    CloseOrResponse::CleanClose => {},
    CloseOrResponse::Crashed(d) => panic!("crashed: {d}"),
    CloseOrResponse::Hung if is_spec_legal_notification => {
        // JSON-RPC §4.1: server MUST NOT reply to a notification.
        // Silence within REQUEST_TIMEOUT is the correct outcome.
        // Harness is poisoned by the timeout path; `with_live_harness`
        // respawns on the next case. The throughput cost is the
        // proptest's choice, not the server's.
    }
    CloseOrResponse::Hung => panic!("hung on {envelope}"),
}
```

The `is_spec_legal_notification` check is in the test body, not the
strategy, so the missing-`jsonrpc` cases that originally triggered
#277 stay in coverage and exercise the validator's reject path. The
strategy is unchanged.

The harness respawn overhead (every notification-shaped case triggers
`with_live_harness` to spawn a fresh server) is acceptable for 1000-
case property runs and matches the cost we already pay for
`CleanClose` outcomes in #275/#276 tests. If the overhead becomes a
problem under nightly higher case counts, a follow-up can add a
`send_notification_and_confirm_silence(line, dur)` harness method
that doesn't poison on timeout.

## Testing

**Property — must un-ignore and pass:**

- `prop_envelope_never_panics` at 1000 cases (`PROPTEST_CASES=1000`,
  the default). Nightly scales via the existing
  `mcp-fuzz-nightly.yml` workflow. The property body is amended per
  the section above before un-ignoring.

**Wire-pinned negative tests** in `mcp_wire_negative.rs` (mirrors the
#275 / #276 conventions — one test per row, strict assertions on code
and id):

1. `envelope_missing_jsonrpc_returns_invalid_request` — input
   `{"method":"a"}` → `-32600`, `id: null`.
2. `envelope_missing_jsonrpc_with_numeric_id_echoes_id` —
   `{"method":"a","id":42}` → `-32600`, `id: 42`.
3. `envelope_missing_jsonrpc_with_string_id_echoes_id` —
   `{"method":"a","id":"abc"}` → `-32600`, `id: "abc"`.
4. `envelope_missing_jsonrpc_with_malformed_id_uses_null` —
   `{"method":"a","id":[1,2]}` → `-32600`, `id: null`.
5. `envelope_with_wrong_jsonrpc_value_returns_invalid_request` —
   `{"jsonrpc":"1.0","method":"x","id":1}` → `-32600`, `id: 1`.
6. `envelope_with_non_string_method_returns_invalid_request` —
   `{"jsonrpc":"2.0","method":42,"id":1}` → `-32600`, `id: 1`.
7. `envelope_batch_array_returns_invalid_request` —
   `[{"jsonrpc":"2.0","method":"x","id":1}]` → `-32600`, `id: null`.
8. `envelope_invalid_json_returns_parse_error` — `not valid json` →
   `-32700`, `id: null`.
9. `envelope_empty_line_is_skipped` — empty line followed by valid
   `tools/list` request → `tools/list` response arrives on time, no
   spurious error envelope precedes it.
10. `session_survives_invalid_envelope` — valid `initialize` →
    invalid envelope → valid `tools/list`. The third message gets a
    normal response; the session is not closed.

All tests run against the production binary via the existing
`Harness` — no test-only hooks needed in the validator.

**Unit tests** in `wire_validator.rs::tests` covering `validate()` in
isolation, one assertion per row of the validation rules table. Pure
function, no async, ~30 lines of test code.

**Integration regression** — full `mcp_wire_negative.rs` and
`mcp_wire_proptest.rs` suites must pass with the validator in place
without ANY existing test going from pass → fail. The validator's
forward set is a strict superset of the JSON-RPC 2.0 grammar, so
this should hold by construction.

## Risks & mitigations

- **Validator framing drift from rmcp's codec.** rmcp splits on `\n`
  and tolerates a trailing `\r` (`without_carriage_return` in
  `async_rw.rs`). Validator uses `read_until(b'\n', ...)` and forwards
  the buffer (including the trailing `\n`) verbatim — rmcp's codec
  then strips `\r` and parses normally. Strict validation runs on
  the buffer minus the trailing `\n`/`\r`, matching rmcp's view.
  Pin a wire-level test with `\r\n` line endings.
- **Validator stricter than rmcp on a shape rmcp accepts.** The
  forward set is the JSON-RPC 2.0 envelope grammar — rmcp's
  compatibility shim is a strict subset of that. Mitigation: every
  existing `mcp_wire_negative.rs` test continues to pass unchanged.
- **Duplex buffer deadlock.** The two duplex pairs are independent;
  one direction stalling cannot block the other. Buffer is 64 KiB,
  far larger than any sane envelope. Mitigation: leave the buffer
  generous; the proptest will exercise heterogeneous envelope sizes.
- **Async cancellation safety.** The validator and passthrough tasks
  are spawned with `tokio::spawn`; they own their I/O handles and
  drop them on task exit. Cancellation on the outer runtime cancels
  the tasks, which closes the duplex ends, which surfaces to rmcp as
  EOF or write-error — the same shutdown shape as today's direct
  stdio transport.
- **Backpressure under sustained malformed input.** Each rejection
  writes to real stdout from the validator task. A slow consumer
  could stall the validator; that's identical to today's stall
  behavior on rmcp's outbound write under a slow consumer, and is
  out of scope.

## Dependencies and merge plan

This fix is the final merge blocker for PR #278 (the #266 fuzzing
umbrella). The implementation lands on
`feature/issue-266-mcp-fuzzing` directly, in one diff that includes:

1. `wire_validator.rs` and `main.rs` swap.
2. Property body amendment for `is_spec_legal_notification` (case 2
   distinction).
3. Un-ignore `prop_envelope_never_panics`.
4. The 10 new wire-pinned tests in `mcp_wire_negative.rs`.
5. Mirror docs (this spec is committed before implementation starts).

Once green, PR #278 comes out of draft and goes to review with all
three blockers (#275, #276, #277) resolved.

## Out of scope

- **Upstream rmcp fix.** Filing a separate issue against rmcp to make
  `JsonRpcMessageCodec::decode` propagate rejections is reasonable
  future work but not on this critical path. The local validator
  closes the contract independently.
- **Outbound validation.** Our server's outbound envelopes come
  through rmcp's typed `ServerJsonRpcMessage` and are well-formed by
  construction. The passthrough side does not need to validate.
- **Custom error data fields.** Sticking to `{code, message}` for
  these envelopes is sufficient. Re-evaluate if a client reports
  needing structured diagnostics.
