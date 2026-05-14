# Pre-Initialize Request Handling (#275)

**Date:** 2026-05-14
**Issue:** [#275](https://github.com/randomparity/rusty-imap-mcp/issues/275)
**Discovered by:** Phase 4 negative-path testing (#266)
**Status:** Design approved; implementation pending

## Problem

A JSON-RPC client that sends any non-`initialize`, non-`ping` request as its
first message causes `rusty-imap-mcp` to exit with code `1` and a stderr log:

```
expect initialized request, but received: Some(Request(ListToolsRequest(...)))
```

The crash corrupts audit trails (the `process_end` record is emitted with
`reason: Error`) and gives misbehaving clients no actionable wire-level signal.

## Root cause

The rmcp 1.5 service loop
([`rmcp-1.5.0/src/service/server.rs:172-204`](https://docs.rs/rmcp/1.5.0/src/rmcp/service/server.rs.html))
accepts only `PingRequest` or `InitializeRequest` as the first message; anything
else short-circuits to
`ServerInitializeError::ExpectedInitializeRequest(Some(msg))`. The server
entrypoint at `crates/rimap-server/src/main.rs:138-140` wraps that error with
`anyhow!`, which propagates to `main()` and triggers `ExitCode::FAILURE`.

The originating test —
`crates/rimap-server/tests/mcp_wire_negative.rs:339-368`
(`tools_list_before_initialize`) — is currently `#[ignore]`'d pending this fix.

## Desired behavior

1. **Pre-initialize Request** (e.g. `tools/list`): reply with a JSON-RPC error
   envelope echoing the request's `id`, then close cleanly and exit `0`.
2. **Pre-initialize Notification or Response**: drop silently, close cleanly,
   exit `0`. (Per JSON-RPC §4.1, notifications never receive a response;
   a response without a matching server request is malformed.)
3. **Audit log**: `process_end` emits with `reason: Eof`, not `Error`.

## Approach

A new `crates/rimap-server/src/mcp/preinit.rs` module exposes one pure helper:

```rust
pub(crate) fn synthesize_pre_init_error_envelope(
    msg: &ClientJsonRpcMessage,
) -> Option<String>
```

The helper returns `Some(<newline-terminated JSON line>)` for the `Request`
variant and `None` for `Notification` / `Response` / other variants. No I/O,
no transport access — it is trivially unit-testable against
`serde_json::Value` snapshots.

The call site in `main.rs::run` matches on the specific rmcp error variant:

```rust
let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
    Ok(svc) => svc,
    Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
        if let Some(line) = synthesize_pre_init_error_envelope(&msg) {
            let mut out = tokio::io::stdout();
            let _ = out.write_all(line.as_bytes()).await;
            let _ = out.flush().await;
        }
        return Ok(());
    }
    Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
};
```

Returning `Ok(())` causes the outer `mcp_result` to be `Ok`, which the
existing `process_end` block at `main.rs:158-171` records as `reason: Eof`
and the process exits `0`.

Because rmcp has already consumed its `tokio::io::Stdout` by the time the
error returns, the helper writes through a freshly acquired
`tokio::io::stdout()` handle. This is safe: both handles wrap the same
process stdout file descriptor.

The cancellation channel + drainer (`main.rs:133-134`) only matter for
mid-dispatch cancellation; the early-return path skips them entirely.

## Envelope shape

```json
{
  "jsonrpc": "2.0",
  "id": <echoed verbatim>,
  "error": {
    "code": -32002,
    "message": "Server not initialized: send `initialize` before any other request"
  }
}
```

- **Code `-32002`** lives in the JSON-RPC server-error band (`-32000..=-32099`)
  and is the conventional "Server not initialized" code in the LSP / MCP
  ecosystem. It does not collide with existing codes in
  `crates/rimap-server/src/mcp/error.rs`: `-32001` posture-denied,
  `-32003` rate-limited, `-32004` breaker, `-32005` attachment-too-large.
  A new `pub const NOT_INITIALIZED: McpCode = McpCode(-32002);` is added
  to that file so the code registry remains in one place; `preinit.rs`
  references it from there.
- **`id` echoing**: numbers, strings, and `null` pass through unchanged
  via `serde_json::Value`. No `as_u64()` coercion.
- **Message text**: a fixed string. No echo of the offending method name
  or any client-supplied content (matches the opaque-message pattern
  already used for `ProtectedFolder` / `ExpungeDenied` at
  `crates/rimap-server/src/mcp/error.rs:41-44`).
- **No `data` field**.

## Test plan

### Unit (`crates/rimap-server/src/mcp/preinit.rs`)

1. `Request` with numeric id → envelope with same numeric id,
   `error.code == -32002`, valid JSON-RPC framing.
2. `Request` with string id → envelope with same string id.
3. `Request` with `null` id → envelope with `id: null`.
4. `Notification` → returns `None`.
5. `Response` → returns `None`.
6. Output ends with exactly one `\n`, is single-line, parses round-trip
   via `serde_json::from_str`.

### Integration

**Un-ignore `tools_list_before_initialize`** at
`crates/rimap-server/tests/mcp_wire_negative.rs:339-368`:

- Remove `#[ignore]`.
- Replace the accept-either-envelope-or-close branch with a strict
  envelope assertion (`error.code == -32002`, `id` matches the id the
  harness sent).
- Add a follow-up `response_or_close` call that asserts `CleanClose`
  (proves the server exited `0` after the envelope was written).
- Update the docstring to reference #275 as fixed.

**New wire tests in `mcp_wire_negative.rs`:**

- `pre_initialize_notification_silent_close`: first message is
  `notifications/cancelled`; assert `CleanClose` only (no envelope).
- `tools_list_before_initialize_str_id`: same as the un-ignored test
  but with a string id; pins id-type preservation at the wire layer.

### Audit log

One assertion in either the un-ignored test or a sibling test that
reads the audit log post-shutdown and verifies `process_end.reason
== Eof`. The pattern follows existing audit-tail tests under
`crates/rimap-server/tests/`.

### Out of scope

- `mcp_wire_proptest.rs` already runs `initialize` first; no proptest
  changes.
- No e2e (Dovecot) test changes — this is a wire-level behavior.

## Risks

1. **rmcp upstream variant rename.** `ServerInitializeError` is
   `#[non_exhaustive]`. If rmcp renames `ExpectedInitializeRequest`
   or splits Request / Notification cases, the explicit match arm
   becomes a compile error — the desired failure mode. The fallback
   `Err(other) =>` arm preserves today's behavior for every other
   initialization failure (transport errors, unsupported protocol
   version, etc.) so we do not silently swallow real bugs.
2. **stderr behavior.** The early-return path no longer emits
   `tracing::error!`. A single `tracing::info!` log entry is added
   at envelope-write time so audit operators can correlate the
   wire event — kept at `info` because this is a normal handled
   case, not a fault.
3. **stdout fd reuse.** Acquiring a fresh `tokio::io::stdout()` after
   rmcp drops its handle is safe because both wrap the same OS file
   descriptor. Anything rmcp wrote on this path (e.g. a ping response
   if the client sent `ping` before the offending request) is a
   well-formed JSON-RPC line; our envelope simply follows it on a new
   line. No partial writes or interleaving.

## What does not change

- Tool dispatch after `initialize` completes.
- Audit-envelope guarantees for in-flight tool calls.
- Other negative-path tests in `mcp_wire_negative.rs`.
- The `RimapError` / `ErrorCode` taxonomy in `crates/rimap-core`
  (the pre-init code lives only in the wire-level `McpCode` registry).

## Explicitly out of scope

- Issue #276 (protocol-version negotiation echoes unsupported versions).
- Reorganizing `main.rs::run` (currently ~119 lines, over the 100-line
  cap; flagged but addressed only if it becomes load-bearing).
- Adding a new `ErrorCode` variant to `rimap_core::ErrorCode`.

## Acceptance

Mirrors the issue:

- Pre-initialize Request results in a JSON-RPC error envelope with
  `code == -32002`; pre-initialize Notification / Response is dropped
  silently.
- `tools_list_before_initialize` and the two new wire tests pass with
  strict assertions on the chosen behavior.
- `rusty-imap-mcp` exits `0` (not `1`) on misbehaving-client input.
- `process_end` audit record reports `reason: Eof`.
