# Initialize Protocol-Version Negotiation (#276)

**Date:** 2026-05-14
**Issue:** [#276](https://github.com/randomparity/rusty-imap-mcp/issues/276)
**Discovered by:** Phase 4 negative-path testing (#266)
**Status:** Design approved; implementation pending
**Depends on:** [#275](https://github.com/randomparity/rusty-imap-mcp/issues/275) (pre-initialize handling)

## Problem

A client sending `initialize` with `protocolVersion: "1999-01-01"` (or any
unknown string) receives a success response with `protocolVersion: "1999-01-01"`
echoed back. The server silently advertises support for any version the
client names. Clients cannot detect version-negotiation failure, and a client
speaking an MCP version we cannot handle proceeds with mismatched semantics.

## Root cause

rmcp 1.5's `serve_server_with_ct_inner`
([`rmcp-1.5.0/src/service/server.rs:230-238`](https://docs.rs/rmcp/1.5.0/src/rmcp/service/server.rs.html))
computes the wire response's `protocol_version` as:

```rust
let protocol_version = match peer_protocol_version
    .partial_cmp(&init_response.protocol_version)
    .ok_or(ServerInitializeError::UnsupportedProtocolVersion(...))?
{
    std::cmp::Ordering::Less => peer_info.params.protocol_version.clone(),
    _ => init_response.protocol_version,
};
init_response.protocol_version = protocol_version;
```

`ProtocolVersion` (`rmcp/model.rs:140`) derives `PartialOrd` on a single
`Cow<'static, str>` field, so `partial_cmp` performs lexicographic string
comparison. For peer `"1999-01-01"` vs server `"2025-11-25"`,
`"1999-01-01".cmp("2025-11-25") == Less` → rmcp's downgrade branch picks
the peer's version and overwrites our response. `ProtocolVersion::KNOWN_VERSIONS`
exists in rmcp (`model.rs:162-167`) but the negotiation logic never
consults it.

Consequence: even if we override `ServerHandler::initialize` to set a
specific `protocol_version` on the response, rmcp's post-handler overwrite
still echoes any peer string that lex-sorts lower than `LATEST`.

The originating test —
`crates/rimap-server/tests/mcp_wire_negative.rs:612-668`
(`initialize_unsupported_protocol_version`) — is currently `#[ignore]`'d
pending this fix.

## Desired behavior

1. **Peer's `protocolVersion` is in `ProtocolVersion::KNOWN_VERSIONS`**
   (one of `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`):
   accept and complete the handshake normally. rmcp's downgrade logic
   produces a spec-compliant response (echo the peer's version when
   older, return our `LATEST` when newer).
2. **Peer's `protocolVersion` is anything else** (unknown string,
   empty string, garbage): reply with a JSON-RPC `-32602` error
   envelope that lists the supported versions, then close cleanly
   and exit `0`.
3. **Audit log:** `process_end.reason: Eof` on the rejection path
   (rmcp emitted the envelope; this is a clean handled rejection,
   not a server fault).

## Approach

Override `ServerHandler::initialize` on `ImapMcpServer`
(`crates/rimap-server/src/mcp/server.rs`):

```rust
async fn initialize(
    &self,
    request: InitializeRequestParams,
    context: RequestContext<RoleServer>,
) -> Result<InitializeResult, ErrorData> {
    if !ProtocolVersion::KNOWN_VERSIONS.contains(&request.protocol_version) {
        return Err(unsupported_protocol_version_error(&request.protocol_version));
    }
    if context.peer.peer_info().is_none() {
        context.peer.set_peer_info(request);
    }
    Ok(self.get_info())
}
```

The check uses `rmcp::model::ProtocolVersion::KNOWN_VERSIONS` directly —
single source of truth, automatically tracks rmcp version-list bumps.

A small private helper `unsupported_protocol_version_error` lives near
the bottom of `mcp/server.rs`:

```rust
fn unsupported_protocol_version_error(peer_version: &ProtocolVersion) -> ErrorData {
    let supported: Vec<&str> = ProtocolVersion::KNOWN_VERSIONS
        .iter()
        .map(ProtocolVersion::as_str)
        .collect();
    let message = format!(
        "Unsupported protocol version: '{}'. Server supports: {}.",
        peer_version.as_str(),
        supported.join(", "),
    );
    let data = serde_json::json!({ "supported_versions": supported });
    ErrorData::invalid_params(message, Some(data))
}
```

When the handler returns `Err`, rmcp at `service/server.rs:222` calls
`transport.send(ServerJsonRpcMessage::error(...))` to write the envelope,
then returns `Err(ServerInitializeError::InitializeFailed(error_data))`
from `serve_server`. Our `main.rs::run` adds a third match arm symmetric
to the #275 `ExpectedInitializeRequest` arm:

```rust
Err(ServerInitializeError::InitializeFailed(_)) => {
    // rmcp already sent the error envelope; this is a clean rejection
    // of an invalid initialize request (unsupported protocol version,
    // future bad-params cases), not a server fault.
    tracing::info!("rejected initialize request with error envelope");
    return Ok(());
}
```

Returning `Ok(())` causes `process_end` to record `reason: Eof` and the
process to exit `0` — the same audit semantics as #275's pre-init handled
path.

### Why counter-proposal isn't viable through rmcp

The MCP spec's preferred path is "respond with a version we support":

> "If the server supports the requested protocol version, it MUST respond
> with the same version. Otherwise, the server MUST respond with a version
> it does support."

Setting `init_response.protocol_version = ProtocolVersion::LATEST` in our
override does not work — rmcp's downgrade logic overwrites it with
`min(peer, server)` lexicographically. The only paths that produce a
spec-legal wire outcome without an upstream rmcp patch are:

1. Return `Err` from `initialize` → wire error envelope (this design).
2. Wrap rmcp's transport to intercept and rewrite the InitializeResult.

Option 2 costs significantly more code and is explicitly out of scope.
The spec's bug report accepts either "success result with a server-
supported version OR a JSON-RPC error"; option 1 satisfies the latter.

## Dependencies

This branch is stacked on
[`fix/issue-275-pre-initialize-handling`](https://github.com/randomparity/rusty-imap-mcp/pull/279).
#276's match-arm addition to `main.rs::run` sits right next to #275's
`ExpectedInitializeRequest` arm; the two changes touch adjacent lines.

Like #275, this is a merge blocker for PR #278 — the test
`initialize_unsupported_protocol_version` is `#[ignore]`'d on
`feature/issue-266-mcp-fuzzing` pending this fix.

**Branching strategy.** Fix PR targets either:

1. `fix/issue-275-pre-initialize-handling` directly while #279 is open;
   merging this PR rolls #275 + #276 into #275's branch. Practical
   choice while #279 is in review.
2. `feature/issue-266-mcp-fuzzing` once #279 merges; rebase
   `fix/issue-276-protocol-version-negotiation` onto the merged base
   and re-point the PR.

Either path lands the un-ignore commit alongside the production fix in
one diff, matching the #266 merge-blocker policy.

## Error envelope shape

```json
{
  "jsonrpc": "2.0",
  "id": <echoed verbatim>,
  "error": {
    "code": -32602,
    "message": "Unsupported protocol version: '<peer-version>'. Server supports: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25.",
    "data": {
      "supported_versions": ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
    }
  }
}
```

- **Code `-32602` (`INVALID_PARAMS`)**: the protocol version is structured
  data inside `params`. The standard JSON-RPC code for bad `params` is
  -32602. Reusing `ErrorData::invalid_params` keeps the envelope
  consistent with the rest of the dispatch path (`ErrorCode::InvalidInput`
  in `crates/rimap-server/src/mcp/error.rs:37` already maps here). Avoids
  burning a custom `-3200X` code for a single semantically-standard case.
- **Message text**: echoes the peer's bad version in single quotes for
  actionability. The peer-supplied protocol version is a client-asserted
  protocol string, not adversarial content like email body — reflection
  here doesn't carry the leakage risk #275 guards against. The supported
  list is built at compile time from `ProtocolVersion::KNOWN_VERSIONS`,
  so a future rmcp bump auto-updates the message without code changes.
- **`data` field**: machine-readable `{"supported_versions": [...]}` so
  a smart client can pick a version it speaks and retry. JSON-RPC §5.1
  allows the field; MCP doesn't require it but doesn't forbid it.

**No new `McpCode` constant.** `INVALID_PARAMS` is already in
`rmcp::model::ErrorCode`; the `NOT_INITIALIZED: McpCode(-32002)` added
in #275 stays.

## Test plan

### Integration

**Un-ignore `initialize_unsupported_protocol_version`** at
`crates/rimap-server/tests/mcp_wire_negative.rs:612-668`:

- Remove `#[ignore]`.
- Replace the accept-either-branch with strict assertions on the error
  envelope path:
  - `envelope["error"]["code"] == -32602`
  - `envelope["error"]["data"]["supported_versions"]` is a JSON array
    containing `"2025-11-25"` and non-empty
  - `envelope["error"]["message"]` contains `"1999-01-01"` (the
    peer's version, echoed back per the message-text rule above)
- Add a follow-up `response_or_close` call asserting `CleanClose`
  (proves the server exited `0` after rmcp sent the envelope).
- Add an audit-log assertion: `read_process_end_reason(...) == Eof`.
- Update the docstring to reference #276 as fixed.

**New wire test — `initialize_with_known_older_version_succeeds`**:

- Send `initialize` with `protocolVersion: "2024-11-05"`.
- Assert success envelope (no `error` field).
- Assert `envelope["result"]["protocolVersion"]` is a string in
  `KNOWN_VERSIONS` (rmcp's downgrade will produce `"2024-11-05"`,
  which is spec-legal — peer asked for an older version we accept).
- Pins the permissive-posture decision: older known versions are
  NOT rejected.

**New wire test — `initialize_with_empty_string_protocol_version`**:

- Send `protocolVersion: ""` — edge case where the client sends valid
  JSON but a degenerate version string.
- Assert error envelope with `code == -32602` (`""` is not in
  `KNOWN_VERSIONS`).
- Pins the boundary so future code that special-cases empty strings
  is caught.

### Unit

**`mcp/server.rs::tests` — `unsupported_protocol_version_error_shape`**:

- Construct a `ProtocolVersion` from `"1999-01-01"` (the rmcp
  deserializer's fallback path produces an arbitrary string).
- Call `unsupported_protocol_version_error(&version)`.
- Assert: returned `ErrorData.code == INVALID_PARAMS`,
  message contains `"1999-01-01"`, `data["supported_versions"]` is
  a JSON array equal to the stringified `KNOWN_VERSIONS`.
- Lives at the bottom of `mcp/server.rs` next to the helper. No I/O,
  fast.

**Optional: `unsupported_protocol_version_error_lists_all_known_versions`**:

- Same helper, any peer version.
- Assert `data["supported_versions"].len() == KNOWN_VERSIONS.len()`
  and each value matches an entry in `KNOWN_VERSIONS`.
- Pins the contract that the list is constructed from `KNOWN_VERSIONS`
  (not hard-coded). Catches future drift if someone hand-edits the
  list.

### Out of scope

- `mcp_wire_proptest.rs` — proptest harness uses
  `PINNED_PROTOCOL_VERSION` so this code path is never hit fuzzily.
  No proptest changes.
- No e2e (Dovecot) test changes — this is a wire-level concern.

## Risks

1. **`KNOWN_VERSIONS` is rmcp-1.5-specific.** If we bump rmcp later, the
   list may change shape. Mitigation: we reference
   `ProtocolVersion::KNOWN_VERSIONS` live — bumping rmcp adjusts the
   acceptance set automatically. The unit test that asserts the
   stringified format flags the change visibly.

2. **Permissive posture overstates compatibility.** Accepting
   `"2024-11-05"` through `"2025-11-25"` is a claim that we speak all
   four. Our schema fixtures and validation pin `"2025-11-25"`. A
   client speaking an older version completes `initialize` but may
   hit wire-shape mismatches in subsequent tool calls. Mitigation:
   rmcp's downgrade logic claims to handle the wire differences.
   Acknowledged limitation; explicitly accepted by the user during
   design; out of scope for #276 to verify cross-version compat.

3. **`InitializeFailed` arm catches all initialize-handler failures,
   not just version mismatches.** If a future change adds new
   `initialize` validation (e.g., `capabilities` field constraints),
   it also gets classified as clean exit. That's the correct
   behavior — rmcp will have sent the wire envelope, so exit 0 with
   audit Eof is the right semantics for any handled rejection at the
   initialize layer. No change needed.

4. **rmcp upstream lex-comparison fix.** If rmcp ever fixes the
   downgrade logic to consult `KNOWN_VERSIONS` directly, our override
   becomes a no-op (the peer's bad version would already be rejected
   upstream). That's fine — the override is defensive, costs nothing
   when redundant.

## What does not change

- `synthesize_pre_init_error_envelope` and #275's pre-initialize
  handling.
- `get_info()` continues to advertise `ProtocolVersion::LATEST` as
  the server's preferred version.
- Tool dispatch, audit envelopes, other negative-path tests.
- The `RimapError` / `ErrorCode` taxonomy in `crates/rimap-core`.

## Explicitly out of scope

- Counter-proposal via transport wrapper (requires significantly more
  code; rmcp's lex-min logic blocks the direct path).
- Cross-version wire compatibility (we accept older known versions
  but don't actively translate wire shapes).
- Patching rmcp upstream to use `KNOWN_VERSIONS` instead of lex
  comparison (worth filing but separate from #276).
- #277 (hung-on-unknown-method) — separate bug, separate plan.

## Acceptance

Mirrors the issue:

- `initialize` with an unknown version returns a JSON-RPC `-32602`
  error envelope listing the supported versions; the server exits
  `0` and the audit log records `process_end.reason: Eof`.
- `initialize` with a known older version (e.g., `"2024-11-05"`)
  succeeds; the response's `protocolVersion` is the peer's version
  (per rmcp's downgrade logic).
- `initialize_unsupported_protocol_version` and the new wire tests
  pass with strict assertions on the chosen behavior.
- No crash, no `Crashed(...)` outcome from the harness on
  unsupported-version input.
