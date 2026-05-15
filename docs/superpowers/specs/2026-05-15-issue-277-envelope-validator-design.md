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

Pre-initialize handling is otherwise unchanged — `preinit` still owns
`ServerInitializeError::ExpectedInitializeRequest` (a
semantically-wrong-but-syntactically-valid first message), and the
validator catches everything that rmcp's codec would otherwise silently
drop, both pre- and post-initialize. **One mechanical change is
required**: `emit_pre_init_error_envelope` in `main.rs` writes to real
stdout and so must lock the validator's shared mutex — see "Pre-init
shares the validator stdout" below.

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
                       ┌──── Arc<Mutex<Stdout>> ─ shared writer ────┐
                       ↑ rejections     ↑ rmcp frames     ↑ pre-init envelope
                       │                │                 │
real stdin → [validator] ──valid line→ duplex_in.our_end  │     main.rs::run
                                       duplex_in.rmcp_end →─→ rmcp transport
                       [passthrough] ← duplex_out.our_end ←─ duplex_out.rmcp_end
                                          │
                                          └──── locks shared writer ──→ real stdout

   supervisor.join() races service.waiting() in main.rs:
     - validator/passthrough JoinHandle errors → mcp_outcome: Err → process_end.reason: Error
     - clean EOF on both directions               → mcp_outcome: Ok  → process_end.reason: Eof
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
write; the affected bridge task returns that error from its
`JoinHandle` and the supervisor surfaces it to `main.rs::run` so
`process_end.reason: Error` is recorded (see "Bridge-task supervisor"
below).

rmcp's `IntoTransport` impl
(`rmcp/transport/async_rw.rs:22-31`) accepts any
`(R: AsyncRead, W: AsyncWrite)` pair. Our pair is two
`tokio::io::DuplexStream` ends — substitution requires zero changes to
rmcp.

### Validator entry point

The validator returns a struct rather than a bare tuple so the bridge
tasks' lifecycle, the shared stdout writer, and the rmcp-facing
transport are owned together. The shared stdout is exposed so all
synchronized stdout writers in the process (validator rejections,
passthrough frames, **and** the pre-init error envelope emitted from
`main.rs`) lock the same mutex — see "Pre-init shares the validator
stdout" below.

```rust
// crates/rimap-server/src/mcp/wire_validator.rs

pub struct ValidatedStdio {
    /// Hand to rmcp via `rmcp::serve_server(server, validated.transport)`.
    pub transport: (DuplexStream, DuplexStream),
    /// Shared writer for synchronized stdout output. `main.rs`'s
    /// pre-init error path locks this same mutex; the bridge tasks
    /// hold `Arc::clone`s.
    pub stdout: Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
    /// Bridge-task supervisor; must be polled alongside
    /// `service.waiting()` so write errors propagate.
    pub supervisor: ValidatorSupervisor,
}

pub struct ValidatorSupervisor {
    inbound: JoinHandle<io::Result<()>>,
    outbound: JoinHandle<io::Result<()>>,
}

impl ValidatorSupervisor {
    /// Resolves with the first bridge-task error encountered, or
    /// `Ok(())` once both tasks exit cleanly (the normal EOF path).
    ///
    /// On error from either task, the other is aborted; both
    /// duplex ends are dropped, which surfaces to rmcp as a
    /// transport error on its next read/write.
    pub async fn join(mut self) -> io::Result<()> { ... }
}

/// Build the validated stdio transport. The two bridge tasks are
/// spawned immediately; their lifecycle is exposed via `supervisor`.
pub fn stdio_with_validation() -> ValidatedStdio {
    let (inbound_our_end, inbound_rmcp_end) = tokio::io::duplex(BUF_SIZE);
    let (outbound_rmcp_end, outbound_our_end) = tokio::io::duplex(BUF_SIZE);

    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

    let inbound = tokio::spawn(validate_inbound(
        tokio::io::stdin(),
        inbound_our_end,
        Arc::clone(&stdout),
    ));
    let outbound = tokio::spawn(passthrough_outbound(
        outbound_our_end,
        Arc::clone(&stdout),
    ));

    ValidatedStdio {
        transport: (inbound_rmcp_end, outbound_rmcp_end),
        stdout,
        supervisor: ValidatorSupervisor { inbound, outbound },
    }
}
```

`BUF_SIZE = 64 * 1024`. Generous enough that one well-formed envelope
fits in a single write; both directions are independent tasks so
inbound stalls cannot cause outbound deadlock.

### Bridge-task supervisor

The supervisor has two methods so the shutdown logic can both
**fail-fast** during service runtime and **drain** after service
completion — `service.waiting()` resolving `Ok(())` only proves
rmcp finished writing to the duplex, not that the passthrough
flushed those bytes to real stdout. Without the drain phase, a
`BrokenPipe` on the final response would be silently lost.

```rust
impl ValidatorSupervisor {
    /// Non-consuming. Resolves when either bridge task returns
    /// `Err`, OR when both bridges exit `Ok` cleanly (an exotic
    /// mid-service condition — usually one side stays alive
    /// until the service ends and drains it). Used for fail-fast
    /// during the `service.waiting()` race.
    pub async fn watch_for_error(&mut self) -> io::Result<()>;

    /// Consuming. Awaits both bridge tasks to completion;
    /// returns the first error encountered. Used after
    /// `service.waiting()` resolves so final-write failures
    /// surface.
    pub async fn drain(self) -> io::Result<()>;
}
```

`main.rs::run` runs two phases — race, then drain:

```rust
let validated = wire_validator::stdio_with_validation();
let stdout_for_preinit = Arc::clone(&validated.stdout);

let service = match Box::pin(rmcp::serve_server(mcp_server, validated.transport)).await {
    Ok(svc) => svc,
    Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
        emit_pre_init_error_envelope(&msg, &stdout_for_preinit).await?;
        // Drop the supervisor (drain on the way out so any pre-init
        // queued frames flush; failures surface as Err).
        return match validated.supervisor.drain().await {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow!("validator bridge drain after pre-init: {e}")),
        };
    }
    Err(ServerInitializeError::InitializeFailed(error_data)) => {
        return handle_initialize_failed(&error_data);
    }
    Err(other) => return Err(anyhow!("MCP server init: {other}")),
};

let mut supervisor = validated.supervisor;
let mut service_fut = Box::pin(service.waiting());

// Phase 1: race service against bridge errors.
let service_outcome: anyhow::Result<()> = tokio::select! {
    biased;
    bridge = supervisor.watch_for_error() => {
        match bridge {
            Err(e) => Err(anyhow!("validator bridge: {e}")),
            Ok(()) => {
                // Both bridges exited cleanly while service still
                // running (exotic). Treat as a transport teardown
                // and let service finish — it will see EOF.
                (&mut service_fut).await.map_err(|e| anyhow!("rmcp: {e}"))
            }
        }
    }
    result = &mut service_fut => result.map_err(|e| anyhow!("rmcp: {e}")),
};

// Phase 2: drop service to release rmcp's transport ends, then drain.
drop(service_fut);
let drain_outcome = supervisor
    .drain()
    .await
    .map_err(|e| anyhow!("validator bridge drain: {e}"));

let mcp_outcome = match (service_outcome, drain_outcome) {
    (Err(e), _) => Err(e),         // race-phase failure dominates
    (Ok(()), Err(e)) => Err(e),    // drain-phase failure surfaces
    (Ok(()), Ok(())) => Ok(()),
};
```

The `biased` discriminator gives the supervisor arm priority on
race-phase ties; the drain phase is unconditional after the race
resolves so a final-write `BrokenPipe` always lands in
`mcp_outcome: Err` → `process_end.reason: Error`. Any audit work
still flushes via the existing `drainer_handle.await` further down
in `main.rs::run`.

### Pre-init shares the validator stdout

`main.rs`'s `emit_pre_init_error_envelope` currently writes directly to
`tokio::io::stdout()` (`main.rs:199-211`). After the transport swap,
the bridge tasks hold the synchronized stdout writer; a direct
`tokio::io::stdout()` write from `emit_pre_init_error_envelope` races
the passthrough task and can corrupt line-delimited output (e.g. a
pre-init `ping` request arrives, rmcp emits a response via passthrough,
and the next line is a `tools/list` rejection envelope — interleaved
mid-line).

Mechanical change to `main.rs`:

```rust
async fn emit_pre_init_error_envelope(
    msg: &rmcp::model::ClientJsonRpcMessage,
    stdout: &Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
) -> anyhow::Result<()> {
    let Some(line) = rimap_server::mcp::preinit::synthesize_pre_init_error_envelope(msg) else {
        return Ok(());
    };
    let mut out = stdout.lock().await;
    out.write_all(line.as_bytes())
        .await
        .context("writing pre-init error envelope to stdout")?;
    out.flush()
        .await
        .context("flushing pre-init error envelope")?;
    Ok(())
}
```

`preinit::synthesize_pre_init_error_envelope` itself is unchanged — it
remains a pure formatter. Only the caller in `main.rs` and the
function's signature change.

The new pre-init wire test
`preinit_envelope_does_not_interleave_with_rmcp_frame` (see "Testing")
exercises the formerly racy ordering and asserts both stdout lines
parse cleanly.

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
  - `pub struct ValidatedStdio { transport, stdout, supervisor }` and
    `pub fn stdio_with_validation() -> ValidatedStdio` — entry point
    used by `main.rs`.
  - `pub struct ValidatorSupervisor` with `pub async fn join(self) -> io::Result<()>`.
  - `fn validate(line: &str) -> ValidationOutcome` — pure
    function, no I/O. Unit-testable in isolation.
  - `enum ValidationOutcome { Forward, Skip, Reject(ErrorEnvelope) }`
  - `fn synthesize_error_envelope(code: i32, message: &str, id: Option<Value>) -> String`
  - `async fn validate_inbound(...)` and `async fn passthrough_outbound(...)` —
    the two bridge tasks, each returning `io::Result<()>` so write
    failures surface via the supervisor's `JoinHandle`s.
- **Modified:** `crates/rimap-server/src/main.rs` —
  - swap the transport constructor (`stdio_with_validation()`),
  - thread `Arc<Mutex<Stdout>>` into `emit_pre_init_error_envelope` so
    pre-init rejections share the validator's stdout writer,
  - two-phase shutdown: race `service.waiting()` against
    `supervisor.watch_for_error()` via `tokio::select! { biased; ... }`,
    then unconditionally `supervisor.drain().await` before classifying
    `mcp_outcome`.
- **Modified:** `crates/rimap-server/src/mcp/mod.rs` — `pub mod wire_validator;`
- **Modified:** `crates/rimap-server/tests/support/wire/harness.rs` —
  - `pub enum NotificationOutcome { SilentThenAlive, UnexpectedResponse(String), FailedLiveness(CloseOrResponse) }`
  - `pub async fn assert_notification_then_alive(&mut self, line, silence_dur, liveness_dur) -> NotificationOutcome`
    that does not poison the harness on `SilentThenAlive`.
  - `pub const SILENCE_TIMEOUT: Duration = Duration::from_millis(250);`
  - `pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(1);`
  - `pub async fn request_with_timeout(&mut self, method, params, dur) -> CloseOrResponse`
    (small extension; reuses the existing send + `response_or_close` core
    with a parameterized timeout).
- **Modified:** `crates/rimap-server/tests/mcp_wire_proptest.rs:310` —
  remove the `#[ignore]` from `prop_envelope_never_panics`, and amend
  the property body to dispatch spec-legal notifications through
  `assert_notification_then_alive` (see "Property body adjustment").
- **Modified:** `crates/rimap-server/tests/mcp_wire_negative.rs` — new
  pinned tests (see "Testing" below).
- **No changes to** `crates/rimap-server/src/mcp/preinit.rs` itself —
  its `synthesize_pre_init_error_envelope` remains a pure formatter;
  the I/O caller in `main.rs` is what changes.

## Property body adjustment (case 2)

`prop_envelope_never_panics` currently treats `CloseOrResponse::Hung`
as a `panic!`. After the validator lands, the only remaining `Hung`
source is the spec-compliant silent-ignore path: valid JSON-RPC 2.0
notifications (`jsonrpc:"2.0"`, no `id`, non-standard `method`). The
property body must distinguish that case from a real hang — AND not
poison the harness, since `Harness::response_or_close` poisons on
every `Hung` outcome (`harness.rs:514-516`). Poisoning means
`with_live_harness` respawns the harness for the next case,
defeating the throughput rationale for accepting notifications at
all.

### Non-poisoning probe on the harness

Add a method to `Harness` (in `tests/support/wire/harness.rs`) that
handles the entire send → expected-silence → liveness-ping pattern
atomically without poisoning on the spec-legal silent timeout:

```rust
pub enum NotificationOutcome {
    /// Expected: notification produced no response, ping confirmed
    /// the server is still responsive.
    SilentThenAlive,
    /// Spec violation: notification produced a response.
    UnexpectedResponse(String),
    /// Liveness ping failed (hung, crashed, or closed unexpectedly).
    /// Harness IS poisoned in this case.
    FailedLiveness(CloseOrResponse),
}

/// Send `line` as a notification (no response expected), wait
/// `silence_dur` to confirm no response arrives, then send a `ping`
/// request and require a well-formed response within `liveness_dur`.
///
/// `self.poisoned` is set to `true` ONLY for `UnexpectedResponse`
/// and `FailedLiveness` outcomes — the `SilentThenAlive` path
/// leaves the harness usable so subsequent proptest cases can reuse it.
pub async fn assert_notification_then_alive(
    &mut self,
    line: &str,
    silence_dur: Duration,
    liveness_dur: Duration,
) -> NotificationOutcome;
```

Behavior detail:
- Send `line` via `send_line`.
- Read with timeout `silence_dur`. If a line arrives:
  → `UnexpectedResponse(line)`, set `poisoned = true`.
- If `silence_dur` elapses with no read: **do not poison** (this is
  the spec-legal outcome). Continue to liveness probe.
- Send a `ping` request via `request_with_timeout("ping", json!({}), liveness_dur)`.
- If `CloseOrResponse::Response` with a well-formed result envelope:
  → `SilentThenAlive`, harness stays usable.
- Otherwise (Hung, CleanClose, Crashed): → `FailedLiveness(outcome)`,
  `poisoned = true`.

### Property body using the probe

```rust
let is_spec_legal_notification = envelope
    .get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
    && envelope.get("id").is_none()
    && envelope.get("method").and_then(|v| v.as_str()).is_some();

if is_spec_legal_notification {
    match h
        .assert_notification_then_alive(
            &envelope.to_string(),
            SILENCE_TIMEOUT,
            LIVENESS_TIMEOUT,
        )
        .await
    {
        NotificationOutcome::SilentThenAlive => {} // pass; harness stays usable
        NotificationOutcome::UnexpectedResponse(line) => panic!(
            "notification {envelope} produced a response: {line}",
        ),
        NotificationOutcome::FailedLiveness(o) => panic!(
            "ping after notification {envelope} failed liveness: {o:?}",
        ),
    }
    return h;
}

// Non-notification path: the existing flow.
h.send_line(&envelope.to_string()).await;
let outcome = h.response_or_close(REQUEST_TIMEOUT).await;
match outcome {
    CloseOrResponse::Response(line) => {
        let env: Value = serde_json::from_str(line.trim_end())
            .expect("server response must be valid JSON");
        assert_envelope_valid(&env);
    }
    CloseOrResponse::CleanClose => {} // harness already poisoned by harness.rs
    CloseOrResponse::Crashed(d) => panic!("crashed on {envelope}: {d}"),
    CloseOrResponse::Hung => panic!("hung on {envelope} (post-validator)"),
}
```

The `is_spec_legal_notification` check is in the test body, not the
strategy, so the missing-`jsonrpc` cases that originally triggered
#277 stay in coverage and exercise the validator's reject path. The
strategy is unchanged.

**New constants** in `harness.rs`:
- `SILENCE_TIMEOUT: Duration = Duration::from_millis(250)` — long
  enough that a spec-legal notification doesn't false-positive as
  `UnexpectedResponse`, short enough that 1000 cases × 25% × 250ms
  ≈ 62.5s isn't unbearable. Tunable.
- `LIVENESS_TIMEOUT: Duration = Duration::from_secs(1)` — same order
  as the existing `REQUEST_TIMEOUT`.

**Liveness rationale.** `Hung` is just "no bytes within timeout" — it
does not prove the child process is responsive. Without the ping, a
panic-on-notification or a deadlock-on-notification would be silently
classified as spec-legal silence, defeating the `never_panics`
guarantee for this input class. The probe forces the server to
*demonstrate* it is still processing requests before the case passes.

**Overhead under 1000-case runs.** Roughly 25% of envelopes are
notification-shaped → ~250 cases each pay `SILENCE_TIMEOUT` +
`LIVENESS_TIMEOUT` round-trip (`~250ms + ~5ms ≈ 255ms`). Total
overhead: ~64s. Significantly larger than the prior estimate
(~2.5s); the SILENCE_TIMEOUT dominates. Trade-off note:
shortening `SILENCE_TIMEOUT` to e.g. 50ms cuts overhead 5× at the
cost of false-positive risk on slow systems. The 250ms default
matches the rmcp `FramedRead` poll cadence and gives generous
margin; nightly runs can override via env var if needed.

Critically, this is the cost of the **probe**, NOT the cost of
respawning the harness — which under the original (poisoning) design
would have been ~1.5s × 250 cases ≈ 6 minutes. The non-poisoning
probe is what keeps the property practical.

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
11. `preinit_envelope_does_not_interleave_with_rmcp_frame` — pre-init
    `ping` (which rmcp answers via the passthrough) immediately
    followed by a pre-init `tools/list` (which `emit_pre_init_error_envelope`
    rejects with `-32002`) → both stdout lines parse as well-formed,
    distinct JSON-RPC envelopes with the expected `id` mapping. Pins
    the new shared-stdout invariant.
12. `process_end_on_validator_rejection_write_failure` — closed-stdout
    harness variant: client sends an invalid envelope, validator's
    `-32600` write fails with `BrokenPipe`, supervisor surfaces the
    error to `mcp_outcome`, audit records `process_end.reason: Error`,
    exit is non-zero. Mirrors #275's `process_end_on_pre_init_write_failure`.
13. `process_end_on_rmcp_response_write_failure` — closed-stdout
    harness variant during race phase: client sends a valid
    `tools/list`, rmcp's response write into the passthrough fails
    while `service.waiting()` is still running, `watch_for_error`
    catches it, audit records `process_end.reason: Error`, exit
    non-zero. Companion to test 12 for the outbound bridge.
14. `process_end_on_drain_phase_write_failure` — closed-stdout
    harness variant during drain phase: client sends valid
    `initialize` + `tools/list`, then closes stdin so `service.waiting()`
    resolves `Ok(())`. rmcp's `tools/list` response is queued in the
    outbound duplex but the passthrough's write to (closed) stdout
    fails. `supervisor.drain()` surfaces the error, audit records
    `process_end.reason: Error`, exit non-zero. Pins the race-vs-drain
    distinction.
15. `harness_notification_probe_does_not_poison` — unit test on the
    harness alone (no proptest involvement): construct a harness,
    complete the initialize handshake, call
    `assert_notification_then_alive("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":0}}", SILENCE_TIMEOUT, LIVENESS_TIMEOUT)`,
    assert the outcome is `SilentThenAlive`, then assert
    `harness.is_usable() == true`. Pins the non-poisoning contract
    so a regression in the harness method gets caught before the
    proptest runs it 250 times per session.

All tests run against the production binary via the existing
`Harness`. Tests 12, 13, and 14 use the closed-stdout harness variant
added in `tests/support/wire/harness.rs` for #275. Test 15 exercises
the new `assert_notification_then_alive` method in isolation.

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
  are spawned with `tokio::spawn`; the supervisor owns their
  `JoinHandle`s. On `service.waiting()` resolution the supervisor's
  `join()` is dropped, which aborts the tasks; the tasks own their
  I/O handles and drop them on exit, surfacing EOF/write-error to
  rmcp. Same shutdown shape as today's direct stdio transport, with
  the added guarantee that a write error from either task is
  captured by `tokio::select!` before the supervisor is dropped.
- **Backpressure under sustained malformed input.** Each rejection
  writes to real stdout from the validator task. A slow consumer
  could stall the validator; that's identical to today's stall
  behavior on rmcp's outbound write under a slow consumer, and is
  out of scope.
- **Audit-record masking by silent task failures.** Without the
  supervisor (the original spec draft), a bridge task could die
  with `BrokenPipe` and `service.waiting()` could resolve `Ok(())`
  on its own EOF path, recording `process_end.reason: Eof` even
  though no response ever reached the client. Mitigation: the
  supervisor uses two-phase shutdown — `watch_for_error()` for
  race-phase fail-fast plus an unconditional `drain()` after
  service completion. Tests 12, 13, and 14 pin the audit
  semantics on both bridges across both shutdown phases.
- **Drain-phase write failure invisibility.** If we only raced
  `service.waiting()` against the supervisor and short-circuited
  on whichever resolved first, `service.waiting() → Ok(())` could
  fire while a final passthrough frame is still queued in the
  duplex; a subsequent `BrokenPipe` on that write would be lost.
  Mitigation: drain is unconditional after the race; test 14
  exercises exactly this ordering.
- **Notification liveness blind spot.** The property's amended
  arm for spec-legal notifications must prove the server is still
  responsive, not merely silent. Mitigation: each notification-
  shaped envelope dispatches through `assert_notification_then_alive`
  which sends a `ping` after the silence wait — a hung or crashed
  server fails the case instead of being respawned as "spec-legal
  silence."
- **Harness poisoning kills proptest throughput.** The existing
  `Harness::response_or_close` poisons on every `Hung`, so a naïve
  liveness-ping after `Hung` would still leave the harness flagged
  for respawn. Mitigation: `assert_notification_then_alive` owns
  the entire send → silence → ping cycle and only poisons on
  actual liveness failure. Test 15 pins the non-poisoning contract.

## Dependencies and merge plan

This fix is the final merge blocker for PR #278 (the #266 fuzzing
umbrella). The implementation lands on
`feature/issue-266-mcp-fuzzing` directly, in one diff that includes:

1. `wire_validator.rs` with `ValidatedStdio` / `ValidatorSupervisor`
   (`watch_for_error` + `drain`), the `validate()` pure function,
   and the two bridge tasks.
2. `main.rs` updates: transport swap, `emit_pre_init_error_envelope`
   signature thread-through, two-phase shutdown
   (race `watch_for_error` against `service.waiting()` then
   unconditional `drain`).
3. Harness extensions in `tests/support/wire/harness.rs`:
   `NotificationOutcome`, `assert_notification_then_alive`,
   `request_with_timeout`, `SILENCE_TIMEOUT`, `LIVENESS_TIMEOUT`.
4. Property body amendment dispatching spec-legal notifications
   through `assert_notification_then_alive`.
5. Un-ignore `prop_envelope_never_panics`.
6. 15 new wire-pinned tests across `mcp_wire_negative.rs` and the
   harness suite (10 for validation rules, 1 for pre-init ordering,
   3 for closed-stdout audit semantics on both shutdown phases,
   1 for the non-poisoning harness contract).
7. Mirror docs (this spec, committed before implementation starts).

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
