# MCP Protocol Fuzzing & Negative-Path Coverage — Design

**Status:** Draft 2026-05-13
**Issue:** #266 (Phase 4 of 4)
**Depends on:** #263 (Phase 1 wire harness, closed), #265 (Phase 3 Dovecot fixture, closed)
**Scope:** Property-based and targeted negative-path tests for the MCP
JSON-RPC wire: malformed envelopes, protocol-state errors, oversized
payloads, concurrent requests, cancellation mid-call, audit fail-closed
boundary. Builds on the wire-driving `Harness` shipped in Phase 1.

## 1. Motivation

Phases 1–3 cover happy-path conformance against three different
validators (vendored MCP spec schema in #263, official Node SDK in
#264, Dovecot behavioral conformance in #265). They do not cover what
happens when a misbehaving or malicious client sends garbage. The
server must respond with well-formed JSON-RPC error envelopes (per
spec) — or cleanly close the connection — rather than crash, hang, or
leak partial state. The most security-relevant tests live here, and
this phase locks in the negative-path contract before any new tool or
config surface is added.

## 2. Goals & Non-Goals

### Goals

- Cover the negative-path categories the issue enumerates: malformed
  input, method-level errors, protocol-state errors, concurrency,
  cancellation, property-based envelope fuzzing, audit fail-closed.
- Every test asserts a concrete contract — no test that only checks
  "didn't crash."
- Deterministic concurrency (no clock-based races); deterministic
  proptest reproducibility (`proptest-regressions/` committed).
- ≥1000 cases per property in CI; overnight runs scale via
  `PROPTEST_CASES`.
- Zero new production crate dependencies. Reuse the Phase 1 harness
  and the existing workspace `proptest`.

### Non-Goals

- IMAP-server-side fuzzing — covered by `rimap-content` ammonia
  property tests and the mail-parser adversarial corpus.
- Coverage-guided fuzzing infrastructure — `.clusterfuzzlite/`
  already exists.
- Tool-output schema fuzzing — Phase 4 targets the wire/envelope
  layer; output schemas are validated in Phase 1 and Phase 3.
- New tools, new config surface, new production code paths. Phase 4
  is testing only, except for the small `test-support` knob noted in
  §6.4 if `chmod`-based audit failure injection turns out to be
  unreliable in CI.

## 3. Architecture

Four new test binaries, all reusing the existing `support/wire/`
module from Phase 1. The harness is extended in place — no new
struct, no forked spawn path.

| File | Purpose | Spawn config |
| --- | --- | --- |
| `crates/rimap-server/tests/mcp_wire_negative.rs` | Malformed JSON, protocol-state errors, version negotiation failures, concurrent in-flight requests. | Zero-account (`Harness::spawn`). |
| `crates/rimap-server/tests/mcp_wire_proptest.rs` | `proptest`-driven envelope and `tools/call` argument fuzzing. ≥1000 cases per property by default. | Zero-account, harness reused across cases per property block. |
| `crates/rimap-server/tests/mcp_audit_failure.rs` | Audit fail-closed boundary tests. | Zero-account, audit path on a write-failing target. |
| `crates/rimap-server/tests/e2e_wire_cancellation.rs` | `notifications/cancelled` mid-`tools/call`, assert `tool_end { status: cancelled }` audit record. | Phase 3 Dovecot fixture (`support/dovecot/harness.rs`). |

### 3.1 Harness extensions

`crates/rimap-server/tests/support/wire/harness.rs` gains these methods.
The existing `request` / `notify` / `shutdown_and_wait` surface is
unchanged so Phases 1 and 3 continue to validate envelopes by default.

```rust
async fn send_raw(&mut self, bytes: &[u8]);
async fn send_line(&mut self, line: &str);                     // appends \n
async fn recv_line_within(&mut self, dur: Duration) -> Option<String>;
async fn send_request_no_wait(&mut self, method: &str, params: Value) -> u64;
async fn recv_until_id(&mut self, id: u64) -> Value;
async fn assert_clean_shutdown_or_response(&mut self, request_dur: Duration);
```

The notification-skip loop currently inlined in `request` is refactored
into a private `read_one_envelope` helper so `request` and
`recv_until_id` share parsing and the stderr-on-failure diagnostics.
`recv_until_id` buffers out-of-order responses in a small `VecDeque`
keyed by id — when a later call asks for a buffered id, it is returned
without touching stdout.

### 3.2 Determinism primitives

- **Concurrency** — `send_request_no_wait` + `recv_until_id` is a
  single-task design; no `tokio::spawn`, no shared `Mutex` over
  stdout. The harness drains stdout linearly; out-of-order responses
  are buffered. Deterministic under nextest load.
- **Cancellation timing** — the Dovecot-backed test polls the audit
  log for `tool_start` (100 ms cap, 10 ms granularity) before issuing
  `notifications/cancelled`. No `sleep()`-and-hope ordering.
- **Proptest seeds** — `proptest-regressions/` is committed (same
  pattern `rimap-content` already uses). Each shrink reproduces from
  the committed seed.

## 4. Test inventory & contracts

Every test asserts a concrete contract. Probe-based contracts ("either
envelope-X or clean close") record the probed behavior inline so
future readers can tell why the assertion is shaped that way.

### 4.1 `mcp_wire_negative.rs` (≈8–10 tests, zero-account)

| Test | Input | Contract |
| --- | --- | --- |
| `unparsable_json_errors_or_closes` | `not json\n` | Envelope `code: -32700` OR child exits 0 within `SHUTDOWN_TIMEOUT`. |
| `valid_json_invalid_envelope_returns_minus_32600` | `{"foo":"bar"}` | `-32600` invalid request, `jsonrpc == "2.0"`. |
| `missing_method_field` | envelope without `method` | `-32600`. |
| `wrong_type_method_field` | `"method": 42` | `-32600`. |
| `oversized_params_payload` | `params.note` = 1 MiB string | Valid envelope (success or error) or clean close; never hang past `REQUEST_TIMEOUT`. |
| `initialize_after_already_initialized` | Two `initialize` calls | Second returns an error envelope; exact code recorded inline. |
| `tools_list_before_initialize` | `tools/list` without prior `initialize` | Error envelope; code recorded. |
| `initialize_unsupported_protocol_version` | `protocolVersion: "1999-01-01"` | Echo of supported version OR error envelope (spec allows either). |
| `concurrent_tools_list_two_inflight` | Two `tools/list` via `send_request_no_wait`, both awaited via `recv_until_id` | Both responses received within `REQUEST_TIMEOUT`, ids match, no corruption. |
| `bidi_override_in_tool_argument` | `tools/call use_account` with bidi-override in `account_id` | Accepted or rejected with valid error envelope; no panic in audit writer. |

### 4.2 `mcp_wire_proptest.rs` (3 properties, zero-account)

```rust
#![proptest_config(ProptestConfig::with_cases(1000))]
```

`PROPTEST_CASES` overrides the case count. Overnight runs use 100 000.
Each property block spawns one `Harness` and replays N envelopes
through it — re-spawning per case would push the suite past minutes
without adding coverage.

1. **`prop_envelope_never_panics`** — strategy generates arbitrary
   JSON values with optional `jsonrpc`, `id`, `method`, `params`
   fields of randomized types. Assert: every input either produces a
   well-formed JSON-RPC envelope validating against
   `JSONRPCResponse`/`JSONRPCError`, or the server cleanly closes the
   connection. No panic, no hang past `REQUEST_TIMEOUT`, no
   malformed line.
2. **`prop_tools_call_unknown_tool`** — arbitrary string tool names
   plus arbitrary JSON `arguments`. Assert: every response validates
   as `JSONRPCErrorResponse`; `code` is one of a documented small
   set.
3. **`prop_tools_call_use_account_argument_shape`** — `use_account`
   called with arbitrary argument shapes. Assert: server returns a
   valid error envelope (no account configured ⇒ rejection); never
   a result envelope. (`list_accounts` is also advertised in the
   zero-account config but takes no arguments, so it is not a
   useful fuzz target for argument-shape properties; envelope-level
   coverage for it lives in property 1.)

### 4.3 `mcp_audit_failure.rs` (2–3 tests, zero-account)

| Test | Setup | Contract |
| --- | --- | --- |
| `audit_write_failure_fails_closed_for_tools_call` | Audit path on a read-only directory (preferred) or a sentinel-rejecting `AuditSink` behind `test-support` feature (fallback, §6.4). | `tools/call use_account` returns an error envelope; server does NOT silently succeed. |
| `audit_write_failure_does_not_block_initialize` | Same setup. | `initialize` either succeeds or fails with a clear error; exact behavior asserted from probe. |

### 4.4 `e2e_wire_cancellation.rs` (2 tests, Dovecot-backed)

| Test | Flow | Contract |
| --- | --- | --- |
| `cancel_search_emits_tool_end_cancelled` | `use_account` → start `tools/call search` over a large folder → poll audit log for `tool_start` (≤ 100 ms) → send `notifications/cancelled` with the request id → drain stdout. | Exactly one `tool_end` audit record for the cancelled request with `status: cancelled` (issues #71, #99). No `tool_end {status: ok}`. No panic. |
| `cancel_unknown_request_id_is_noop` | Send `notifications/cancelled` for an id that was never used. | No response, no panic, server still responsive to subsequent `tools/list`. |

## 5. Error handling

Every assertion failure includes captured child stderr via the
existing `Harness::captured_stderr` helper. Test diagnostics quote the
captured stream so a CI failure surfaces the binary's
`tracing::error!` output, not just the test panic line.

For probe-based contracts, the probed behavior is documented inline:

```rust
// Probed 2026-05-13 (rmcp 1.5): server responds with -32700.
// If this changes, the parse-error path either tightened (stricter
// envelope rejection) or the framing changed — investigate before
// updating the assertion.
```

Bugs found during probing — server panics on malformed input, hangs,
leaks partial state, emits malformed envelopes — are filed as
separate issues per the issue's acceptance criteria and fixed before
Phase 4 merges. Each such bug gets a regression test that lands with
the fix.

## 6. CI, dependencies, decomposition

### 6.1 CI integration

- Default `cargo test -p rimap-server` runs the 1000-case proptest
  properties under a per-property budget that keeps the suite under
  the existing `rimap-server` test wall-clock. No CI matrix changes.
- Overnight runs: GitHub Actions cron workflow at
  `.github/workflows/mcp-fuzz-nightly.yml` sets
  `PROPTEST_CASES=100000` and runs
  `cargo test -p rimap-server --tests mcp_wire_proptest -- --nocapture`.
  Pinned to a SHA per the repo's existing convention; `zizmor`
  passes before merge.
- Nextest classification: proptest tests use
  `slow-timeout` overrides so a stuck case fails fast instead of
  hitting the full CI timeout.
- Dovecot-backed cancellation tests reuse the existing
  `dovecot` gating mechanism from `e2e_wire.rs`.

### 6.2 Dependencies

No new crate. The fuzzing layer reuses `proptest` 1.6 (already a
workspace dep), `jsonschema`, `tempfile`, `tokio`, `serde_json`,
`assert_cmd`. `rmcp` 1.5 unchanged; the existing version-drift
detector in
`wire_protocol_version_negotiation_matches_vendored_schema` will
catch any bump that invalidates a fuzz assertion.

### 6.3 Decomposition

Phase 4 lands as a single PR but the work decomposes into sequenced
commits so probing-phase fallout does not block earlier commits:

1. **Harness extensions** (`support/wire/harness.rs`). Exercised
   transitively by the first test in `mcp_wire_negative.rs` that
   uses each new method — no separate unit-test module is added to
   `harness.rs` (the file currently has none and the integration
   tests are the natural call site).
2. **`mcp_wire_negative.rs`** — all probed contracts. Bugs found
   during probing are fixed on sibling branches before this commit
   lands.
3. **`mcp_wire_proptest.rs`** — three properties at 1000 cases.
   `proptest-regressions/` directory committed.
4. **`mcp_audit_failure.rs`** — fail-closed boundary tests. May
   reveal a small accessor need in `rimap-audit` (e.g., a way to
   observe writer failure from a test); scope-flagged in the PR if
   needed.
5. **`e2e_wire_cancellation.rs`** — Dovecot-backed cancel tests.
   Lands last; depends on Phase 3 harness + #99 Drop-emits-cancelled
   discipline.
6. **Nightly CI workflow** — same PR, reviewed separately.

### 6.4 Audit failure injection — primary and fallback

Primary mechanism: write the audit path to a `chmod 0o500` directory
(`tempfile::TempDir` followed by a `std::fs::set_permissions` to
revoke write). This is hermetic, requires no production-code change,
and tests the real `AuditSink` against a real `EACCES`.

Fallback (if `chmod` is unreliable as root in some CI runners): a
`SentinelRejectingAuditSink` behind a `test-support` feature on
`rimap-audit` that returns `Err` from every write. The test enables
the feature and configures the sink via a `test-support`-gated config
hook. Adds a permanent test-only branch in `rimap-audit`; choose
during implementation based on whether the `chmod` path actually
works on Linux + macOS CI.

## 7. Risk register

| Risk | Mitigation |
| --- | --- |
| Probing reveals a panic in the server on malformed input. | File issue, fix on sibling branch, regression test lands in Phase 4. Expected outcome, not blocker. |
| Proptest finds a minimal-shrunk case hard to reproduce. | `proptest-regressions/` committed; each property's regressions reviewed in the PR. |
| Concurrent-request test flaky under nextest. | Determinism comes from `send_request_no_wait` + `recv_until_id` (no clock races). If the binary serializes responses, the test still passes — just less interesting. |
| `chmod 0o500` audit-fail trick doesn't work as root in CI. | Fall back to `SentinelRejectingAuditSink` (§6.4). |
| Dovecot cancel test races `tool_start` audit landing. | Poll audit file 100 ms cap, 10 ms granularity rather than sleep-and-hope. |
| Proptest at 100 000 cases overruns the nightly job's runner budget. | `slow-timeout` per property; nightly runs publish duration as part of the failure summary so we can split a single property into smaller ones if needed. |

## 8. Acceptance criteria mapping

Each acceptance criterion from issue #266 maps to a concrete artifact:

- [ ] `cargo test -p rimap-server --tests mcp_wire_*` exercises every
      category — covered by §4.1–§4.4 across four files.
- [ ] Property tests run for ≥1000 cases per property in CI, gated by
      env flag — `ProptestConfig::with_cases(1000)` + `PROPTEST_CASES`
      override, §4.2 and §6.1.
- [ ] Every negative case has an explicit assertion about correct
      behavior — every row in §4.1–§4.4 has a contract column; "didn't
      crash" alone is never an assertion (§5).
- [ ] No new flakiness — determinism primitives in §3.2.
- [ ] Bugs found during implementation filed as separate issues and
      fixed before merge — §6.3 step 2 and §5.
- [ ] Design doc in `docs/superpowers/specs/` — this file.

## 9. Out of scope (explicit)

- Coverage-guided fuzzing (`.clusterfuzzlite/` already exists).
- IMAP-server-side fuzzing.
- Tool-output schema fuzzing.
- New tools, new config surface.
- Schema drift detection — already covered by
  `wire_protocol_version_negotiation_matches_vendored_schema` from
  Phase 1.
