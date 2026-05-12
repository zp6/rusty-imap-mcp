# MCP Wire-Shape Conformance Harness — Design

**Status:** Draft 2026-05-12
**Scope:** Phase 1 of 4 (issue #263) — a Rust integration test that spawns
`rusty-imap-mcp` via stdio, drives a fixed sequence of MCP JSON-RPC
requests, and validates every response against the MCP spec's official
JSON schemas. Phases 2–4 (Node strict-client, behavioral conformance vs.
Dovecot, protocol fuzzing) are tracked in #264 / #265 / #266 and are out
of scope here.

## 1. Motivation

Two real wire-shape bugs shipped past 200+ unit tests, the full
Dovecot-backed `tests/e2e.rs` integration suite, and `cargo deny`:

1. **#261 — empty `capabilities`.** `ServerInfo::default()` produced
   `"capabilities": {}` because every field was `None` and serde
   dropped them via `skip_serializing_if`. Spec-strict clients
   (`bobshell`) refused to call `tools/list`.
2. **`fix/tool-input-schema-object-type` — empty `inputSchema`.**
   No-argument tools (`list_folders`, `list_accounts`) advertised
   `"inputSchema": {}` instead of `{"type":"object","properties":{},"additionalProperties":false}`.
   Zod-based clients rejected the tools.

Neither bug is reachable from the in-process Rust API used by
`tests/e2e.rs`, which calls `ImapMcpServer::dispatch_account_scoped`
directly and bypasses serialization. Permissive clients (Claude
Desktop, IBM Bob desktop, MCP Inspector) tolerated both regressions;
the problems only surfaced against `bobshell` during a multi-hour
remote debugging session.

This phase eliminates the class of bug from regression-testing without
requiring Docker, a real IMAP server, or a Node toolchain.

## 2. Goals & Non-Goals

### Goals

- Spawn the production `rusty-imap-mcp` binary, drive its stdio with a
  deterministic JSON-RPC sequence, and validate every response against
  the MCP spec's JSON schemas.
- Permanent regression nets for the two cited bugs:
  - `initialize.result.capabilities.tools` is present on the wire.
  - Every `tools/list.result.tools[*].inputSchema.type == "object"`.
- Sub-second per test, no Docker, no network, no flakiness.
- Vendored schemas with a CI drift detector — deterministic offline
  builds, but no silent staleness when upstream MCP spec bumps.

### Non-Goals

- IMAP behavior (Phase 3 / #265).
- Node SDK strict-client validation (Phase 2 / #264).
- Coverage-guided fuzzing or property tests (Phase 4 / #266).
- Schema validation of tool *output* shape — out of scope for Phase 1;
  the spec schemas describe envelope and method-level result shape,
  which is what the cited bugs exercised.

## 3. Architecture

### 3.1 Test driver

New file: `crates/rimap-server/tests/mcp_wire_conformance.rs`.

A `Harness` helper owns the spawned child and exposes:

```rust
async fn request(&mut self, method: &str, params: Value) -> Value;
async fn notify(&mut self, method: &str, params: Value);
async fn assert_no_response_within(&mut self, dur: Duration);
async fn shutdown_and_wait(self) -> ExitStatus;
```

- Spawns via `tokio::process::Command` with stdin/stdout/stderr piped.
  Stderr is drained into a `Vec<u8>` for failure diagnostics.
- `request` writes exactly one line of JSON-RPC, reads exactly one line
  of stdout under a 2 s timeout, and parses to `serde_json::Value`. On
  timeout the captured stderr is included in the panic message.
- `notify` is fire-and-forget; pairs with `assert_no_response_within`.
- `shutdown_and_wait` closes stdin, awaits the child with a 1 s
  timeout, and returns the exit status.
- One `Harness::spawn()` per test — clean isolation, parallel-safe
  (`cargo test` runs integration tests in parallel by default).

The harness uses `assert_cmd::cargo::cargo_bin("rusty-imap-mcp")` to
resolve the freshly-built binary path. `assert_cmd` is already in
dev-dependencies.

### 3.2 Spawned-binary config

For each test the harness:

1. Creates a `TempDir`.
2. Writes a minimal `config.toml` with `accounts = []` and
   `audit.path = <tempdir>/audit.jsonl`.
3. Invokes the binary with `--config <path>`.

No accounts means no IMAP connection attempts, no keychain access, no
network. The audit log writes inside the tempdir and is cleaned up
when the test finishes.

### 3.3 Vendored MCP spec schemas

Layout:

```
crates/rimap-server/tests/fixtures/mcp-spec/
  README.md                        # source URL, refresh procedure, any local diffs
  2025-06-18/
    schema.json                    # verbatim vendored copy
```

One version is pinned. The pinned version is selected during plan
execution to match what `rmcp 1.4` negotiates by default (likely
`2025-06-18`, to be confirmed by reading rmcp's protocolVersion
handling in the implementation plan).

Schemas are compiled lazily via `OnceLock<jsonschema::Validator>` per
fragment (`InitializeResult`, `ListToolsResult`, `ListResourcesResult`,
`JSONRPCResponse`, `JSONRPCError`). Compilation happens once per test
process; reuse is cheap.

### 3.4 Schema refresh script

`scripts/refresh-mcp-spec.sh`. POSIX bash, `set -euo pipefail`,
`shellcheck`-clean.

Two modes:

- Default (`refresh-mcp-spec.sh <version>`): `curl` the schema from
  `https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/<version>/schema.json`,
  write atomically over the vendored file.
- Check (`refresh-mcp-spec.sh --check <version>`): fetch upstream into
  a temp file, `diff` against the vendored copy, exit non-zero on
  drift.

### 3.5 CI drift detector

New workflow: `.github/workflows/mcp-spec-drift.yml`.

- Trigger: `schedule: cron: '0 12 * * 1'` (Mondays at noon UTC) +
  `workflow_dispatch`.
- Runs `scripts/refresh-mcp-spec.sh --check <pinned-version>`.
- On drift, the workflow uses `gh issue list --label mcp-spec-drift
  --state open` to find an existing tracking issue. If one exists, it
  posts a comment with the diff summary. Otherwise it opens a new
  issue labelled `mcp-spec-drift` with the diff in the body.
- The workflow itself fails (red badge) so drift is visible in the
  Actions tab even if the issue mechanism breaks.

Permissions: minimum-scope `GITHUB_TOKEN` (`contents: read`,
`issues: write`). Pinned to SHA per project convention.

## 4. Test sequence

Each item is one `#[tokio::test(flavor = "multi_thread")]` function.

1. **`wire_initialize_advertises_tools_capability`**
   - Send `initialize` with a vendored client info payload.
   - Assert the full response validates against the
     `InitializeResult` schema fragment.
   - Assert `result.protocolVersion == <pinned>`.
   - Assert `result.capabilities.tools` is present (regression net for
     #261).

2. **`wire_initialized_notification_elicits_no_response`**
   - Run the `initialize` handshake.
   - Send `notifications/initialized`.
   - Assert no bytes appear on stdout within 200 ms.

3. **`wire_tools_list_returns_object_schemas`**
   - Handshake, then `tools/list`.
   - Assert envelope + `ListToolsResult` validate.
   - Assert at least `list_accounts` and `use_account` are present.
   - For every tool, assert `inputSchema.type == "object"`
     (regression net for `fix/tool-input-schema-object-type`).

4. **`wire_resources_list_is_empty_for_no_accounts`**
   - Handshake, then `resources/list`.
   - Assert envelope + `ListResourcesResult` validate.
   - Assert `result.resources == []`.

5. **`wire_tools_call_unknown_tool_returns_error_envelope`**
   - Handshake, then `tools/call` with a tool name that does not
     exist.
   - Assert envelope validates as `JSONRPCError`.
   - Assert `error.code` matches whatever rmcp emits for this case;
     the exact code is recorded in the test with a comment so a
     change in rmcp's mapping is a visible test edit, not silent
     drift.

6. **`wire_unknown_method_returns_minus_32601`**
   - Handshake, then a request with `method == "foo/bar"`.
   - Assert envelope validates as `JSONRPCError`.
   - Assert `error.code == -32601`.

7. **`wire_clean_eof_shutdown_exits_zero`**
   - Handshake, then close stdin.
   - Assert `shutdown_and_wait()` returns `ExitStatus::success()`
     within 1 s.

8. **`wire_protocol_version_negotiation_matches_vendored_schema`**
   - Send `initialize`.
   - Assert the returned `protocolVersion` equals the version directory
     under `tests/fixtures/mcp-spec/`. If rmcp bumps and the directory
     does not move, this test fails first and tells us to refresh
     the vendored schema before everything else breaks.

## 5. Dependencies

Added to `[workspace.dependencies]`:

```toml
# Validates MCP JSON-RPC envelopes against the vendored MCP spec schemas.
# Test-only — gated to dev-dependencies in member crates.
jsonschema = { version = "0.34", default-features = false }
```

Added to `[dev-dependencies]` in `crates/rimap-server/Cargo.toml`:

```toml
jsonschema = { workspace = true }
```

The exact `jsonschema` version is chosen during plan execution by
reading the latest stable release notes. No new runtime dependencies.

## 6. Risks & mitigations

- **rmcp emits fields outside the upstream schema.** Most MCP spec
  fragments do not set `additionalProperties: false`, but if any
  fragment we use is strict we relax it in the vendored copy and
  document the diff in `tests/fixtures/mcp-spec/<version>/README.md`.
- **The binary writes non-JSON to stdout before the JSON-RPC stream.**
  Would break framing. The boot logging path already goes to stderr;
  the harness includes a guard that asserts the first line on stdout
  is a parseable JSON-RPC response. If a future change adds stdout
  noise, this guard fires before anything else.
- **Slow CI runners exceed the 2 s per-request timeout on first
  call.** Mitigated by a separate, longer spawn timeout (5 s) on
  `Harness::spawn()`, distinct from the per-request budget.
- **CRLF line endings on Windows runners.** Not relevant — we publish
  for Linux / macOS only — but the reader trims `\r` for safety.
- **Parallel test runs spawn N binaries concurrently.** Each owns its
  own tempdir and stdio pipes; no shared state. Bounded by the test
  thread pool.

## 7. Acceptance criteria mapping

| Issue #263 criterion | Where addressed |
| --- | --- |
| Test file lands at `crates/rimap-server/tests/mcp_wire_conformance.rs` | §3.1, §4 |
| Runs under `cargo test -p rimap-server --tests mcp_wire_conformance` | §3.1 |
| No external deps beyond existing dev-deps + `jsonschema` | §5 |
| Sub-second per test, no flakiness from process startup races | §3.1 (timeouts), §6 (mitigations) |
| Documented in `docs/superpowers/specs/` | This document |
| Regression net for #261 (capabilities.tools present) | §4 case 1 |
| Regression net for `fix/tool-input-schema-object-type` | §4 case 3 |

## 8. Open items resolved during plan execution

- Exact pinned `protocolVersion` value (read rmcp 1.4 source).
- Exact `jsonschema` crate version (pick current stable; vet via
  `cargo deny` and supply-chain reviewer per project convention).
- Exact rmcp error code for `tools/call` with unknown tool name
  (record in test with a `// rmcp 1.4 emits this code` comment).
- Whether the spec ships a single combined `schema.json` or multiple
  fragment files (current upstream: single `schema.json` — confirm at
  fetch time and adjust §3.4 if it has split).

## 9. References

- Issue #263 — phasing parent.
- #261 — capabilities-empty bug, fixed.
- `fix/tool-input-schema-object-type` — inputSchema-empty bug, fix
  pending PR.
- MCP specification repo:
  `https://github.com/modelcontextprotocol/modelcontextprotocol`
- `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`
  — broader test-strategy context; this phase is complementary, not
  overlapping, with Sprint B3 (`rimap-server` + `rimap-imap` fuzz +
  mutation hardening).
