# MCP Behavioral Conformance via Stdio against Dovecot — Design

**Status:** Draft 2026-05-12
**Scope:** Phase 3 of 4 (issue #265) — a Rust integration test that drives
`rusty-imap-mcp` over its stdio JSON-RPC wire against the existing
Dovecot fixture, exercises every draft-safe-posture tool category at
least once, validates every response against both Phase 1's vendored MCP
spec schemas and a new set of project-local per-tool result schemas, and
asserts audit-log pairing plus posture-denial wire shape. Phase 1
(#263, landed) and Phase 2 (#264, landed) cover wire-shape conformance
without IMAP. Phase 4 (#TBD, protocol fuzzing) covers negative-path
wire traffic and is out of scope here.

## 1. Motivation

`crates/rimap-server/tests/e2e.rs::e2e_full_session` is comprehensive
against the IMAP backend but calls `ImapMcpServer::dispatch_account_scoped`
directly via the Rust API — it bypasses JSON-RPC serialization,
dispatch routing, and the stdio transport entirely. Two real bugs
slipped past it:

- **#261** — `initialize.result.capabilities` serialized as `{}`.
- **`fix/tool-input-schema-object-type`** — tools advertised
  `inputSchema: {}` with no `type` field.

Phases 1 and 2 catch wire-shape bugs in zero-account mode. They do not
catch dispatch and serialization bugs that only surface when a tool
actually executes against a real backend (e.g. response payload shape
for `list_folders` with real folders, error envelopes for IMAP-side
failures, attachment download with real bytes, audit envelope pairing
under real dispatch). Phase 3 fills that gap.

The phase reuses the existing fixture infrastructure:
`crates/rimap-imap/tests/integration/support/container.rs`,
`tests/integration/dovecot/docker-compose.yml`, the seeding helpers,
and the port-race handling already in `e2e.rs`.

## 2. Goals & Non-Goals

### Goals

- Drive a Dovecot-backed `rusty-imap-mcp` session over stdio JSON-RPC
  from a new Rust integration test.
- Exercise every category named in #265 at least once: list (folders,
  attachments, labels, accounts), fetch (message, attachment download),
  mutate (flag, label, move, draft), admin (use_account).
- Validate every response against (a) Phase 1's vendored MCP spec
  envelope + method schemas and (b) new project-local per-tool result
  schemas generated from the tool output structs.
- Exercise two postures — draft-safe and read-only — to surface
  advertise/dispatch posture-matrix drift at the wire layer.
- Assert paired `tool_start` / `tool_end` audit records for every wire
  tool call, plus the posture-denial record for a read-only mutation
  attempt.
- Match `e2e_full_session`'s gating exactly: silent skip when no
  container runtime is found or host arch is not `x86_64`;
  `RIMAP_REQUIRE_DOCKER=1` flips to loud failure.

### Non-Goals

- New IMAP fixtures — reuse what exists (Dovecot 2.3.21 amd64 image,
  one seeded `rimap-test` user).
- Replacing Phases 1 or 2 — all three coexist; they catch different
  regression classes.
- Negative-path / malformed-input wire traffic — Phase 4's job. Phase 3
  stays on happy + posture-denial paths.
- Auth isolation between MCP-side accounts — `rimap-imap` already
  covers per-user IMAP login; Phase 3's two accounts share the same
  Dovecot user because the surface under test is the posture matrix,
  not authentication.
- Schema validation of tool *input* shape — Phase 1 already pins every
  tool's `inputSchema.type == "object"`; Phase 3 focuses on result
  shape.
- Refactoring `e2e_full_session` to wire-only — keep the in-process
  Rust-API path for fast stack-trace debugging when wire tests fail
  (per #265 motivation).

## 3. Architecture

### 3.1 Layout

```
crates/rimap-server/tests/
├── support/                              # NEW shared module for integration tests
│   ├── mod.rs                            #   pub mod wire; pub mod dovecot;
│   ├── wire/
│   │   ├── mod.rs                        #   Harness, request/notify, schema validators
│   │   ├── harness.rs                    #   moved from mcp_wire_conformance.rs
│   │   └── schema.rs                     #   moved validator_for + assert_envelope_valid
│   └── dovecot.rs                        #   DovecotHarness moved out of e2e.rs
├── mcp_wire_conformance.rs               # CHANGED: uses support::wire (no behavior change)
├── e2e.rs                                # CHANGED: uses support::dovecot (no behavior change)
├── e2e_wire.rs                           # NEW: Phase 3 test file
└── fixtures/
    ├── mcp-spec/2025-11-25/schema.json   # unchanged (Phase 1)
    └── rimap-tool-schemas/                # NEW: generated, checked-in (one file per tool)
        ├── list_folders.schema.json
        ├── list_accounts.schema.json
        ├── list_labels.schema.json
        ├── list_attachments.schema.json
        ├── download_attachment.schema.json
        ├── search.schema.json
        ├── fetch_message.schema.json
        ├── mark_read.schema.json
        ├── mark_unread.schema.json
        ├── flag.schema.json
        ├── unflag.schema.json
        ├── add_label.schema.json
        ├── remove_label.schema.json
        ├── move_message.schema.json
        ├── create_draft.schema.json
        └── use_account.schema.json
```

The Phase 1 file (`mcp_wire_conformance.rs`) is unchanged in behavior —
only its `use` lines flip from inline module items to `support::wire::…`.
The Phase 1 schema cache, validator, and harness shape are preserved
byte-for-byte through the extraction so the regression net documented in
Phase 1's design remains intact.

### 3.2 Why a shared `support/` module

Rust integration tests under `tests/` each compile as their own crate.
The idiomatic share-pattern is a `tests/support/` (or `tests/common/`)
directory included via `#[path = "support/mod.rs"] mod support;` at the
top of each integration file. Phase 3 picks `support/` to match
`crates/rimap-imap/tests/integration/support/` which already follows the
same convention.

The alternative (each test file inlines its own copy of the wire driver
and schema validator) reproduces exactly the wire-shape duplication
problem that motivated Phases 1–3 in the first place. Approach
explicitly rejected during brainstorming.

### 3.3 Two-binary support layer

The `rusty-imap-mcp` binary already has the `--features test-support`
flag for Phase 1's `--allow-empty-accounts` and Phase 2's
`dump-tool-catalog` subcommand. Phase 3 adds a sibling subcommand
`dump-tool-schemas` under the same feature gate, which serializes every
`JsonSchema`-deriving tool output struct to a stable JSON Schema
document keyed by tool name. A new `just regen-tool-schemas` recipe
runs the subcommand and writes to `tests/fixtures/rimap-tool-schemas/`.
CI runs the regen and fails on a non-empty `git diff` — same drift
detector pattern Phase 1 uses for the vendored MCP spec fixtures.

### 3.4 Gating

Match `e2e_full_session` exactly:

- `DovecotHarness::try_start()` returns `None` (silent skip) when no
  container runtime is found or `std::env::consts::ARCH != "x86_64"`.
- `RIMAP_REQUIRE_DOCKER=1` flips silent skip to a `panic!` with the
  captured cause string.
- No new env vars introduced.

CI placement: add to the existing linux-x86_64 integration job that
already runs `e2e.rs`. Dovecot bring-up is amortized across both tests.

## 4. Components

### 4.1 `support::wire::Harness`

The `Harness` type, its methods, and the schema validators move from
`mcp_wire_conformance.rs` into `support::wire`. Phase 1's test file is
edited to swap inline definitions for `use crate::support::wire::…`
imports — the test bodies and assertions are byte-for-byte unchanged.

Existing surface: `spawn()`, `request()`, `notify()`,
`initialize_handshake()`, `send_initialized()`,
`assert_no_response_within()`, `shutdown_and_wait()`.

One new constructor:

```rust
impl Harness {
    /// Spawn with a caller-supplied config path. Used by Phase 3 to
    /// point at a Dovecot-backed multi-account TOML; Phase 1's
    /// `spawn()` becomes a thin wrapper that builds the zero-account
    /// TOML and calls this.
    async fn spawn_with_config(config_path: &Path, tempdir: TempDir) -> Self;
}
```

`stderr` capture changes from `Stdio::null()` to `Stdio::piped()` with a
drain task. The child's `tracing` output is the most useful diagnostic
when a wire response is unexpected. Phase 1's tests are sub-second; the
captured buffer is usually <4 KB per test and is included in panic
messages on assertion failure.

### 4.2 `support::dovecot::DovecotHarness`

Lifted unchanged from `e2e.rs` (including `ReservedPort`,
`wait_for_ready`, `read_fingerprint`, `compose_down`, the
`MAX_ATTEMPTS` / `BACKOFF_MS` port-collision retry, and `Drop`).
Container lifecycle stays per-test — keeps test isolation; the
~5–15 s bring-up cost is amortized across only the two suites that
need it (`e2e.rs` and `e2e_wire.rs`).

### 4.3 `support::wire::schema`

Phase 1's `validator_for(fragment: &'static str) -> Arc<jsonschema::Validator>`
and `assert_envelope_valid(value)` move here unchanged. One addition:

```rust
/// Compile (lazily, cached) a validator for the per-tool response
/// schema at `tests/fixtures/rimap-tool-schemas/<tool>.schema.json`.
/// Panics in the test process if the fixture is missing — that's the
/// signal that `just regen-tool-schemas` was not run.
fn validator_for_tool_response(tool: &'static str) -> Arc<jsonschema::Validator>;
```

Same `OnceLock` + `Mutex<HashMap>` cache shape so parallel tests
compiling different fragments do not serialize.

### 4.4 `dump-tool-schemas` test-support subcommand

Tool responses are emitted on the wire as `{"meta": {...},
"untrusted": {...}}` (verified against `e2e.rs` assertions). Each tool
that produces an `untrusted` payload has two separate response
structs in source (`<Tool>Meta` and `<Tool>Untrusted`); tools that
only produce metadata have just a `<Tool>Meta`. The `dump-tool-schemas`
subcommand composes them into one JSON Schema per tool that describes
the combined wire envelope, then writes one file per tool to stdout
keyed by tool name. The `just regen-tool-schemas` recipe pipes the
output into `tests/fixtures/rimap-tool-schemas/<tool>.schema.json`,
one file per key.

Sketch (gated behind `#[cfg(feature = "test-support")]` in
`crates/rimap-server/src/main.rs`):

```rust
#[cfg(feature = "test-support")]
fn dump_tool_schemas() -> Result<()> {
    let mut g = schemars::SchemaGenerator::default();

    // Helper: compose a {meta, untrusted} schema for tools that emit both.
    let compose = |meta: schemars::Schema, untrusted: schemars::Schema| { /* ... */ };

    let mut out = BTreeMap::<&'static str, schemars::Schema>::new();

    // meta-only tools
    out.insert("list_folders",  g.root_schema_for::<ListFoldersMeta>());
    out.insert("list_accounts", g.root_schema_for::<ListAccountsMeta>());
    out.insert("list_labels",   g.root_schema_for::<ListLabelsMeta>());
    out.insert("mark_read",     g.root_schema_for::<FlagsMeta>());
    out.insert("mark_unread",   g.root_schema_for::<FlagsMeta>());
    out.insert("flag",          g.root_schema_for::<FlagsMeta>());
    out.insert("unflag",        g.root_schema_for::<FlagsMeta>());
    out.insert("add_label",     g.root_schema_for::<LabelsMeta>());
    out.insert("remove_label",  g.root_schema_for::<LabelsMeta>());
    out.insert("move_message",  g.root_schema_for::<MoveMessageMeta>());
    out.insert("create_draft",  g.root_schema_for::<CreateDraftMeta>());
    out.insert("use_account",   g.root_schema_for::<UseAccountMeta>());

    // meta + untrusted tools
    out.insert("search", compose(
        g.root_schema_for::<SearchMeta>(),
        g.root_schema_for::<SearchUntrusted>(),
    ));
    out.insert("fetch_message", compose(
        g.root_schema_for::<FetchMessageMeta>(),
        g.root_schema_for::<FetchMessageUntrusted>(),
    ));
    out.insert("list_attachments", compose(
        g.root_schema_for::<ListAttachmentsMeta>(),
        g.root_schema_for::<ListAttachmentsUntrusted>(),
    ));
    out.insert("download_attachment", compose(
        g.root_schema_for::<DownloadAttachmentMeta>(),
        g.root_schema_for::<DownloadAttachmentUntrusted>(),
    ));

    // One file per tool, JSON-pretty-printed for review-friendly diffs.
    for (name, schema) in &out {
        let path = fixture_dir.join(format!("{name}.schema.json"));
        std::fs::write(path, serde_json::to_string_pretty(schema)?)?;
    }
    Ok(())
}
```

The struct names above are the actual public structs in the current
tree (verified via `grep` against `crates/rimap-server/src/tools/`).
The implementation plan adds `#[derive(schemars::JsonSchema)]` next to
the existing `Serialize` derive on each struct, gated behind
`#[cfg(any(test, feature = "test-support"))]` so the production binary
does not depend on `schemars`.

Tools advertised by the server but not in the dump set
(`send_email`, `delete_message`, `expunge`, `create_folder`,
`rename_folder`, `delete_folder`) are out of scope for Phase 3 — they
are gated by postures Phase 3 does not exercise (`ready-to-send`,
mutating-folder operations) or require seeded state the suite does not
build (folder lifecycle). They can be added in a follow-up without
spec churn — the regen recipe just needs another line and the test
sequence one more `tools/call`.

`flag` and `unflag` *are* in scope despite sharing `FlagsMeta` with
`mark_read`/`mark_unread`: schema equivalence does not imply dispatch
equivalence. They have separate `ToolName` variants, separate
posture-matrix entries, separate handler functions, and mutate a
different IMAP flag (`\Flagged` vs `\Seen`). A regression in either
would pass a `mark_read`-only test.

### 4.5 `e2e_wire.rs`

Two `#[tokio::test]` cases:

- `wire_e2e_full_session_draft_safe` — mirrors `e2e_full_session`'s
  sequence over the wire (list_folders → seed via in-process IMAP →
  search → fetch_message → mark_read → create_draft × 2 →
  move_message), plus the issue-named extras
  (`list_attachments`, `download_attachment`, `list_labels`,
  `list_accounts`, `use_account`).
- `wire_e2e_readonly_posture_denial` — second account configured
  `read-only`; `tools/list` asserts mutating tools are not advertised
  under the read-only namespace; one `tools/call` against
  `readonly.move_message` asserts the JSON-RPC error envelope is the
  posture-denial shape, and the captured audit log contains a
  denied-by-posture record paired with its `tool_start`.

### 4.6 Multi-account config TOML builder

`support::wire::config::build_dovecot_config(harness, audit_path,
allowed_base) -> String` writes a `[[accounts]]`-table TOML with two
accounts (`draftsafe` draft-safe, `readonly` read-only) both pointing at
Dovecot's seeded `rimap-test` user.

Two MCP accounts, one Dovecot user. The surface under test is the
posture matrix on the wire; auth isolation is `rimap-imap`'s concern
and is already tested there.

**Why not the id `default`.** `crates/rimap-server/src/mcp/server.rs`
records `account = None` in audit envelopes for any account whose id
equals `rimap_core::account::DEFAULT_ACCOUNT_NAME` (`"default"`), even
in multi-account deployments — a backwards-compat carve-out for the
legacy single-account path. Naming one of the two test accounts
`default` would mask the very thing the suite is meant to verify: that
account-scoped tool calls are attributed to the right tenant in the
audit log. Both Phase 3 accounts therefore use non-reserved ids
(`draftsafe`, `readonly`).

Because the test config has more than one account, the binary
advertises namespaced tool names (`<account>.<tool>`) — the same
multi-account display path `e2e.rs` does not exercise today. This is
intentional additional coverage.

## 5. Data Flow

### 5.1 `wire_e2e_full_session_draft_safe`

```
1. DovecotHarness::try_start()        → silent skip on no runtime / non-x86_64
2. harness.create_mailbox("Drafts")
   harness.create_mailbox("Trash")
3. Build multi-account TOML in tempdir:
     - [[accounts]] id="draftsafe" posture="draft-safe"  → rimap-test@dovecot
     - [[accounts]] id="readonly"  posture="read-only"   → rimap-test@dovecot
     - [audit] path=<tempdir>/audit.jsonl  allowed_base_dir=<tempdir>
   (Neither id is "default" — see §4.6 for why DEFAULT_ACCOUNT_NAME
   would mask audit attribution.)
4. Seed one multipart MIME message into INBOX via in-process
   Connection::append_message. The seed body has at least one
   non-trivial attachment part (e.g. `application/octet-stream` with
   filename `attached.bin` and a known byte payload) so the wire
   `list_attachments` and `download_attachment` calls in step 9
   exercise the real-bytes path, not an empty-list edge. The seed is
   built once in `support::dovecot::fixtures::multipart_with_attachment()`.
5. Harness::spawn_with_config(config_path)
6. initialize → assert_valid(InitializeResult); capture protocol version
7. notifications/initialized
8. tools/list → assert_valid(ListToolsResult)
   - Build a map { tool_name → tool_def } from the response
   - Assert namespaced names exist: draftsafe.list_folders,
     readonly.list_folders, etc.
   - Assert read-only namespace LACKS mutating tools
     (move_message, create_draft, mark_read, mark_unread, flag, unflag,
     add_label, remove_label, …)
9. For each step in the e2e_full_session sequence + issue-named extras:
     a. tools/call name="draftsafe.<tool>" arguments=<json>
     b. assert_envelope_valid(response)
     c. assert_valid(response.result.structuredContent, tool_response_schema)
     d. Apply the same behavioral assertion e2e.rs makes
        (folders contains INBOX; search returns the seed uid; …)
   The sequence covers:
     - list_folders                                  (list/folders)
     - list_attachments → assert ≥1 part with a non-empty `part_id`
     - download_attachment → assert the downloaded path is under the
       per-account `download_dir` (sandboxed) and bytes equal the
       seed attachment payload
     - list_labels                                   (list/labels)
     - search → fetch_message (round-trip the seed uid)
     - mark_read / mark_unread                       (flag mutation,
       Seen)
     - flag / unflag                                 (flag mutation,
       Flagged — distinct ToolName variants from mark_read/unread)
     - add_label / remove_label                      (label mutation)
     - create_draft × 2                              (one with
       in_reply_to_uid, one bare)
     - move_message → re-search to assert it's gone from INBOX
     - use_account (admin, switches to readonly), list_accounts
10. shutdown_and_wait() → assert exit 0
11. Read audit.jsonl, group records by (tool_start, tool_end):
    - For each account-scoped tools/call from step 9: exactly one
      tool_start + one tool_end, both carrying `account = "draftsafe"`.
    - For each infrastructure tools/call (`use_account`,
      `list_accounts`): both records carry `account = None`.
    - tool_end.start_seq == tool_start.seq (pairing invariant).
```

### 5.2 `wire_e2e_readonly_posture_denial`

```
1-7. Same harness/initialize/initialized as above.
8. tools/list →
   - Assert readonly.move_message is NOT advertised.
   - Assert draftsafe.move_message IS advertised.
9. tools/call name="readonly.move_message"
   arguments={"folder":"INBOX","destination":"Trash","uid":1}
   - assert_envelope_valid(response)
   - Assert response.error.code is the posture-denial code
     (pinned in a const near the assertion; comment "if this changes,
     rmcp's error mapping or posture-denial bridge drifted; update with
     rationale" — same pattern Phase 1 uses for the -32602 INVALID_PARAMS
     pin on unknown-tool calls).
10. shutdown_and_wait() → exit 0
11. Read audit.jsonl → assert exactly one tool_start for
    readonly.move_message carrying `account = "readonly"` (proving
    the audit boundary is correctly scoped under the read-only
    namespace, not collapsed to legacy `None`), paired with a
    tool_end carrying the posture-denial outcome (exact field name
    from the current AuditRecord shape; looked up during plan
    execution, not pinned in this spec).
```

### 5.3 Seed strategy

Use the in-process `Connection::append_message` shortcut that `e2e.rs`
already uses, not a wire tool. There is no `append_raw_message` MCP
tool — `create_draft` is opinionated and adds keywords
(`$PendingReview`). Treating `create_draft` as the seed would couple
the seeding step to one of the assertions later in the same flow.

The wire surface is what's being exercised; the seed is plumbing.
Keeping the seed in-process makes the test's intent honest.

**Seed body shape.** Phase 3's seed differs from `e2e.rs`'s
`test_message()`. Where `e2e_full_session` uses a single-part
`text/plain` body — sufficient for its assertions — Phase 3 requires
a multipart message because the wire flow exercises `list_attachments`
and `download_attachment`. A `text/plain`-only seed makes both calls
either empty or error paths, voiding the real-bytes attachment
regression coverage Phase 3 claims.

`support::dovecot::fixtures::multipart_with_attachment()` constructs a
`multipart/mixed` MIME message with:

- A `text/plain` body part with deterministic content (so
  `fetch_message` assertions remain a one-line equality check).
- One `application/octet-stream` attachment part with
  `Content-Disposition: attachment; filename="attached.bin"` and a
  small fixed byte payload (e.g. 16–64 deterministic bytes) so
  `download_attachment` can byte-compare the downloaded file against
  the known payload.

The fixture is a `pub const`/`fn` in `support::dovecot::fixtures` so
both seeds and assertions reference the same payload — no duplication
between "what was seeded" and "what to compare against."

## 6. Error Handling

Three failure classes, three diagnostic shapes:

| Class | Symptom | Handling |
|---|---|---|
| Infrastructure | Docker missing, arch mismatch, Dovecot health-check timeout | Silent skip (`return;`) — matches `e2e_full_session`. `RIMAP_REQUIRE_DOCKER=1` flips silent skip to a `panic!` with the captured cause string. |
| Wire / protocol | Spawned binary exits early, stdout closed mid-handshake, response is non-JSON, response `id` doesn't match request, envelope fails `assert_envelope_valid` | `panic!` with the captured stderr from the child plus the offending payload. |
| Semantic | Tool call succeeded on the wire but a behavioral assertion fails (uid missing, body content wrong, audit pairing broken) | `assert!` / `assert_eq!` with the response value and audit-record context in the message. |

**Spawned-binary stderr is captured, not silenced.** Phase 1 currently
uses `Stdio::null()` for stderr. Phase 3 flips to `Stdio::piped()` with
a stderr-drain task. When a wire call fails, the binary's own `tracing`
output is the most useful diagnostic. The drain task lives in
`support::wire::Harness` so Phase 1 also benefits; the cost is a
post-test buffer of usually <4 KB.

**Cleanup ordering.** `DovecotHarness::Drop` calls
`compose down -v --remove-orphans` (unchanged from today). The
`Harness` (spawned binary) holds `kill_on_drop(true)` like Phase 1 so a
panicking test does not leak the child. Order: child dies first (test
scope unwind), then Dovecot teardown, then tempdir cleanup. Container
lifecycle outlives the spawned binary in every successful path.

**Audit-log read timing.** Audit records are written from a
`spawn_blocking` task. After the last `tools/call` returns successfully
on the wire, the test calls `shutdown_and_wait()` *before* opening the
audit file. Phase 1's `wire_clean_eof_shutdown_exits_zero` already
proves the binary flushes audit before exit. This avoids the
"did the last record get persisted" race that `dispatch_ticket.rs`
solves with `drop(server)`; the wire-test equivalent is
`shutdown_and_wait()`.

**Posture-denial wire pin.** The exact JSON-RPC error code returned
for a posture-denied tool call is whatever `rmcp`'s `ErrorData` bridge
produces today. The test pins the observed code in a `const` near the
assertion with a comment explaining the drift-detection intent. Same
discipline Phase 1 uses for the `-32602` pin on unknown-tool calls.

## 7. Testing the Test

### 7.1 Tool-schema regen drift detector

A new CI step runs `just regen-tool-schemas` followed by
`git diff --exit-code tests/fixtures/rimap-tool-schemas/`. If a tool's
output struct changes shape and the dev forgot to regen, CI fails with
a precise diagnostic naming the divergent files. Local workflow:
edit struct → `just regen-tool-schemas` → commit both diffs. Same
pattern Phase 1 documents for `tests/fixtures/mcp-spec/`.

### 7.2 MCP-spec version pin propagation

Phase 1 already has a three-way drift check
(`rmcp::ProtocolVersion::LATEST` ↔ `PINNED_PROTOCOL_VERSION` ↔ fixture
directory). Phase 3's harness inherits that constant from
`support::wire`, so a single test
(`wire_protocol_version_negotiation_matches_vendored_schema`) gates
both phases.

### 7.3 Wall-time budget

Issue #265 acceptance criterion: "Wall time documented; if >60s, gate
behind an env flag." The implementation plan measures actual wall time
after the test lands. Expected: ~10–20 s on a warm machine, Dovecot
bring-up dominating; the wire flow itself is sub-second. If the
measured time exceeds 60 s in practice, the plan adds
`RIMAP_RUN_E2E_WIRE=1` gating and documents the trigger in
`AGENTS.md` — that's a fallback path, not the primary one.

### 7.4 CI placement

No new workflow files. Add to the same job that already runs
`e2e.rs` (the existing linux-x86_64 integration job — same Dovecot
bring-up, amortized). Phase 1 and Phase 2 jobs are untouched.

### 7.5 What Phase 3 does NOT cover

Phase 4 (#TBD, protocol fuzzing) handles negative-path and
malformed-input wire traffic. Phase 3 stays on the happy + posture-
denial paths; treating malformed JSON-RPC or oversized payloads as
Phase 3's job blurs the line with Phase 4 and inflates this PR.

## 8. Acceptance criteria (from #265, refined)

- [ ] `cargo test -p rimap-server --test e2e_wire` exercises at least
  one wire-driven Dovecot scenario. (`--test` selects the integration
  target; the earlier `--tests <name>` form would silently degrade to
  a name-filter that matches nothing and pass with zero tests run.)
- [ ] CI runs the Phase 3 target via `cargo nextest run -p rimap-server
  --test e2e_wire` (or the `cargo test` equivalent) wrapped in a
  zero-tests-selected guard — `nextest`'s `--no-tests=fail` or, with
  `cargo test`, a `--list` count check — so a future rename / move /
  delete of the test file cannot produce a green CI signal with no
  Phase 3 scenarios actually run. Exact flag pinned in the plan.
- [ ] Coverage of all draft-safe-posture tools named in the issue
  scope is confirmed by tool-call audit records in the captured audit
  log, every record carrying the correct account namespace
  (`draftsafe` for account-scoped tools; `None` for the
  `use_account` / `list_accounts` infrastructure tools): list_folders,
  list_attachments, download_attachment, list_labels, list_accounts,
  search, fetch_message, mark_read, mark_unread, flag, unflag,
  add_label, remove_label, move_message, create_draft, use_account.
- [ ] Attachment coverage is concrete: the seed is a `multipart/mixed`
  message with at least one non-trivial attachment; `list_attachments`
  returns ≥1 part with a non-empty `part_id`; `download_attachment`
  writes a file inside the sandboxed `download_dir` whose bytes equal
  the seed attachment's known payload.
- [ ] Posture denial: at least one mutating tool call against the
  read-only account returns the pinned posture-denial error envelope
  and produces a paired tool_start/tool_end record in the audit log
  carrying `account = "readonly"` (not collapsed to `None`).
- [ ] Every wire response validates against (a) Phase 1's vendored MCP
  spec envelope/method schemas and (b) the per-tool response schema in
  `tests/fixtures/rimap-tool-schemas/`.
- [ ] Tool-schema regen drift detector lands as a CI step.
- [ ] Skips cleanly when Docker/Podman are not available (silent
  skip; `RIMAP_REQUIRE_DOCKER=1` flips to loud failure).
- [ ] Wall time documented in `AGENTS.md` test-strategy section; if
  >60 s, gated behind an env flag and the trigger documented.
- [ ] Phase 1 (`mcp_wire_conformance.rs`) and Phase 2
  (`tests/mcp-conformance/`) continue to pass with no behavior change.
- [ ] Design doc (this file) and a cross-link from `AGENTS.md`.

## 9. Phasing context

Phase 3 of 4. Phase 1 (#263) and Phase 2 (#264) landed in May 2026 and
share the wire driver this spec extracts into `support::wire`. Phase 4
(#TBD, protocol fuzzing) is the final phase and is unblocked once
Phase 3 lands.
