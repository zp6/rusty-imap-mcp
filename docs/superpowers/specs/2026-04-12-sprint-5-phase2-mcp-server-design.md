# Sprint 5 Phase 2 — MCP Server, v1 Tool Surface, Draft-Safe Send

**Status:** Approved 2026-04-12
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](2026-04-07-rusty-imap-mcp-design.md) §Sprint 5
**Phase 1 handoff:** [`../plans/2026-04-10-sprint-5-phase1-handoff.md`](../plans/2026-04-10-sprint-5-phase1-handoff.md)
**Branch:** `feat/sprint-5`

## 1. Scope and Strategy

Phase 2 wires the MCP server binary, implements all v1 tool handlers, adds
IMAP mutation operations, and ships `v0.1.0`. It is decomposed into four
sub-phases executed sequentially on `feat/sprint-5`:

| Sub-phase | Scope | New deps |
|-----------|-------|----------|
| **2a** | IMAP mutations (STORE, MOVE, APPEND) + `spawn_blocking` | none |
| **2b** | rmcp stdio transport, tool dispatch, 9 tool handlers, attachment sandboxing | `rmcp 1.4.0`, `infer`, `schemars 1.0` |
| **2c** | `create_draft` handler: `mail-builder`, threading, `$PendingReview`, draft rate limit | `mail-builder 0.4.4` |
| **2d** | End-to-end smoke test (Dovecot), 5 documentation files, `epvme_runner` tests, mutants rerun, `v0.1.0` tag |  none |

### Issues addressed

| Issue | Items included | Items deferred |
|-------|---------------|----------------|
| #8 (audit lifecycle glue) | ProcessStart/ProcessEnd in server startup/shutdown | — |
| #53 item 1 (spawn_blocking) | Async wrapper in rimap-server | — |
| #53 item 2 (epvme_runner tests) | Integration tests in 2d | — |

### Deferred beyond Sprint 5

- **#14, #18, #19** — security review tooling (post-v1)
- **#32** — fetch_body backpressure (architectural, post-v1)
- **#44, #45** — audit retention and backup exclusion (post-v1)
- **#50 item 2** — Authentication-Results parser (needs own spec)
- **#51 item 1** — `message/rfc822` recursion (needs own spec)

## 2. Phase 2a — IMAP Mutations + `spawn_blocking`

### 2.1 STORE (flag manipulation)

File: `crates/rimap-imap/src/ops/store.rs` (new)

```rust
pub async fn store_flags(
    &mut self,
    folder: &str,
    uids: &[MessageUid],
    flags: &[Flag],
    action: FlagAction,  // Add | Remove
) -> Result<Vec<MessageUid>, ImapError>;
```

- Uses UID STORE, not sequence numbers.
- Batch-bounded: `rimap-imap` enforces ≤100 UIDs defensively. Returns
  `ImapError::BatchTooLarge` if exceeded.
- Returns the UIDs that were actually updated (IMAP server may silently
  skip non-existent UIDs).

Four tool-level operations map to this:

| Tool | Flags | Action |
|------|-------|--------|
| `mark_read` | `\Seen` | Add |
| `mark_unread` | `\Seen` | Remove |
| `flag` | `\Flagged` | Add |
| `unflag` | `\Flagged` | Remove |

### 2.2 MOVE

File: `crates/rimap-imap/src/ops/move_msg.rs` (new)

```rust
pub async fn move_messages(
    &mut self,
    source_folder: &str,
    dest_folder: &str,
    uids: &[MessageUid],
) -> Result<Vec<MoveResult>, ImapError>;

pub struct MoveResult {
    pub old_uid: MessageUid,
    pub new_uid: Option<MessageUid>,  // None without UIDPLUS
}
```

- Capability-check `MOVE` extension first.
- Fallback: `COPY` + `STORE +FLAGS \Deleted` + `EXPUNGE` when MOVE is
  absent. The fallback is not atomic — this is documented in the error
  type and the `move_message` tool response.
- Same ≤100 UID batch cap.

### 2.3 APPEND (for drafts)

File: `crates/rimap-imap/src/ops/append.rs` (new)

```rust
pub async fn append_message(
    &mut self,
    folder: &str,
    message: &[u8],
    flags: &[Flag],
    keywords: &[&str],
) -> Result<AppendResult, ImapError>;

pub struct AppendResult {
    pub uid: Option<MessageUid>,  // requires UIDPLUS
}
```

- Takes raw RFC 5322 bytes (from `mail-builder` in Phase 2c).
- Sets flags and keywords in the APPEND command.
- Returns assigned UID if server supports UIDPLUS.

### 2.4 `spawn_blocking` wrapper

File: `crates/rimap-server/src/content.rs` (new)

```rust
pub async fn parse_message_async(
    raw: &[u8],
) -> Result<Content, ContentError> {
    let raw = raw.to_vec();
    tokio::task::spawn_blocking(move || {
        rimap_content::parse_message(&raw)
    }).await?
}
```

- `parse_message` is CPU-bound (~2ms). `spawn_blocking` prevents it from
  blocking the tokio runtime under concurrent MCP requests.
- `JoinError` from `spawn_blocking` maps to `ContentError::Internal`.

### 2.5 Testing (Phase 2a)

- Integration tests against Dovecot container harness for each STORE
  operation (add/remove `\Seen`, add/remove `\Flagged`).
- Integration test for MOVE (with MOVE capability).
- Integration test for MOVE fallback (COPY+DELETE path). Test by mocking
  the capability response or configuring Dovecot without MOVE.
- Integration test for APPEND: append a raw message to INBOX, verify it
  appears with correct flags.
- Batch cap enforcement: verify `BatchTooLarge` on 101 UIDs.
- Unit test for `parse_message_async`: verify same result as sync call.

## 3. Phase 2b — MCP Server Wiring + Tool Handlers

### 3.1 New dependencies

Add to `[workspace.dependencies]` in root `Cargo.toml`:

```toml
rmcp = { version = "1.4", features = ["server", "macros", "transport-io"] }
schemars = "1.0"
infer = "0.19"
sha2 = "0.11"
```

- `rmcp`: MCP server framework. Edition 2024, deps align with workspace
  (`thiserror 2`, `tokio 1`, `serde 1`, `futures 0.3`).
- `schemars`: JSON Schema generation for tool input structs. Used by rmcp
  for `list_tools` schema advertisement.
- `infer`: MIME type sniffing for `download_attachment`.
- `sha2`: SHA-256 hashing for downloaded attachments.

Update `deny.toml` with entries for all new crates. `cargo deny check`
must pass.

### 3.2 Server structure

File: `crates/rimap-server/src/server.rs` (new)

```rust
struct ImapMcpServer {
    config: Config,
    imap: ImapClient,
    matrix: EffectiveMatrix,
    rate_limiter: RateLimiter,
    breaker: CircuitBreaker,
    audit: AuditWriter,
    download_dir: PathBuf,  // resolved at startup
}
```

### 3.3 Startup sequence

In `main.rs`, when no subcommand is given (MCP server mode):

1. Load and validate config.
2. Initialize `AuditWriter` — write `ProcessStart` record (#8).
3. Resolve `download_dir`: use configured `attachments.download_dir` if
   set, otherwise create a per-session tempdir.
4. Authenticate to IMAP server (TLS + login).
5. Build `EffectiveMatrix` from config posture + per-tool overrides.
6. Build `RateLimiter` and `CircuitBreaker` from config limits.
7. Register tools: iterate `ToolName` variants, check
   `matrix.allows(posture, tool)`, register only allowed tools with rmcp.
8. Start rmcp stdio transport, serve until stdin closes.
9. On shutdown: write `ProcessEnd` audit record, flush audit, clean up
   tempdir if session-created.

### 3.4 Tool dispatch chain

File: `crates/rimap-server/src/dispatch.rs` (new)

Every tool handler passes through a shared dispatch wrapper:

```rust
async fn dispatch<F, Fut, T>(
    &self,
    tool: ToolName,
    args: &serde_json::Value,
    f: F,
) -> Result<ToolResponse, McpError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, ToolError>>,
    T: Serialize,
```

Pipeline:

1. **Authz** — verify `matrix.allows(posture, tool)` (defense-in-depth;
   tool shouldn't be registered if denied, but check anyway).
2. **Circuit breaker** — check breaker state. Auth failures trip
   immediately. IMAP errors tracked in sliding window.
3. **Rate limiter** — check global bucket. Draft-specific bucket checked
   only for `create_draft` (Phase 2c).
4. **Audit ToolStart** — write record with redacted args per config
   policy.
5. **Execute** — call the inner function.
6. **Audit ToolEnd** — write record with outcome (success or error code).
7. **Format response** — wrap result in the `meta` / `untrusted` /
   `security_warnings` envelope.

### 3.5 Response envelope

Every tool response follows the design spec §5 structure:

```json
{
  "meta": { },
  "untrusted": { },
  "security_warnings": [ ]
}
```

- `meta`: server-controlled metadata. Trusted.
- `untrusted`: sanitized content from email. Agents treat as untrusted.
- `security_warnings`: structured observations from the sanitization and
  lookalike layers. Trusted metadata.

Tools that produce no untrusted content (e.g., flag mutations) omit the
`untrusted` field or return it empty.

### 3.6 Input validation via `schemars`

Each tool's input struct derives `JsonSchema` via `schemars 1.0`:

```rust
#[derive(Deserialize, JsonSchema)]
struct FetchMessageInput {
    folder: String,
    uid: u32,
    include_html: Option<bool>,
    max_body_bytes: Option<usize>,
}
```

rmcp uses these schemas for `list_tools` advertisement and automatic
input shape validation. Field-level semantic validation (e.g., folder
name not empty, uid > 0) is done in the handler.

### 3.7 Tool handler details

#### `list_folders`

- IMAP: LIST + STATUS (existing `rimap-imap` ops).
- Content: folder names through `rimap_content::unicode::sanitize` (NFKC,
  control char strip).
- Response: `meta.folders[]` with `name`, `delimiter`, `flags`, `exists`,
  `unseen`, `uid_validity`.

#### `search`

- Input: structured fields (from, to, subject, since, before, etc.) plus
  `advanced_query` (full posture only — guarded by matrix check on
  `search.advanced_query`).
- IMAP: build SEARCH command from structured fields. FETCH ENVELOPE +
  FLAGS + RFC822.SIZE for matched UIDs, paginated by `limit`/`offset`.
- Content: header-only sanitization (NFKC, control char strip, lookalike
  scan on From/To/Cc/Reply-To).
- Response: `meta.total_matched`, `meta.truncated`,
  `untrusted.messages[]`, `security_warnings[]`.
- Search results include headers only — never body content.

#### `fetch_message`

- Input: `folder`, `uid`, `include_html` (optional), `max_body_bytes`
  (optional).
- `include_html=true` rejected unless matrix allows
  `fetch_message.include_html`. Returns `ERR_FORBIDDEN` if denied.
- IMAP: FETCH BODY[] for full raw message.
- Content: `parse_message_async` → full `Content` struct.
- Response: `meta` (folder, uid, message_id, size_bytes, truncated),
  `untrusted` (headers, common_headers, mailing_list, body_text,
  body_html_sanitized if allowed, attachments, link_warnings),
  `security_warnings`.
- `max_body_bytes` truncates `body_text` and `body_html_sanitized` on a
  grapheme boundary. Sets `meta.truncated = true`.

#### `list_attachments`

- IMAP: FETCH BODYSTRUCTURE (existing `rimap-imap` op).
- Content: attachment metadata from MIME structure walk. Filenames through
  `sanitize_filename`.
- Response: `meta`, `untrusted.attachments[]` (part_id,
  filename_sanitized, mime_type, size_bytes), `security_warnings`.

#### `download_attachment`

- Input: `folder`, `uid`, `part_id`, `dest_dir` (optional).
- Resolve destination:
  1. If `dest_dir` provided: canonicalize, verify it starts with
     configured `attachments.download_dir`. Reject path traversal with
     `ERR_INVALID_PARAMS`.
  2. If not provided: use session tempdir (created lazily on first
     download, cleaned on server shutdown).
- IMAP: FETCH BODY[part_id] for raw part bytes.
- Filename: from MIME metadata → `rimap_content::sanitize_filename`.
- De-duplicate on collision: append `_1`, `_2`, etc.
- Write bytes to disk.
- MIME sniff via `infer` on the written bytes.
- SHA-256 hash via `sha2`.
- Response: `meta.path`, `meta.size_bytes`, `meta.sha256`,
  `meta.mime_type_declared`, `meta.mime_type_sniffed`,
  `untrusted.filename_original`, `security_warnings`.

#### `mark_read` / `mark_unread` / `flag` / `unflag`

- Input: `folder`, `uid` or `uids` (≤100).
- IMAP: `store_flags` from Phase 2a.
- Response: `meta.folder`, `meta.uids_updated[]`.
- No `untrusted` or `security_warnings` — pure metadata operations.

#### `move_message`

- Input: `source_folder`, `dest_folder`, `uid` or `uids` (≤100).
- IMAP: `move_messages` from Phase 2a.
- Response: `meta.source_folder`, `meta.dest_folder`,
  `meta.moves[].old_uid`, `meta.moves[].new_uid`.
- No `untrusted` or `security_warnings`.

### 3.8 Error mapping

Tool errors map to stable MCP error codes from the design spec §9:

| Domain | Code |
|--------|------|
| Input validation | `ERR_INVALID_PARAMS` |
| Authz denied | `ERR_FORBIDDEN` |
| Rate limited | `ERR_RATE_LIMITED` |
| Breaker open | `ERR_UNAVAILABLE` |
| IMAP failure | `ERR_IMAP` |
| TLS failure | `ERR_TLS` |
| Content parse | `ERR_CONTENT` |
| Internal | `ERR_INTERNAL` |

Each error includes a human-readable `message` field. No email content
leaks into error messages.

### 3.9 Testing (Phase 2b)

- Unit tests for the dispatch wrapper: mock IMAP client, verify audit
  records written, verify error mapping for each error domain.
- Unit tests per handler: mock IMAP responses → verify JSON response
  structure matches spec.
- Integration test: start MCP server in-process with Dovecot backend,
  send tool requests, verify responses.
- `cargo deny check` passes with all new dependencies.

## 4. Phase 2c — `create_draft`

### 4.1 New dependency

Add to `[workspace.dependencies]`:

```toml
mail-builder = "0.4"
```

Same author/org as `mail-parser` (Stalwart Labs). Single runtime
dependency (`gethostname`). Apache-2.0 OR MIT. Update `deny.toml`.

### 4.2 Draft construction

File: `crates/rimap-server/src/tools/create_draft.rs` (new)

Input:

```rust
#[derive(Deserialize, JsonSchema)]
struct CreateDraftInput {
    to: Vec<Address>,
    cc: Option<Vec<Address>>,
    bcc: Option<Vec<Address>>,
    subject: String,
    body_text: String,
    in_reply_to_uid: Option<u32>,
    in_reply_to_folder: Option<String>,  // defaults to INBOX
}
```

### 4.3 Threading header resolution

When `in_reply_to_uid` is provided:

1. FETCH the referenced message's `Message-ID` and `References` headers
   from `in_reply_to_folder` (default INBOX).
2. Set `In-Reply-To: <fetched-message-id>`.
3. Set `References: <fetched-references> <fetched-message-id>` (appending
   per RFC 5322 §3.6.4).
4. If the fetch fails (message deleted, folder inaccessible), return
   `ERR_INVALID_PARAMS` with detail explaining the referenced message
   was not found. Do not silently drop threading.

### 4.4 Message construction

```rust
let msg = MessageBuilder::new()
    .from(config.email_address())
    .to(input.to)
    .cc(input.cc)
    .bcc(input.bcc)
    .subject(&input.subject)
    .in_reply_to(referenced_message_id)
    .references(references_chain)
    .text_body(&input.body_text)
    .write_to_vec()?;
```

- `Message-ID` auto-generated by `mail-builder` (uses hostname via
  `gethostname`).
- `Date` auto-generated.
- Body is plain text only — no HTML composition in v1.

### 4.5 IMAP APPEND

```rust
let result = imap.append_message(
    &config.drafts_folder(),  // default "Drafts"
    &msg,
    &[Flag::Draft],
    &["$PendingReview"],
).await?;
```

- `\Draft` flag marks it as a draft.
- `$PendingReview` keyword is the safety signal — agents and humans can
  filter on this to find AI-created drafts awaiting review before manual
  send.
- Drafts folder name from config (default `"Drafts"`; Gmail uses
  `"[Gmail]/Drafts"`, configurable).

### 4.6 Rate limiting

`create_draft` has its own rate limit bucket separate from the global one:

- Config: `limits.drafts_per_minute` (default 5/min).
- Enforced by the existing `RateLimiter` in `rimap-authz` which already
  has a draft-specific bucket.
- Exceeding the limit returns `ERR_RATE_LIMITED` with `retry_after_ms`.

### 4.7 Response

```json
{
  "meta": {
    "folder": "Drafts",
    "uid": 12345,
    "message_id": "<generated-id@hostname>",
    "keywords": ["$PendingReview"]
  }
}
```

- No `untrusted` block — the server constructed this content, it is
  trusted.
- No `security_warnings` — no adversarial input to scan.
- `uid` is `null` if server lacks UIDPLUS.

### 4.8 Audit

- `ToolStart` logs: recipient addresses (redacted per config policy),
  subject (redacted per config policy), `in_reply_to_uid` if present.
  Body is NOT logged (too large; the draft is retrievable from the
  mailbox).
- `ToolEnd` logs: assigned UID and `message_id`.

### 4.9 Testing (Phase 2c)

- Unit test: construct a draft with threading headers, round-trip the raw
  RFC 5322 bytes through `mail-parser`, verify expected headers present.
- Unit test: `in_reply_to_uid` pointing to non-existent message returns
  `ERR_INVALID_PARAMS`.
- Unit test: rate limit enforcement — 6th draft in one minute returns
  `ERR_RATE_LIMITED`.
- Integration test (Dovecot): create draft → IMAP SELECT Drafts → verify
  message exists with `\Draft` flag and `$PendingReview` keyword, verify
  threading headers when `in_reply_to_uid` was provided.

## 5. Phase 2d — End-to-End Tests, Documentation, Cleanup

### 5.1 End-to-end smoke test (Dovecot)

File: `tests/e2e_dovecot.rs` (or `crates/rimap-server/tests/e2e.rs`)

A single scripted session against the Dovecot container harness:

1. Start MCP server, authenticate to Dovecot.
2. `list_folders` — verify INBOX and Drafts present.
3. Seed a test message via IMAP APPEND (with attachment).
4. `search` — search by From, verify hit.
5. `fetch_message` — fetch seeded message, verify
   `meta`/`untrusted`/`security_warnings` structure.
6. `list_attachments` — verify attachment metadata.
7. `download_attachment` — download, verify SHA256 and MIME sniff result.
8. `flag` — flag the message, verify flags updated.
9. `mark_read` — mark read, verify `\Seen` flag.
10. `create_draft` — reply draft with `in_reply_to_uid`, verify threading.
11. Fetch from Drafts — confirm `\Draft`, `$PendingReview`, threading
    headers.
12. `move_message` — move original to a test folder.
13. `mark_unread` — mark unread in new location.

**Audit log assertions:** after the session, read the audit JSONL:
- `ProcessStart` record at the beginning.
- `ToolStart`/`ToolEnd` record pairs for every tool invocation.
- Redacted fields match config policy.
- No `ToolEnd` records with error status.

**Test gating:** behind `RIMAP_REQUIRE_DOCKER=1`. Skipped silently when
no container runtime is available.

**Proton Bridge:** manual validation only. Not automated.

### 5.2 Documentation

All under `docs/`:

| File | Content |
|------|---------|
| `configuration.md` | Config file format, all fields with defaults, env var overrides, credential resolution (keyring, env, file) |
| `postures.md` | Three postures (readonly, draft-safe, full), tool matrix, per-tool overrides, `list_tools` behavior |
| `security-model.md` | Threat model summary, sanitization pipeline, lookalike detection, audit log as forensic record, `$PendingReview` gate |
| `proton-bridge-setup.md` | Bridge install, TLS fingerprint capture walkthrough, config example, known quirks |
| `audit-log.md` | JSONL schema, record types, rotation config, `audit merge` reference, operator notes on file permissions |

These describe existing behavior. Written from the code and specs.

### 5.3 `epvme_runner` integration tests

Address the 44 surviving mutants from Sprint 4b in
`src/bin/epvme_runner.rs`:

- Add integration tests for `collect_eml_files` and `run_dataset` over a
  small fixture directory (2-3 `.eml` files).
- Verify correct output format, error handling on missing directory, and
  fixture count reporting.

### 5.4 Mutants rerun

- Run `cargo mutants --package rimap-content --timeout 120`.
- Confirm library kill rate ≥ 85% (up from 83.9% after Phase 1).
- Update `docs/superpowers/mutants-survivors.md` with measured numbers.
- If survivors reveal easy kills, add targeted tests.

### 5.5 `v0.1.0` tag

After all sub-phases merge to `main` and CI is green:

1. Tag `v0.1.0` on `main`.
2. Verify binary runs as MCP server against Claude Code / Claude Desktop.

## 6. New Dependencies Summary

| Crate | Version | Sub-phase | Purpose |
|-------|---------|-----------|---------|
| `rmcp` | 1.4 | 2b | MCP server framework (stdio transport, tool macros) |
| `schemars` | 1.0 | 2b | JSON Schema for tool input structs |
| `infer` | 0.19 | 2b | MIME type sniffing for attachment downloads |
| `sha2` | 0.11 | 2b | SHA-256 hashing for attachment downloads |
| `mail-builder` | 0.4 | 2c | RFC 5322 message construction for drafts |

All require `deny.toml` updates. `cargo deny check` must pass before
each sub-phase merges.

## 7. Files Changed (by sub-phase)

### Phase 2a

| File | Changes |
|------|---------|
| `crates/rimap-imap/src/ops/store.rs` | New: STORE flag manipulation |
| `crates/rimap-imap/src/ops/move_msg.rs` | New: MOVE with COPY+DELETE fallback |
| `crates/rimap-imap/src/ops/append.rs` | New: APPEND for drafts |
| `crates/rimap-imap/src/ops/mod.rs` | Wire new modules |
| `crates/rimap-imap/src/types.rs` | `FlagAction`, `MoveResult`, `AppendResult` types |
| `crates/rimap-imap/src/error.rs` | `BatchTooLarge` variant |
| `crates/rimap-server/src/content.rs` | New: `parse_message_async` wrapper |

### Phase 2b

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `rmcp`, `schemars`, `infer`, `sha2` to workspace deps |
| `crates/rimap-server/Cargo.toml` | Add dep references |
| `deny.toml` | Entries for new crates |
| `crates/rimap-server/src/main.rs` | MCP server mode startup/shutdown |
| `crates/rimap-server/src/server.rs` | New: `ImapMcpServer` struct |
| `crates/rimap-server/src/dispatch.rs` | New: dispatch wrapper (authz → breaker → rate limit → audit → execute) |
| `crates/rimap-server/src/tools/mod.rs` | New: tool handler module |
| `crates/rimap-server/src/tools/list_folders.rs` | New |
| `crates/rimap-server/src/tools/search.rs` | New |
| `crates/rimap-server/src/tools/fetch_message.rs` | New |
| `crates/rimap-server/src/tools/list_attachments.rs` | New |
| `crates/rimap-server/src/tools/download_attachment.rs` | New |
| `crates/rimap-server/src/tools/mark_read.rs` | New |
| `crates/rimap-server/src/tools/mark_unread.rs` | New |
| `crates/rimap-server/src/tools/flag.rs` | New |
| `crates/rimap-server/src/tools/unflag.rs` | New |
| `crates/rimap-server/src/tools/move_message.rs` | New |
| `crates/rimap-server/src/download.rs` | New: attachment download sandboxing |

### Phase 2c

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `mail-builder` to workspace deps |
| `crates/rimap-server/Cargo.toml` | Add dep reference |
| `deny.toml` | Entry for `mail-builder`, `gethostname` |
| `crates/rimap-server/src/tools/create_draft.rs` | New: draft construction + threading |

### Phase 2d

| File | Changes |
|------|---------|
| `tests/e2e_dovecot.rs` | New: full-session smoke test |
| `docs/configuration.md` | New |
| `docs/postures.md` | New |
| `docs/security-model.md` | New |
| `docs/proton-bridge-setup.md` | New |
| `docs/audit-log.md` | New |
| `crates/rimap-content/tests/epvme_integration.rs` | New: epvme_runner tests |
| `docs/superpowers/mutants-survivors.md` | Updated numbers |

## 8. Exit Criteria (v0.1.0)

All must be true before tagging:

1. Binary runs as MCP server against Claude Code / Claude Desktop.
2. Every v1 tool works against Proton Bridge (manual validation).
3. Adversarial corpus still green.
4. `just ci` green.
5. Five documentation files published.
6. Library mutant kill rate ≥ 85%.
7. Tag `v0.1.0` on `main`.

## 9. Out of Scope

- Authentication-Results parser (#50 item 2)
- `message/rfc822` recursion (#51 item 1)
- `<style>` block class/id resolution (deferred since 4b)
- Runtime-configurable content limits (deferred since 4b)
- Differential HTML oracle
- cargo-fuzz harnesses
- Proton Bridge automated tests
- HTTP/SSE transport (v3.x)
- Direct SMTP send (v2)
- Multi-account support (v3)
