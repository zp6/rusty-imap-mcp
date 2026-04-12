# Sprint 5 Phase 2c — `create_draft` Tool Handler

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `create_draft` MCP tool handler using `mail-builder` for RFC 5322 message construction, with threading header resolution, `$PendingReview` keyword, and draft-specific rate limiting.

**Architecture:** The handler constructs an RFC 5322 message via `mail-builder`, optionally fetches threading headers from a referenced message, and APPENDs to the Drafts folder with `\Draft` flag and `$PendingReview` keyword. The draft rate limiter (already in `rimap-authz::Governor`) provides a separate bucket from the global rate limit.

**Tech Stack:** `mail-builder 0.4` (RFC 5322 construction), `rimap-imap` APPEND op (from Phase 2a), `rimap-authz::Governor` draft bucket.

**Spec:** [`../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md`](../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md) §4

---

## File Structure

| File | Responsibility |
|------|---------------|
| `Cargo.toml` (root) | Add `mail-builder` to workspace deps |
| `crates/rimap-server/Cargo.toml` | Add dep reference |
| `deny.toml` | Entry for `mail-builder`, `gethostname` if needed |
| `crates/rimap-server/src/tools/create_draft.rs` | `create_draft` handler |
| `crates/rimap-server/src/tools/mod.rs` | Wire module |
| `crates/rimap-server/src/server.rs` | Replace placeholder dispatch |

---

### Task 1: Add `mail-builder` dependency

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/rimap-server/Cargo.toml`

- [ ] **Step 1:** Add to `[workspace.dependencies]` in root Cargo.toml:
```toml
mail-builder = "0.4"
```

- [ ] **Step 2:** Add to `crates/rimap-server/Cargo.toml` under `[dependencies]`:
```toml
mail-builder = { workspace = true }
```

- [ ] **Step 3:** Run `cargo check --package rimap-server && cargo deny check`

- [ ] **Step 4:** Commit:
```bash
git commit -m "chore(server): add mail-builder workspace dependency"
```

---

### Task 2: Implement `create_draft` handler

**Files:**
- Create: `crates/rimap-server/src/tools/create_draft.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

The handler:
1. Parse input (to, cc, bcc, subject, body_text, in_reply_to_uid, in_reply_to_folder)
2. If `in_reply_to_uid` is set, fetch the referenced message's Message-ID and References headers
3. Construct RFC 5322 message via `mail_builder::MessageBuilder`
4. APPEND to Drafts folder with `\Draft` flag and `$PendingReview` keyword
5. Return meta with folder, uid, message_id, keywords

Threading resolution:
- Fetch the referenced message via `server.imap.fetch_body(folder, uid)`
- Parse with `mail_parser` to extract Message-ID and References headers
- Set `In-Reply-To` and `References` on the new message

The "from" address comes from the config — `server.config.config.imap.username` as the email address (or a dedicated `email_address` config field if it exists).

---

### Task 3: Wire dispatch and test

**Files:**
- Modify: `crates/rimap-server/src/server.rs`
- Modify: `crates/rimap-server/src/tools/create_draft.rs` (add tests)

Replace the `CreateDraft` placeholder in `dispatch_tool` with the real handler. Add unit tests:
- Draft construction round-trips through `mail-parser`
- Threading headers are set correctly when `in_reply_to_uid` is provided
- Rate limit enforcement (6th draft in one minute returns error)

---

### Task 4: Run `just ci` and verify

- [ ] Run `just ci`
- [ ] Verify all tests pass
- [ ] Commit any fixups
