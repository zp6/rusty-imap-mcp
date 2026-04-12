# Post-Sprint 5 Issue Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 14 actionable open issues grouped by subsystem, each group as an independent commit on branch `fix/post-sprint5-issues`.

**Architecture:** Issues are grouped into 5 implementation groups ordered by dependency: (A) IMAP protocol safety, (B) server MIME safety, (C) server input validation & schemas, (D) server async safety, (E) audit enhancements. Three issues (#14, #18, #19) are deferred meta-issues for future security-review agents and are not implemented here.

**Tech Stack:** Rust, async-imap, mail_parser, schemars, tokio, fs4, time

**Deferred (not in scope):**
- #14 — threat-model-reviewer agent (post-v1 tooling)
- #18 — SECURITY.md hygiene reviewer (post-v1 tooling)
- #19 — release integrity reviewer (post-v1 tooling)
- #32 — fetch_body backpressure (async-imap 0.11 limitation, no fix path)

---

## Group A: IMAP Protocol Safety (#56, #57)

### Task 1: Add `max_append_bytes` size cap to APPEND (#56)

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs:40-55` (add field to `ConnectionConfig`)
- Modify: `crates/rimap-imap/src/ops/append.rs` (add size check)
- Modify: `crates/rimap-imap/src/error.rs` (reuse `SizeLimit` variant or add context)
- Modify: `crates/rimap-config/src/model.rs` (add `max_append_bytes` to `LimitsConfig`)
- Modify: `crates/rimap-config/src/validate.rs` (validate > 0)
- Modify: `crates/rimap-server/src/bootstrap.rs` or wherever `ConnectionConfig` is built (wire config value)

- [ ] **Step 1: Write the failing test in `ops/append.rs`**

```rust
#[test]
fn append_rejects_oversized_message() {
    // Directly test the size check logic
    let limit: u64 = 100;
    let message = vec![0u8; 200];
    let result = check_append_size(message.len(), limit);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::SizeLimit { .. }));
}

#[test]
fn append_accepts_message_within_limit() {
    let limit: u64 = 200;
    let message = vec![0u8; 100];
    let result = check_append_size(message.len(), limit);
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-imap append_rejects_oversized`
Expected: FAIL — `check_append_size` does not exist

- [ ] **Step 3: Add `max_append_bytes` to `LimitsConfig`**

In `crates/rimap-config/src/model.rs`, add to `LimitsConfig`:
```rust
/// Hard cap on APPEND message size in bytes.
/// Default: 10 MB. Prevents prompt-injection-driven storage exhaustion.
#[serde(default = "default_max_append")]
pub max_append_bytes: u64,
```

Add the default function:
```rust
fn default_max_append() -> u64 {
    10 * 1024 * 1024
}
```

In `validate.rs`, add to `validate_limits()`:
```rust
if cfg.limits.max_append_bytes == 0 {
    return Err(ConfigError::InvalidValue {
        field: "limits.max_append_bytes".into(),
        reason: "must be > 0".into(),
    });
}
```

- [ ] **Step 4: Add `max_append_bytes` field to `ConnectionConfig`**

In `crates/rimap-imap/src/connection.rs`, add to `ConnectionConfig`:
```rust
/// Hard cap on APPEND message size in bytes.
pub max_append_bytes: u64,
```

- [ ] **Step 5: Implement `check_append_size` and wire it into `append()`**

In `crates/rimap-imap/src/ops/append.rs`:
```rust
/// Check that the message does not exceed the configured append size limit.
fn check_append_size(len: usize, limit: u64) -> Result<(), Error> {
    let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
    if len_u64 > limit {
        return Err(Error::SizeLimit { limit });
    }
    Ok(())
}
```

Update the `append()` function signature to accept `max_append_bytes: u64` and call `check_append_size(message.len(), max_append_bytes)?;` at the top.

- [ ] **Step 6: Wire `max_append_bytes` through `Connection::append_message`**

Wherever `Connection::append_message` calls `ops::append::append`, pass `self.inner.cfg.max_append_bytes` as the limit parameter.

Wire the config value into `ConnectionConfig` construction in `rimap-server` bootstrap code.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p rimap-imap append_rejects && cargo test -p rimap-imap append_accepts`
Expected: PASS

- [ ] **Step 8: Run `just ci` and fix any warnings**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-imap/src/ops/append.rs crates/rimap-imap/src/connection.rs \
       crates/rimap-config/src/model.rs crates/rimap-config/src/validate.rs \
       crates/rimap-server/src/
git commit -m "fix(imap): add max_append_bytes size cap to APPEND (#56)"
```

---

### Task 2: Check MOVE capability before UID MOVE (#57)

**Files:**
- Modify: `crates/rimap-imap/src/ops/move_msg.rs` (capability check, remove `Error::No` arm)
- Modify: `crates/rimap-imap/src/connection.rs` (expose capabilities post-login)

The key changes:
1. After login, query `session.capabilities()` and cache whether MOVE is supported.
2. In `move_messages()`, accept a `has_move: bool` parameter.
3. If MOVE absent, go straight to fallback. If present but UID MOVE returns BAD, propagate the error.
4. Remove the `Error::No` arm from `is_move_unsupported`.
5. Return a structured warning when fallback is used.

- [ ] **Step 1: Write failing tests**

In `crates/rimap-imap/src/ops/move_msg.rs` tests:
```rust
#[test]
fn is_move_unsupported_only_matches_bad() {
    // BAD should trigger fallback
    let bad = async_imap::error::Error::Bad("unknown command".to_string());
    assert!(is_move_unsupported(&bad));

    // NO should NOT trigger fallback (server has MOVE but rejected it)
    let no = async_imap::error::Error::No("unknown command".to_string());
    assert!(!is_move_unsupported(&no));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-imap is_move_unsupported_only`
Expected: FAIL — the `Error::No` arm currently returns `true`

- [ ] **Step 3: Fix `is_move_unsupported` to only match `Error::Bad`**

In `crates/rimap-imap/src/ops/move_msg.rs`, replace the function:
```rust
fn is_move_unsupported(err: &async_imap::error::Error) -> bool {
    match err {
        async_imap::error::Error::Bad(_) => true,
        // async_imap::error::Error is #[non_exhaustive], so the
        // wildcard is required.
        _ => false,
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rimap-imap is_move_unsupported_only`
Expected: PASS

- [ ] **Step 5: Add `has_move_capability` parameter to `move_messages`**

Update `move_messages` signature:
```rust
pub async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_move: bool,
) -> Result<(Vec<MoveResult>, bool), Error> {
```

The `bool` return indicates whether the non-atomic fallback was used.

When `has_move` is `false`, skip UID MOVE and go directly to `copy_delete_fallback`. When `has_move` is `true` and UID MOVE returns BAD, propagate the error (don't fall back — the server is misbehaving).

- [ ] **Step 6: Expose capability check on `Connection`**

In `connection.rs`, after successful login, call `session.capabilities()` to check for MOVE. Store the result in `ConnectionInner` (add a `has_move: std::sync::atomic::AtomicBool` field or similar). Expose via `Connection::has_move_capability(&self) -> bool`.

- [ ] **Step 7: Wire through `Connection::move_messages` and the server layer**

Update `Connection::move_messages` to pass `self.has_move_capability()` to `ops::move_msg::move_messages`.

Update `crates/rimap-server/src/tools/move_message.rs` to include a `security_warning` when fallback is used:
```rust
if used_fallback {
    response.security_warnings.push(serde_json::json!({
        "type": "non_atomic_move",
        "message": "server lacks MOVE capability; used non-atomic COPY+DELETE fallback"
    }));
}
```

- [ ] **Step 8: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-imap/src/ops/move_msg.rs crates/rimap-imap/src/connection.rs \
       crates/rimap-server/src/tools/move_message.rs
git commit -m "fix(imap): check MOVE capability before UID MOVE (#57)"
```

---

## Group B: Server MIME Safety (#60, #62, #63)

### Task 3: Add recursion depth limit to MIME tree walkers (#60)

**Files:**
- Modify: `crates/rimap-server/src/tools/list_attachments.rs` (add `depth` param to `collect_attachments`)
- Modify: `crates/rimap-server/src/tools/download_attachment.rs` (add `depth` param to `walk_parts`)

- [ ] **Step 1: Write failing tests for `list_attachments` depth limit**

In `crates/rimap-server/src/tools/list_attachments.rs` tests:
```rust
/// Maximum recursion depth for MIME tree walking.
const MAX_MIME_DEPTH: u32 = 64;

#[test]
fn deeply_nested_mime_respects_depth_limit() {
    // Build a structure nested deeper than MAX_MIME_DEPTH.
    let mut bs = single("application", "pdf", 100);
    for _ in 0..70 {
        bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![bs],
        };
    }
    let mut out = Vec::new();
    collect_attachments(&bs, &mut String::new(), &mut out, 0);
    // The deep attachment should NOT be found (depth exceeded).
    assert!(out.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server deeply_nested_mime`
Expected: FAIL — `collect_attachments` doesn't accept a depth parameter (compile error)

- [ ] **Step 3: Add depth parameter to `collect_attachments`**

```rust
/// Maximum recursion depth for MIME tree walking (DoS guard).
const MAX_MIME_DEPTH: u32 = 64;

fn collect_attachments(
    bs: &BodyStructure,
    prefix: &mut String,
    out: &mut Vec<AttachmentInfo>,
    depth: u32,
) {
    if depth > MAX_MIME_DEPTH {
        return;
    }
    match bs {
        BodyStructure::Single { .. } => { /* unchanged */ }
        BodyStructure::Multipart { parts, .. } => {
            for (i, part) in parts.iter().enumerate() {
                let idx = i + 1;
                let child_prefix = if prefix.is_empty() {
                    idx.to_string()
                } else {
                    format!("{prefix}.{idx}")
                };
                let mut child = child_prefix;
                collect_attachments(part, &mut child, out, depth + 1);
            }
        }
        BodyStructure::Message { body, .. } => {
            let part_id = if prefix.is_empty() {
                "1".to_string()
            } else {
                prefix.clone()
            };
            collect_attachments(body, &mut part_id.clone(), out, depth + 1);
        }
    }
}
```

Update the call site in `handle()`:
```rust
collect_attachments(&bodystructure, &mut String::new(), &mut attachments, 0);
```

Update all existing test calls to pass `0` as the depth argument.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rimap-server list_attachments`
Expected: PASS (all existing + new depth test)

- [ ] **Step 5: Write failing test for `download_attachment` depth limit**

In `crates/rimap-server/src/tools/download_attachment.rs`, add a test module and test:
```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const MAX_MIME_DEPTH: u32 = 64;

    #[test]
    fn walk_parts_respects_depth_limit() {
        // Build a message with mail_parser won't help here since
        // we test the function directly. Instead, test that
        // walk_parts with depth > MAX_MIME_DEPTH returns empty.
        // This is a structural guarantee test.
        //
        // The depth check is in walk_parts; we verify it returns
        // early by calling with depth already at the limit.
        let raw = b"From: a@b\r\nContent-Type: text/plain\r\n\r\nHi\r\n";
        let msg = mail_parser::MessageParser::new().parse(raw).unwrap();
        let mut out = Vec::new();
        // Start at depth = MAX_MIME_DEPTH + 1 to verify early return.
        walk_parts(&msg, 0, "", &mut out, MAX_MIME_DEPTH + 1).unwrap();
        assert!(out.is_empty());
    }
}
```

- [ ] **Step 6: Add depth parameter to `walk_parts` and `compute_part_ids`**

```rust
const MAX_MIME_DEPTH: u32 = 64;

fn compute_part_ids(
    msg: &mail_parser::Message<'_>,
) -> Result<Vec<(usize, String)>, rimap_core::RimapError> {
    let mut result = Vec::new();
    let root = msg.parts.first().ok_or_else(|| {
        rimap_core::RimapError::Internal("message has no parts".into())
    })?;
    if root.is_multipart() {
        walk_parts(msg, 0, "", &mut result, 0)?;
    } else {
        result.push((0, "1".to_string()));
    }
    Ok(result)
}

fn walk_parts(
    msg: &mail_parser::Message<'_>,
    part_idx: usize,
    prefix: &str,
    out: &mut Vec<(usize, String)>,
    depth: u32,
) -> Result<(), rimap_core::RimapError> {
    if depth > MAX_MIME_DEPTH {
        return Ok(());
    }
    // ... rest unchanged except recursive calls pass depth + 1
}
```

- [ ] **Step 7: Run all tests**

Run: `cargo test -p rimap-server`
Expected: PASS

- [ ] **Step 8: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-server/src/tools/list_attachments.rs \
       crates/rimap-server/src/tools/download_attachment.rs
git commit -m "fix(server): add recursion depth limit to MIME tree walkers (#60)"
```

---

### Task 4: Unify MIME tree walking to single parser (#62)

**Files:**
- Modify: `crates/rimap-server/src/tools/download_attachment.rs` (add cross-validation)

Issue #62 identifies a parser differential risk: `list_attachments` walks IMAP BODYSTRUCTURE while `download_attachment` re-parses with `mail_parser`. Full unification would require rearchitecting both tools to use the same parser, which is a larger refactor. The pragmatic fix per the acceptance criteria's "OR" clause is to add a cross-validation step that compares the declared content-type from BODYSTRUCTURE against the actual content-type from `mail_parser`.

- [ ] **Step 1: Write failing test for content-type cross-validation**

In `download_attachment.rs` tests:
```rust
#[test]
fn cross_validate_catches_type_mismatch() {
    let declared = "image/png";
    let actual = "text/html";
    let warnings = cross_validate_mime_type(declared, actual);
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].to_string().contains("mime_type_mismatch"),
    );
}

#[test]
fn cross_validate_passes_on_match() {
    let warnings = cross_validate_mime_type("image/png", "image/png");
    assert!(warnings.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server cross_validate`
Expected: FAIL — function doesn't exist

- [ ] **Step 3: Implement cross-validation helper**

```rust
/// Compare declared MIME type (from BODYSTRUCTURE) against actual
/// type (from mail_parser). Returns security warnings on mismatch.
fn cross_validate_mime_type(
    declared: &str,
    actual: &str,
) -> Vec<serde_json::Value> {
    if declared.eq_ignore_ascii_case(actual) {
        return Vec::new();
    }
    vec![serde_json::json!({
        "type": "mime_type_mismatch",
        "declared": declared,
        "actual": actual,
        "message": "BODYSTRUCTURE type disagrees with parsed content type"
    })]
}
```

This function is called from `handle()` but requires fetching BODYSTRUCTURE alongside the body. Since the current `handle()` only fetches the body, we need to also fetch BODYSTRUCTURE for the target message and look up the part's declared type. If the BODYSTRUCTURE fetch fails or the part isn't found, skip validation (defense-in-depth, not blocking).

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server cross_validate`
Expected: PASS

- [ ] **Step 5: Wire cross-validation into `handle()`**

In `handle()`, after `find_part_by_id` returns `declared_type`, optionally fetch BODYSTRUCTURE and look up the part's declared type from the IMAP side. Compare and add any warnings to the response's `security_warnings`.

This is best-effort: if BODYSTRUCTURE lookup fails, proceed without the warning.

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/tools/download_attachment.rs
git commit -m "fix(server): add MIME type cross-validation in download_attachment (#62)"
```

---

### Task 5: Emit MIME type mismatch security warning (#63)

**Files:**
- Modify: `crates/rimap-server/src/tools/download_attachment.rs:79-94` (add warning when sniffed != declared)

- [ ] **Step 1: Write failing test**

In `download_attachment.rs` tests:
```rust
#[test]
fn sniff_mismatch_produces_warning() {
    let declared = "text/plain";
    let sniffed = Some("image/png".to_string());
    let warnings = check_sniff_mismatch(declared, sniffed.as_deref());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].to_string().contains("mime_sniff_mismatch"));
}

#[test]
fn sniff_match_produces_no_warning() {
    let warnings = check_sniff_mismatch(
        "image/png",
        Some("image/png").as_deref(),
    );
    assert!(warnings.is_empty());
}

#[test]
fn sniff_none_produces_no_warning() {
    let warnings = check_sniff_mismatch("text/plain", None);
    assert!(warnings.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server sniff_mismatch`
Expected: FAIL — function doesn't exist

- [ ] **Step 3: Implement the sniff mismatch check**

```rust
/// Compare declared MIME type against magic-bytes-sniffed type.
/// Returns a security warning when they disagree.
fn check_sniff_mismatch(
    declared: &str,
    sniffed: Option<&str>,
) -> Vec<serde_json::Value> {
    let Some(sniffed) = sniffed else {
        return Vec::new();
    };
    if declared.eq_ignore_ascii_case(sniffed) {
        return Vec::new();
    }
    vec![serde_json::json!({
        "type": "mime_sniff_mismatch",
        "mime_declared": declared,
        "mime_sniffed": sniffed,
        "message": "declared MIME type disagrees with magic-byte detection"
    })]
}
```

- [ ] **Step 4: Wire into `handle()`**

In `handle()`, after computing `mime_sniffed`, call:
```rust
let mut warnings = check_sniff_mismatch(&declared_type, mime_sniffed.as_deref());
```

Then set `security_warnings: warnings` in the response instead of `Vec::new()`.

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-server sniff_mismatch && cargo test -p rimap-server download_attachment`
Expected: PASS

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/tools/download_attachment.rs
git commit -m "fix(server): emit MIME type mismatch security warning (#63)"
```

---

## Group C: Server Input Validation & Schemas (#59, #64, #65)

### Task 6: Add input schemas to tool definitions (#59)

**Files:**
- Modify: `crates/rimap-server/src/server.rs:156-183` (use `schemars::schema_for!`)
- Modify: `crates/rimap-server/src/tools/create_draft.rs` (add `JsonSchema` derive)
- Modify: `crates/rimap-server/src/tools/flags.rs` (add `JsonSchema` derive)
- Modify: `crates/rimap-server/src/tools/move_message.rs` (add `JsonSchema` derive)
- Modify: `crates/rimap-server/Cargo.toml` (ensure `schemars` dependency)

Currently `tool_definition()` creates tools with `Arc::new(serde_json::Map::new())` (empty schema). Input structs for some tools already derive `JsonSchema` but it's not wired in. The fix: generate schemas from each tool's input struct and use them.

- [ ] **Step 1: Write a failing test that schemas are non-empty**

In `crates/rimap-server/src/server.rs` tests:
```rust
#[test]
fn tool_definitions_have_non_empty_schemas() {
    for def in ToolName::all().into_iter().filter_map(tool_definition) {
        let schema = &def.input_schema;
        assert!(
            !schema.is_empty(),
            "tool {} has empty input schema",
            def.name,
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server tool_definitions_have_non_empty`
Expected: FAIL — all schemas are empty

- [ ] **Step 3: Add `JsonSchema` derive to all input structs missing it**

Add `use schemars::JsonSchema;` and `#[derive(JsonSchema)]` to:
- `crates/rimap-server/src/tools/create_draft.rs`: `CreateDraftInput`, `AddressInput`
- `crates/rimap-server/src/tools/flags.rs`: `FlagInput`
- `crates/rimap-server/src/tools/move_message.rs`: `MoveInput`

(`ListAttachmentsInput`, `DownloadAttachmentInput`, `SearchInput`, `FetchMessageInput` already have it.)

`list_folders` has no input struct (takes no arguments) — use an empty object schema for it.

- [ ] **Step 4: Update `tool_definition` to generate schemas**

Replace the function body to return schemas per tool:

```rust
use schemars::schema_for;

fn tool_definition(name: ToolName) -> Option<Tool> {
    let (tool_name, description, schema) = match name {
        ToolName::ListFolders => (
            "list_folders",
            "List all IMAP folders",
            serde_json::Map::new(),
        ),
        ToolName::Search => (
            "search",
            "Search messages with structured query",
            schema_map::<crate::tools::search::SearchInput>(),
        ),
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
        ToolName::FetchMessage => (
            "fetch_message",
            "Fetch message metadata and text body",
            schema_map::<crate::tools::fetch_message::FetchMessageInput>(),
        ),
        ToolName::ListAttachments => (
            "list_attachments",
            "List attachments on a message",
            schema_map::<crate::tools::list_attachments::ListAttachmentsInput>(),
        ),
        ToolName::DownloadAttachment => (
            "download_attachment",
            "Download an attachment to the sandbox directory",
            schema_map::<crate::tools::download_attachment::DownloadAttachmentInput>(),
        ),
        ToolName::MarkRead => (
            "mark_read",
            "Mark messages as read",
            schema_map::<crate::tools::flags::FlagInput>(),
        ),
        ToolName::MarkUnread => (
            "mark_unread",
            "Mark messages as unread",
            schema_map::<crate::tools::flags::FlagInput>(),
        ),
        ToolName::Flag => (
            "flag",
            "Add the flagged flag to messages",
            schema_map::<crate::tools::flags::FlagInput>(),
        ),
        ToolName::Unflag => (
            "unflag",
            "Remove the flagged flag from messages",
            schema_map::<crate::tools::flags::FlagInput>(),
        ),
        ToolName::MoveMessage => (
            "move_message",
            "Move messages to another folder",
            schema_map::<crate::tools::move_message::MoveInput>(),
        ),
        ToolName::CreateDraft => (
            "create_draft",
            "Create a draft email with $PendingReview flag",
            schema_map::<crate::tools::create_draft::CreateDraftInput>(),
        ),
    };

    Some(Tool::new(tool_name, description, Arc::new(schema)))
}

/// Convert a `schemars` root schema into the `serde_json::Map`
/// expected by rmcp's `Tool::new`.
fn schema_map<T: schemars::JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-server tool_definition`
Expected: PASS (all 4 tests including the new non-empty schema test)

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/server.rs crates/rimap-server/src/tools/
git commit -m "feat(server): add input schemas to tool definitions (#59)"
```

---

### Task 7: Cap References chain length in `create_draft` (#64)

**Files:**
- Modify: `crates/rimap-server/src/tools/create_draft.rs:246-265` (truncate References)

- [ ] **Step 1: Write failing test**

In `create_draft.rs` tests:
```rust
#[test]
fn references_chain_capped_at_50() {
    let refs: Vec<String> = (0..200)
        .map(|i| format!("msg-{i}@example.com"))
        .collect();
    let capped = cap_references(refs);
    assert_eq!(capped.len(), 50);
    // First entry is always the root (oldest).
    assert_eq!(capped[0], "msg-0@example.com");
    // Last entry is always the most recent.
    assert_eq!(capped[49], "msg-199@example.com");
}

#[test]
fn references_chain_under_cap_unchanged() {
    let refs: Vec<String> = (0..10)
        .map(|i| format!("msg-{i}@example.com"))
        .collect();
    let capped = cap_references(refs);
    assert_eq!(capped.len(), 10);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server references_chain_capped`
Expected: FAIL — `cap_references` does not exist

- [ ] **Step 3: Implement `cap_references`**

```rust
/// Maximum References chain length. Keeps root + most recent entries.
const MAX_REFERENCES: usize = 50;

/// Truncate a References chain to at most `MAX_REFERENCES` entries,
/// preserving the root (first) and most recent (last) entries.
fn cap_references(mut refs: Vec<String>) -> Vec<String> {
    if refs.len() <= MAX_REFERENCES {
        return refs;
    }
    // Keep the root entry + the (MAX_REFERENCES - 1) most recent.
    let root = refs.remove(0);
    let keep_recent = MAX_REFERENCES - 1;
    let start = refs.len().saturating_sub(keep_recent);
    let mut result = Vec::with_capacity(MAX_REFERENCES);
    result.push(root);
    result.extend(refs.into_iter().skip(start));
    result
}
```

- [ ] **Step 4: Wire into `apply_threading_headers`**

After building `ref_ids` and before passing to `builder.references()`:
```rust
let ref_ids = cap_references(ref_ids);
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-server references_chain && cargo test -p rimap-server create_draft`
Expected: PASS

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/tools/create_draft.rs
git commit -m "fix(server): cap References chain length to 50 in create_draft (#64)"
```

---

### Task 8: Add input length bounds to `create_draft` (#65)

**Files:**
- Modify: `crates/rimap-server/src/tools/create_draft.rs:110-137` (add length checks to `validate_draft_input`)

- [ ] **Step 1: Write failing tests**

In `create_draft.rs` tests:
```rust
#[test]
fn too_many_recipients_rejected() {
    let addrs: Vec<AddressInput> = (0..101)
        .map(|i| AddressInput {
            name: None,
            address: format!("user{i}@example.com"),
        })
        .collect();
    let input = make_input(addrs);
    let err = validate_draft_input(&input).unwrap_err();
    assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
}

#[test]
fn subject_too_long_rejected() {
    let mut input = make_input(vec![AddressInput {
        name: None,
        address: "ok@example.com".into(),
    }]);
    input.subject = "x".repeat(1001);
    let err = validate_draft_input(&input).unwrap_err();
    assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
}

#[test]
fn body_too_large_rejected() {
    let mut input = make_input(vec![AddressInput {
        name: None,
        address: "ok@example.com".into(),
    }]);
    input.body_text = "x".repeat(1_048_577); // 1 MB + 1
    let err = validate_draft_input(&input).unwrap_err();
    assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
}
```

- [ ] **Step 2: Run test to verify they fail**

Run: `cargo test -p rimap-server too_many_recipients && cargo test -p rimap-server subject_too_long && cargo test -p rimap-server body_too_large`
Expected: FAIL — no length checks exist

- [ ] **Step 3: Add length bounds to `validate_draft_input`**

Add constants:
```rust
/// Max combined recipients (to + cc + bcc).
const MAX_RECIPIENTS: usize = 100;
/// Max subject length in characters.
const MAX_SUBJECT_LEN: usize = 1000;
/// Max body_text length in bytes (1 MB).
const MAX_BODY_BYTES: usize = 1_048_576;
```

Add checks in `validate_draft_input` after the empty-to check:
```rust
let total_recipients = input.to.len()
    + input.cc.as_ref().map_or(0, Vec::len)
    + input.bcc.as_ref().map_or(0, Vec::len);
if total_recipients > MAX_RECIPIENTS {
    return Err(rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::InvalidInput,
        message: format!(
            "too many recipients ({total_recipients}); max is {MAX_RECIPIENTS}"
        ),
    });
}

if input.subject.len() > MAX_SUBJECT_LEN {
    return Err(rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::InvalidInput,
        message: format!(
            "subject too long ({} chars); max is {MAX_SUBJECT_LEN}",
            input.subject.len()
        ),
    });
}

if input.body_text.len() > MAX_BODY_BYTES {
    return Err(rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::InvalidInput,
        message: format!(
            "body_text too large ({} bytes); max is {MAX_BODY_BYTES}",
            input.body_text.len()
        ),
    });
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server create_draft`
Expected: PASS (all existing + 3 new tests)

- [ ] **Step 5: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/create_draft.rs
git commit -m "fix(server): add input length bounds to create_draft (#65)"
```

---

## Group D: Server Async Safety (#58, #61)

### Task 9: Wrap blocking filesystem I/O in `spawn_blocking` (#61)

**Files:**
- Modify: `crates/rimap-server/src/download.rs` (wrap `write_attachment`, `resolve_dest_dir`)
- Modify: `crates/rimap-server/src/tools/download_attachment.rs` (wrap `mail_parser` parsing, use async versions)

- [ ] **Step 1: Create async wrappers for blocking operations**

In `download.rs`, create async versions:
```rust
/// Async wrapper for `resolve_dest_dir` — runs on the blocking
/// threadpool to avoid stalling the Tokio runtime on slow filesystems.
pub async fn resolve_dest_dir_async(
    dest_dir: Option<String>,
    allowed_root: PathBuf,
    fallback_dir: PathBuf,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || {
        resolve_dest_dir(dest_dir.as_deref(), &allowed_root, &fallback_dir)
    })
    .await
    .unwrap_or_else(|e| {
        Err(RimapError::Internal(format!(
            "spawn_blocking panicked: {e}"
        )))
    })
}

/// Async wrapper for `write_attachment`.
pub async fn write_attachment_async(
    dir: PathBuf,
    filename: String,
    data: Vec<u8>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || {
        write_attachment(&dir, &filename, &data)
    })
    .await
    .unwrap_or_else(|e| {
        Err(RimapError::Internal(format!(
            "spawn_blocking panicked: {e}"
        )))
    })
}
```

- [ ] **Step 2: Update `download_attachment::handle` to use async wrappers**

Replace sync calls with async versions:
```rust
let dest = download::resolve_dest_dir_async(
    input.dest_dir,
    server.download_dir.clone(),
    server.download_dir.clone(),
).await?;
```

Wrap `mail_parser` parsing in `spawn_blocking`:
```rust
let parsed = tokio::task::spawn_blocking(move || {
    mail_parser::MessageParser::new().parse(&raw)
        .ok_or_else(|| {
            rimap_core::RimapError::Internal(
                "failed to parse message for attachment extraction".into(),
            )
        })
        .map(|m| m.into_owned())
}).await.unwrap_or_else(|e| {
    Err(rimap_core::RimapError::Internal(
        format!("spawn_blocking panicked: {e}"),
    ))
})?;
```

Replace `write_attachment` call:
```rust
let path = download::write_attachment_async(
    dest,
    safe_filename.to_string(),
    part_body.clone(),
).await?;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-server download`
Expected: PASS

- [ ] **Step 4: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/download.rs \
       crates/rimap-server/src/tools/download_attachment.rs
git commit -m "fix(server): wrap blocking filesystem I/O in spawn_blocking (#61)"
```

---

### Task 10: Bound concurrent `spawn_blocking` parse invocations (#58)

**Files:**
- Modify: `crates/rimap-server/src/content.rs` (add semaphore)
- Modify: `crates/rimap-server/src/server.rs` or module-level (own the semaphore)

- [ ] **Step 1: Write failing test**

In `content.rs` tests:
```rust
#[tokio::test]
async fn concurrent_parses_are_bounded() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Semaphore;

    let semaphore = Arc::new(Semaphore::new(4));
    let concurrent = Arc::new(AtomicU32::new(0));
    let max_concurrent = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..20 {
        let sem = semaphore.clone();
        let conc = concurrent.clone();
        let max_c = max_concurrent.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let val = conc.fetch_add(1, Ordering::SeqCst) + 1;
            max_c.fetch_max(val, Ordering::SeqCst);
            tokio::task::yield_now().await;
            conc.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert!(max_concurrent.load(Ordering::SeqCst) <= 4);
}
```

- [ ] **Step 2: Add semaphore to `parse_message_async`**

In `content.rs`:
```rust
use std::sync::LazyLock;
use tokio::sync::Semaphore;

/// Limits concurrent CPU-bound parse operations to avoid exhausting
/// the blocking threadpool (Tokio default: 512 threads).
static PARSE_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(8));

pub async fn parse_message_async(raw: Vec<u8>) -> Result<Content, ContentError> {
    let _permit = PARSE_SEMAPHORE.acquire().await.map_err(|_| {
        ContentError::Malformed {
            reason: "parse semaphore closed".into(),
        }
    })?;
    tokio::task::spawn_blocking(move || parse_message(&raw))
        .await
        .unwrap_or_else(|e| {
            Err(ContentError::Malformed {
                reason: format!("spawn_blocking panicked: {e}"),
            })
        })
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-server content`
Expected: PASS

- [ ] **Step 4: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/content.rs
git commit -m "fix(server): bound concurrent spawn_blocking parse invocations (#58)"
```

---

## Group E: Audit Enhancements (#44, #45, #8)

### Task 11: Implement time-based retention alongside `rotate_keep` (#44)

**Files:**
- Modify: `crates/rimap-config/src/model.rs` (add `retention_seconds` to `AuditConfig`)
- Modify: `crates/rimap-config/src/validate.rs` (validate non-zero if Some)
- Modify: `crates/rimap-audit/src/rotation.rs` (mtime check in `prune_rotated_siblings`)

- [ ] **Step 1: Write failing test for mtime-based pruning**

In `crates/rimap-audit/src/rotation.rs` tests:
```rust
#[test]
fn prune_respects_retention_seconds() {
    let dir = TempDir::new().unwrap();
    let active = dir.path().join("audit.jsonl");

    // Create rotated siblings with old mtime.
    std::fs::write(&active, b"x\n").unwrap();
    let (_buf, _len) = rotate_file(&active, 10, None).unwrap();
    sleep(Duration::from_millis(5));

    // Make the rotated sibling "old" by setting retention to 0 seconds
    // (prune everything older than now).
    std::fs::write(&active, b"y\n").unwrap();
    let (_buf, _len) = rotate_file(&active, 10, Some(0)).unwrap();

    let rotated = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("audit.jsonl."))
        })
        .count();
    // retention_seconds=0 means delete everything older than now,
    // which is all rotated siblings.
    assert_eq!(rotated, 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-audit prune_respects_retention`
Expected: FAIL — `rotate_file` doesn't accept retention parameter

- [ ] **Step 3: Add `retention_seconds` to `AuditConfig`**

In `model.rs`:
```rust
/// Time-based retention cutoff in seconds. Rotated files older than
/// this are deleted regardless of `rotate_keep`. `None` = no
/// time-based expiry (count-only, today's behavior).
#[serde(default)]
pub retention_seconds: Option<u64>,
```

In `validate.rs`, add:
```rust
if let Some(0) = cfg.audit.retention_seconds {
    return Err(ConfigError::InvalidValue {
        field: "audit.retention_seconds".into(),
        reason: "must be > 0 or absent".into(),
    });
}
```

Wait — the issue says `retention_seconds = 0` should be treated as None or rejected. Let's reject it at validation. But the test uses `Some(0)` internally in the rotation code as "delete everything" for testing purposes. The config validation rejects 0 from user config, but the rotation function can still receive any value internally.

Actually, re-reading the test: I should pass retention as a `Duration` or `Option<u64>` to `prune_rotated_siblings` directly in the test, not through config validation. The config validation rejects 0 from user input. The rotation function itself just uses the value.

- [ ] **Step 4: Add retention parameter to `rotate_file` and `prune_rotated_siblings`**

Update signatures:
```rust
pub fn rotate_file(
    active: &Path,
    keep: u32,
    retention_seconds: Option<u64>,
) -> Result<(BufWriter<File>, u64), AuditError> {
    // ... existing code ...
    prune_rotated_siblings(active, keep, retention_seconds);
    Ok((BufWriter::new(new_file), 0))
}
```

Update `prune_rotated_siblings`:
```rust
fn prune_rotated_siblings(active: &Path, keep: u32, retention_seconds: Option<u64>) {
    // ... existing enumeration and sorting ...

    let keep_usize = usize::try_from(keep).unwrap_or(usize::MAX);

    // Two independent filters AND together:
    // 1. Count-based: keep only the `keep` newest
    // 2. Time-based: delete anything older than retention_seconds
    let now = std::time::SystemTime::now();
    let cutoff = retention_seconds.map(|secs| {
        now.checked_sub(std::time::Duration::from_secs(secs))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    for (i, (mtime, path)) in siblings.into_iter().enumerate() {
        let beyond_count = i >= keep_usize;
        let beyond_age = cutoff.is_some_and(|c| mtime < c);
        if beyond_count || beyond_age {
            if let Err(err) = std::fs::remove_file(&path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "audit rotate: failed to delete stale rotated sibling",
                );
            }
        }
    }
}
```

Update all existing callers of `rotate_file` and `prune_rotated_siblings` to pass the retention parameter (existing callers pass `None`).

- [ ] **Step 5: Update existing tests**

All existing `rotate_file` test calls get a `None` third parameter:
```rust
let (_buf, _len) = rotate_file(&active, 3, None).unwrap();
```

- [ ] **Step 6: Wire through `AuditWriter` and `AuditOptions`**

Add `retention_seconds: Option<u64>` to `AuditOptions`. Pass it through to `rotate_file` calls in `writer.rs`.

Wire from `rimap-server` bootstrap: read `config.audit.retention_seconds` and pass to `AuditOptions`.

- [ ] **Step 7: Run tests**

Run: `cargo test -p rimap-audit rotation && cargo test -p rimap-config validate`
Expected: PASS

- [ ] **Step 8: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-config/src/model.rs crates/rimap-config/src/validate.rs \
       crates/rimap-audit/src/rotation.rs crates/rimap-audit/src/writer.rs \
       crates/rimap-server/src/
git commit -m "feat(audit): implement time-based retention alongside rotate_keep (#44)"
```

---

### Task 12: Exclude audit directory from macOS backups (#45)

**Files:**
- Create: `crates/rimap-audit/src/backup_exclude.rs`
- Modify: `crates/rimap-audit/src/lib.rs` (add module)

- [ ] **Step 1: Write the module with platform-gated implementation**

Create `crates/rimap-audit/src/backup_exclude.rs`:

```rust
//! Exclude audit directories from macOS Time Machine backups.
//!
//! On macOS, sets `com.apple.metadata:com_apple_backup_excludeItem`
//! xattr on the given path. No-op on other platforms.

use std::path::Path;

/// Exclude `path` from Time Machine backups (macOS only).
/// Best-effort: logs a warning on failure but never propagates errors.
pub fn exclude_from_backup(path: &Path) {
    #[cfg(target_os = "macos")]
    exclude_macos(path);

    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

#[cfg(target_os = "macos")]
fn exclude_macos(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Binary plist encoding of boolean `true` — fixed bytes per
    // Apple TN2206. This is the canonical representation used by
    // `tmutil addexclusion -p`.
    static BPLIST_TRUE: &[u8] = &[
        0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x30, // bplist00
        0x09, // bool true
        0x08, // offset table offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, // offset table
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // trailer
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    ];

    let xattr_name = CString::new(
        "com.apple.metadata:com_apple_backup_excludeItem"
    ).expect("static CString");

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "backup_exclude: path contains null byte, skipping",
            );
            return;
        }
    };

    // SAFETY: libc::setxattr with valid CString pointers and known-good
    // buffer length. No memory is borrowed across the call boundary.
    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            xattr_name.as_ptr(),
            BPLIST_TRUE.as_ptr().cast(),
            BPLIST_TRUE.len(),
            0, // position (unused for this xattr)
            0, // options (0 = create or replace)
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "backup_exclude: failed to set Time Machine exclusion xattr",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_from_backup_does_not_panic_on_nonexistent_path() {
        // Should be best-effort; no panic on missing path.
        exclude_from_backup(Path::new("/nonexistent/path/audit"));
    }

    #[test]
    fn exclude_from_backup_is_noop_on_non_macos() {
        // On non-macOS, this is a no-op. Just verify it compiles
        // and doesn't error.
        let tmp = tempfile::tempdir().unwrap();
        exclude_from_backup(tmp.path());
    }
}
```

- [ ] **Step 2: Register module in `lib.rs`**

Add `pub mod backup_exclude;` to `crates/rimap-audit/src/lib.rs`.

- [ ] **Step 3: Add `libc` dependency for macOS**

In workspace `Cargo.toml`, add `libc` to workspace dependencies (if not already present).
In `crates/rimap-audit/Cargo.toml`, add:
```toml
[target.'cfg(target_os = "macos")'.dependencies]
libc = { workspace = true }
```

Note: `unsafe_code` is forbidden workspace-wide. The macOS-only `libc::setxattr` call requires an `unsafe` block. Add `#[cfg_attr(target_os = "macos", expect(unsafe_code, reason = "libc::setxattr for Time Machine exclusion"))]` or allow unsafe for that specific function. Check the workspace lint config — if `unsafe_code = "forbid"` is at workspace level, you'll need to override it for this one module:

```rust
#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "libc::setxattr for Time Machine exclusion")]
fn exclude_macos(path: &Path) { ... }
```

Wait — `forbid` cannot be overridden with `expect`. If the workspace uses `forbid`, this needs discussion. Check if `unsafe_code` is `forbid` or `deny`. If `forbid`, the macOS xattr functionality will need to be implemented via the `xattr` crate (pure safe Rust wrapper) instead of `libc`. Adjust accordingly.

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-audit backup_exclude`
Expected: PASS

- [ ] **Step 5: Wire into server startup**

In `rimap-server` bootstrap (wherever `AuditWriter::open` is called), add after opening:
```rust
if let Some(parent) = audit_path.parent() {
    rimap_audit::backup_exclude::exclude_from_backup(parent);
}
```

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-audit/src/backup_exclude.rs crates/rimap-audit/src/lib.rs \
       crates/rimap-audit/Cargo.toml Cargo.toml crates/rimap-server/src/
git commit -m "feat(audit): exclude audit directory from macOS backups (#45)"
```

---

### Task 13: Server lifecycle glue — `process_start` / `process_end` (#8)

**Files:**
- Create: `crates/rimap-audit/src/lifecycle.rs`
- Modify: `crates/rimap-audit/src/lib.rs` (add module export)
- Modify: `crates/rimap-server/src/main.rs` or bootstrap module

This task wires together the existing building blocks:
- `AuditWriter::open` (lock + create)
- `self_check::read_trailing_state` (previous run's state)
- `self_check::current_inode` (this run's inode)
- `record::ProcessStart` / `ProcessEnd` payloads

- [ ] **Step 1: Write failing test for lifecycle start**

In a new `crates/rimap-audit/src/lifecycle.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_process_writes_process_start_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let ctx = StartContext {
            version: "0.1.0".into(),
            git_commit: Some("abc1234".into()),
            posture: "cautious".into(),
            config_path: "/etc/rimap.toml".into(),
            config_hash: "deadbeef".into(),
        };

        let opts = crate::writer::AuditOptions {
            path: path.clone(),
            rotate_bytes: 10_000_000,
            rotate_keep: 5,
            fail_open: false,
            initial_seq: None,
            retention_seconds: None,
        };

        let (writer, _handle) = start_process(opts, ctx).unwrap();
        drop(writer);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("process_start"));
    }
}
```

- [ ] **Step 2: Implement `lifecycle.rs`**

```rust
//! Process lifecycle audit records.

use crate::error::AuditError;
use crate::writer::{AuditOptions, AuditWriter};

/// Context for constructing a `ProcessStart` record.
pub struct StartContext {
    pub version: String,
    pub git_commit: Option<String>,
    pub posture: String,
    pub config_path: String,
    pub config_hash: String,
}

/// Handle returned by `start_process` for emitting `ProcessEnd`.
pub struct ProcessHandle {
    writer: AuditWriter,
}

impl ProcessHandle {
    /// Emit a best-effort `ProcessEnd` record.
    pub fn end_process(self, total_tool_calls: u64) {
        // Best-effort: log but don't propagate errors.
        let payload = crate::record::Payload::ProcessEnd(
            crate::record::ProcessEnd { total_tool_calls },
        );
        if let Err(e) = self.writer.write_record(&payload) {
            tracing::error!(
                error = %e,
                "failed to write process_end audit record",
            );
        }
    }
}

/// Open the audit writer, run self-check, emit `ProcessStart`.
pub fn start_process(
    opts: AuditOptions,
    ctx: StartContext,
) -> Result<(AuditWriter, ProcessHandle), AuditError> {
    let writer = AuditWriter::open(opts)?;

    // Self-check: read trailing state from previous run.
    let prev = crate::self_check::read_trailing_state(writer.path());
    let current_inode = crate::self_check::current_inode(writer.path());
    let inode_changed = match (&prev, &current_inode) {
        (Ok(Some(state)), Ok(inode)) => {
            state.file_inode != *inode
        }
        _ => false,
    };

    let start = crate::record::ProcessStart {
        version: ctx.version,
        git_commit: ctx.git_commit,
        posture: ctx.posture,
        config_path: ctx.config_path,
        config_hash: ctx.config_hash,
        previous_seq: prev.as_ref().ok().and_then(|s| {
            s.as_ref().map(|s| s.seq)
        }),
        previous_process_id: prev.as_ref().ok().and_then(|s| {
            s.as_ref().map(|s| s.process_id.clone())
        }),
        audit_file_inode_changed: inode_changed,
    };

    let payload = crate::record::Payload::ProcessStart(start);
    writer.write_record(&payload)?;

    let handle = ProcessHandle {
        writer: writer.clone(),
    };

    Ok((writer, handle))
}
```

Note: The exact field names and types for `ProcessStart`, `ProcessEnd`, `TrailingState` etc. depend on the existing `record.rs` and `self_check.rs` definitions. The implementer must read those files and adapt accordingly. The structure above is a guide — match the actual types.

- [ ] **Step 3: Register module**

Add `pub mod lifecycle;` to `crates/rimap-audit/src/lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-audit lifecycle`
Expected: PASS

- [ ] **Step 5: Wire into `rimap-server` main**

In `main.rs` or the bootstrap module, replace direct `AuditWriter::open` with `lifecycle::start_process`. Store the `ProcessHandle` and call `end_process` on shutdown (via a signal handler or Drop guard).

- [ ] **Step 6: Run `just ci`**

Run: `just ci`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-audit/src/lifecycle.rs crates/rimap-audit/src/lib.rs \
       crates/rimap-server/src/
git commit -m "feat(audit): add server lifecycle glue for process_start/process_end (#8)"
```

---

## Summary

| Group | Issues | Commits | Focus |
|-------|--------|---------|-------|
| A | #56, #57 | 2 | IMAP protocol safety |
| B | #60, #62, #63 | 3 | MIME tree safety |
| C | #59, #64, #65 | 3 | Input validation & schemas |
| D | #58, #61 | 2 | Async/blocking safety |
| E | #44, #45, #8 | 3 | Audit enhancements |
| **Total** | **14** | **13** | |

**Not in scope (3 issues):** #14, #18, #19 (security-review agent meta-issues, post-v1), #32 (async-imap design limitation).

**Branch:** `fix/post-sprint5-issues`

**Execution order:** Tasks 1-13 in order. Groups A-B have no cross-dependencies so could be parallelized. Group C depends on A (schemas reference all input types). Group D is independent. Group E is independent but Task 11 must precede Task 12-13 (retention parameter flows through rotation).
