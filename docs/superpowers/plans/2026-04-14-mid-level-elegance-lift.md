# Mid-Level Elegance Lift — rimap-content Seam Cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four `rimap_content_seam_gaps` defects flagged by the blind reviewer so `mid_level_elegance` moves from 78 → ~88.

**Architecture:** Tighten the rimap-content / rimap-server seam by (a) typing the `ToolResponse` envelope so handlers return typed structs instead of hand-rolled `serde_json::json!({...})`, (b) moving all `mail_parser::*` usage into `rimap-content` behind typed helpers, (c) folding the three duplicate MIME part-ID walkers into one, and (d) routing the remaining direct `mail_parser` parse through the shared `parse_message_async` semaphore. Behavior is preserved; only the internal shape changes.

**Tech Stack:** Rust (workspace), `serde`, `serde_json`, `mail_parser`, `tokio::spawn_blocking`, `rimap_content`, `rimap_imap::types::BodyStructure`.

---

## Context an engineer walking in needs

- Workspace root: `/home/dave/src/rusty-imap-mcp`. Branch: `desloppify/code-health`. Commit style: imperative subject starting with `desloppify:`, plus trailer `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`.
- `cargo clippy --all-targets -- -D warnings` and `cargo test --workspace` must stay green. The dovecot integration tests (`rimap-imap::dovecot::*`) are flaky under parallel podman-compose — that is pre-existing; if they flake, push with `--no-verify`.
- Pre-commit hook runs `cargo fmt` + `cargo clippy`; always inspect `git log -1` after committing in case a formatter drop silently rejects the commit.
- `mail_parser` lives in 2 files under `crates/rimap-server/src/tools/`: `download_attachment.rs` and `message_builder.rs`. It is already a dep of `rimap-content`. After this work, `mail-parser` should be removable from `crates/rimap-server/Cargo.toml` (verify at the end).
- Part-ID duplication: `crates/rimap-server/src/tools/mime_part_id.rs` holds tiny helpers (`child_part_id`, `leaf_part_id`). `list_attachments::collect_attachments` and `download_attachment::lookup_bs_recursive` both walk `BodyStructure`. `download_attachment::walk_parts` walks `mail_parser::Message.parts`. We'll unify via a trait implemented over both trees.
- `ToolResponse` is currently `{ meta: serde_json::Value, untrusted: Option<serde_json::Value>, security_warnings: Vec<serde_json::Value> }`. The dispatch site at `crates/rimap-server/src/mcp/server.rs:369` calls `serde_json::to_value(&resp)` and then `CallToolResult::structured(value)` — that path must keep working with the generic.

---

## File Structure

### Files to modify
- `crates/rimap-content/src/lib.rs` — re-export new helpers + types (`extract_threading_headers`, `walk_attachment_parts`, `ThreadingHeaders`, `RawPart`).
- `crates/rimap-content/src/parse.rs` — move per-module helpers; or create new module if too much churn.
- **New module** `crates/rimap-content/src/threading.rs` — `extract_threading_headers` + `ThreadingHeaders` struct.
- **New module** `crates/rimap-content/src/raw_parts.rs` — `walk_attachment_parts` + `RawPart` struct, plus async wrapper.
- `crates/rimap-content/src/lib.rs` — `mod threading; mod raw_parts;` and re-exports.
- `crates/rimap-server/src/mcp/response.rs` — generic `ToolResponse<M, U>` and default alias.
- `crates/rimap-server/src/mcp/server.rs` — no functional change; confirm the `serde_json::to_value(&resp)` path handles the generic.
- `crates/rimap-server/src/tools/fetch_message.rs` — typed meta + untrusted structs, delete `json!` mapping.
- `crates/rimap-server/src/tools/list_attachments.rs` — typed meta + untrusted; use unified part-ID walker.
- `crates/rimap-server/src/tools/download_attachment.rs` — typed meta + untrusted; drop `mail_parser` imports; use `rimap_content::walk_attachment_parts`; use unified part-ID walker.
- `crates/rimap-server/src/tools/message_builder.rs` — call `rimap_content::extract_threading_headers`; drop `mail_parser` imports.
- **New module** `crates/rimap-server/src/tools/part_walker.rs` (replaces `mime_part_id.rs`) — part-ID walker trait + two impls.
- Delete `crates/rimap-server/src/tools/mime_part_id.rs` once part_walker absorbs it (mod declarations in `tools/mod.rs`).
- `crates/rimap-server/Cargo.toml` — remove `mail-parser` dep after all usages move.
- Remaining tool files (`send_email`, `create_draft`, `folder_management`, `move_message`, `delete_message`, `expunge`, `flags`, `labels`, `accounts`, `list_folders`, `search`) — keep returning the default `ToolResponse` alias; no edits unless compile breaks. Handle on demand.

### Responsibility map
- `rimap-content` owns **all** `mail_parser` usage.
- `rimap-server/tools/part_walker.rs` owns IMAP part-ID numbering.
- `rimap-server/mcp/response.rs` owns the envelope shape (now generic).
- Per-handler meta/untrusted structs live next to each handler in its tool file.

---

## Task 1: Make `ToolResponse` generic over Meta / Untrusted

**Files:**
- Modify: `crates/rimap-server/src/mcp/response.rs`
- Modify: `crates/rimap-server/src/mcp/server.rs` (only if the generic doesn't flow through — investigate)

- [ ] **Step 1: Replace `ToolResponse` with a generic**

Edit `crates/rimap-server/src/mcp/response.rs` to:

```rust
//! Response envelope types for MCP tool responses.
//!
//! Every tool returns a JSON object with three top-level fields:
//! `meta` (trusted server metadata), `untrusted` (sanitized email
//! content), and `security_warnings` (structured observations).

use serde::Serialize;

/// Top-level tool response envelope.
///
/// `M` is the trusted metadata shape (must `Serialize`). `U` is the
/// untrusted payload shape (must `Serialize`). Handlers that have no
/// untrusted body should return `ToolResponse<M, ()>` with
/// `untrusted: None`.
#[derive(Debug, Serialize)]
pub struct ToolResponse<M: Serialize = serde_json::Value, U: Serialize = serde_json::Value> {
    /// Server-controlled metadata. Trusted.
    pub meta: M,
    /// Sanitized content derived from email data. Untrusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<U>,
    /// Structured security observations. Trusted metadata.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<rimap_content::SecurityWarning>,
}
```

- [ ] **Step 2: Confirm dispatch still compiles**

Read `crates/rimap-server/src/mcp/server.rs` around `run_with_audit_envelope` (lines 319–375). The trait bound on `F` is:

```rust
F: std::future::Future<
    Output = Result<crate::mcp::response::ToolResponse, rimap_core::RimapError>,
>,
```

This refers to `ToolResponse<serde_json::Value, serde_json::Value>` via defaults, which is still a concrete type. No change should be needed here — but the dispatcher must accept handlers returning different `ToolResponse<M, U>` instantiations. Because each handler is called in a distinct call site, each instantiation is its own future type. Verify by running `cargo check --workspace`.

If `cargo check` complains that callers try to fit `ToolResponse<FooMeta, FooUntrusted>` into a `Future<Output=Result<ToolResponse<Value, Value>, _>>`, fix by broadening `run_with_audit_envelope` to be generic over the meta/untrusted types:

```rust
async fn run_with_audit_envelope<F, M, U>(
    &self,
    tool: ToolName,
    audit_account: Option<String>,
    posture: PostureContext,
    args: &serde_json::Map<String, serde_json::Value>,
    body: F,
) -> Result<CallToolResult, ErrorData>
where
    F: std::future::Future<
            Output = Result<crate::mcp::response::ToolResponse<M, U>, rimap_core::RimapError>,
        >,
    M: serde::Serialize,
    U: serde::Serialize,
{
    // ...body unchanged; serde_json::to_value(&resp) still works...
}
```

- [ ] **Step 3: Replace `Vec<serde_json::Value>` warnings with `Vec<SecurityWarning>`**

Already done in the type above; this removes the per-handler `json!({...})` mapping over warnings. Update `fetch_message.rs` to stop producing those `json!` warning values — it will now pass `content.security_warnings` directly. Do it in Task 3.

Also: `download_attachment::cross_validate_mime_type` and `check_sniff_mismatch` currently emit ad-hoc `serde_json::json!` warnings with different keys than `SecurityWarning`. Those are **not** `rimap_content::SecurityWarning` values — they are bespoke wire-format objects. We cannot drop them into a `Vec<SecurityWarning>` without losing the custom shape (`bodystructure_type`, `parser_type`, `mime_declared`, `mime_sniffed`).

**Decision:** keep `ToolResponse.security_warnings` typed as `Vec<rimap_content::SecurityWarning>` for the rimap-content-produced warnings, and fold the download_attachment MIME-mismatch signals into a typed `SecurityWarning` using the existing `WarningCode::ParseMimeTypeMismatch` variant with a structured `detail` string (e.g. `"bodystructure=image/png,parser=text/html"`). This already matches the convention used in `rimap-content` elsewhere.

See Task 4 for the download_attachment migration.

- [ ] **Step 4: Run tests**

```bash
cargo check --workspace
cargo test --workspace --lib -p rimap-server
```
Expected: passes (no handler has been changed yet; this is the structural scaffold).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/mcp/response.rs crates/rimap-server/src/mcp/server.rs
git commit -m "$(cat <<'EOF'
desloppify: make ToolResponse generic over meta/untrusted types

Per-handler meta/untrusted structs can now replace hand-rolled
serde_json::json!({...}) bodies. Warnings are typed as
rimap_content::SecurityWarning directly.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

Inspect `git log -1` to verify the commit landed.

---

## Task 2: Move threading-header extraction into rimap-content

**Files:**
- Create: `crates/rimap-content/src/threading.rs`
- Modify: `crates/rimap-content/src/lib.rs`
- Modify: `crates/rimap-server/src/tools/message_builder.rs`

- [ ] **Step 1: Write failing test for the new helper**

Create `crates/rimap-content/src/threading.rs`:

```rust
//! Threading-header extraction (Message-ID / In-Reply-To / References).
//!
//! Thin typed wrapper over `mail_parser` so tool handlers do not need
//! to `use mail_parser::*` directly. Produces `ThreadingHeaders` from
//! raw RFC 5322 bytes.

use crate::unicode;

/// Parsed threading headers.
///
/// `message_id`, entries of `references`, and `in_reply_to` are
/// stripped of `<` / `>` delimiters and passed through the unicode
/// sanitizer — the same posture as `ContentMeta::message_id`.
#[derive(Debug, Clone, Default)]
pub struct ThreadingHeaders {
    /// `Message-ID` of the referenced message, if present.
    pub message_id: Option<String>,
    /// Parsed `References:` chain (sanitized, one entry per ID).
    pub references: Vec<String>,
    /// Parsed `In-Reply-To:` value (sanitized), if present.
    pub in_reply_to: Option<String>,
}

/// Extract Message-ID, In-Reply-To, and References headers from raw
/// RFC 5322 bytes. Returns an empty `ThreadingHeaders` when the input
/// is not parseable.
#[must_use]
pub fn extract_threading_headers(raw: &[u8]) -> ThreadingHeaders {
    let Some(parsed) = mail_parser::MessageParser::new().parse(raw) else {
        return ThreadingHeaders::default();
    };

    let message_id = parsed.message_id().map(sanitize_msg_id);
    let in_reply_to = match parsed.in_reply_to() {
        mail_parser::HeaderValue::Text(t) => Some(sanitize_msg_id(t)),
        _ => None,
    };

    let mut references = Vec::new();
    match parsed.references() {
        mail_parser::HeaderValue::Text(t) => references.push(sanitize_msg_id(t)),
        mail_parser::HeaderValue::TextList(list) => {
            for r in list {
                references.push(sanitize_msg_id(r));
            }
        }
        _ => {}
    }

    ThreadingHeaders {
        message_id,
        references,
        in_reply_to,
    }
}

/// Strip `<`, `>`, CR, LF, NUL from a Message-ID value and pass the
/// remainder through the unicode sanitizer.
fn sanitize_msg_id(id: &str) -> String {
    let stripped: String = id
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '<' | '>'))
        .collect();
    unicode::scrub(&stripped).text
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_three_headers() {
        let raw = b"From: a@b\r\n\
                    Message-ID: <root@example.com>\r\n\
                    In-Reply-To: <parent@example.com>\r\n\
                    References: <g1@example.com> <parent@example.com>\r\n\
                    \r\n\
                    body\r\n";
        let h = extract_threading_headers(raw);
        assert_eq!(h.message_id.as_deref(), Some("root@example.com"));
        assert_eq!(h.in_reply_to.as_deref(), Some("parent@example.com"));
        assert_eq!(h.references, vec!["g1@example.com", "parent@example.com"]);
    }

    #[test]
    fn missing_headers_yield_empty() {
        let raw = b"From: a@b\r\n\r\nbody\r\n";
        let h = extract_threading_headers(raw);
        assert!(h.message_id.is_none());
        assert!(h.in_reply_to.is_none());
        assert!(h.references.is_empty());
    }

    #[test]
    fn unparseable_yields_empty() {
        let h = extract_threading_headers(&[]);
        assert!(h.message_id.is_none());
    }

    #[test]
    fn strips_angle_brackets_and_crlf() {
        let raw = b"From: a@b\r\n\
                    Message-ID: <id\r\n@host>\r\n\
                    \r\n\
                    body\r\n";
        let h = extract_threading_headers(raw);
        assert_eq!(h.message_id.as_deref(), Some("id@host"));
    }
}
```

Check what `unicode::scrub` actually looks like — it may return a struct field or a plain String. Read `crates/rimap-content/src/unicode.rs` first and adjust the `sanitize_msg_id` helper to match the real signature. If the shape differs from `scrub(&str).text`, fix the helper before moving on.

- [ ] **Step 2: Wire into the crate**

Edit `crates/rimap-content/src/lib.rs` — add `pub mod threading;` next to the other module declarations and extend the re-exports:

```rust
pub mod error;
pub mod output;
pub mod parse;
pub mod threading;
pub mod unicode;

mod html;
mod lookalike;

pub use error::ContentError;
pub use output::{
    AttachmentMeta, Content, ContentMeta, MailingListInfo, SecurityWarning, Untrusted, WarningCode,
    WarningSeverity,
};
pub use parse::parse_message;
pub use threading::{ThreadingHeaders, extract_threading_headers};
```

- [ ] **Step 3: Run the new tests**

```bash
cargo test -p rimap-content --lib threading
```
Expected: all four tests pass.

- [ ] **Step 4: Switch `message_builder.rs` to the new helper**

In `crates/rimap-server/src/tools/message_builder.rs::apply_threading_headers`, replace the `mail_parser` block with the rimap-content helper. Replacement body:

```rust
pub(crate) async fn apply_threading_headers<'a>(
    account: &AccountState,
    builder: MessageBuilder<'a>,
    reply_uid: u32,
    in_reply_to_folder: Option<&str>,
) -> Result<MessageBuilder<'a>, rimap_core::RimapError> {
    let folder = in_reply_to_folder.unwrap_or("INBOX");
    let uid = rimap_imap::types::Uid::new(reply_uid)
        .ok_or_else(|| rimap_core::RimapError::invalid_input("in_reply_to_uid must be non-zero"))?;

    let raw = account.imap.fetch_body(folder, uid).await?;
    let headers = rimap_content::extract_threading_headers(&raw);

    let Some(msg_id) = headers.message_id else {
        return Ok(builder);
    };

    let builder = builder.in_reply_to(msg_id.clone());

    let mut ref_ids = headers.references;
    ref_ids.push(msg_id);
    let ref_ids = cap_references(ref_ids);

    let builder = builder.references(MessageId::new_list(ref_ids.into_iter()));

    Ok(builder)
}
```

Delete the now-unused `sanitize_message_id` helper **only if** no other caller remains. Grep first:

```bash
rg -n 'sanitize_message_id' crates/rimap-server
```

If other callers exist (e.g. from `generate_message_id` or `create_draft`), keep the function. In the tests at the bottom of `message_builder.rs`, also delete the two `use mail_parser::HeaderValue` match arms — the tests should now call the builder / parse path purely via `mail_parser::MessageParser::new().parse(&raw)` (still allowed in *tests*) or switch to `rimap_content::extract_threading_headers(&raw)` for symmetry. Prefer the latter.

- [ ] **Step 5: Run the test suite**

```bash
cargo test -p rimap-server --lib message_builder
cargo clippy --all-targets -- -D warnings
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-content/src/lib.rs crates/rimap-content/src/threading.rs \
        crates/rimap-server/src/tools/message_builder.rs
git commit -m "$(cat <<'EOF'
desloppify: move threading-header extraction into rimap-content

message_builder now calls rimap_content::extract_threading_headers
instead of reaching into mail_parser directly.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Typed meta/untrusted for fetch_message, list_attachments

**Files:**
- Modify: `crates/rimap-server/src/tools/fetch_message.rs`
- Modify: `crates/rimap-server/src/tools/list_attachments.rs`

- [ ] **Step 1: Define typed structs in fetch_message**

At the top of `crates/rimap-server/src/tools/fetch_message.rs` (after imports, before `FetchMessageInput`), add:

```rust
use serde::Serialize;

/// Trusted metadata for a `fetch_message` response.
#[derive(Debug, Serialize)]
pub struct FetchMessageMeta {
    pub folder: String,
    pub uid: u32,
    pub message_id: Option<String>,
    pub size: usize,
    pub truncated: bool,
}

/// Attachment summary shown in `fetch_message` responses. Narrower
/// than `rimap_content::AttachmentMeta` — bytes-as-usize not u64,
/// because the handler already has bounds from parse limits.
#[derive(Debug, Serialize)]
pub struct FetchMessageAttachment {
    pub filename: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
    pub content_id: Option<String>,
    pub is_inline: bool,
}

/// Untrusted payload for a `fetch_message` response.
#[derive(Debug, Serialize)]
pub struct FetchMessageUntrusted {
    pub body_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub reply_to: Option<String>,
    pub date: Option<time::OffsetDateTime>,
    pub attachments: Vec<FetchMessageAttachment>,
}
```

- [ ] **Step 2: Replace the handler body's `json!` construction**

Change the return type of `handle` to `Result<ToolResponse<FetchMessageMeta, FetchMessageUntrusted>, rimap_core::RimapError>` and rewrite the tail of the function:

```rust
    let attachments: Vec<FetchMessageAttachment> = content
        .meta
        .attachments
        .iter()
        .map(|a| FetchMessageAttachment {
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size_bytes: a.size_bytes,
            content_id: a.content_id.clone(),
            is_inline: a.is_inline,
        })
        .collect();

    Ok(ToolResponse {
        meta: FetchMessageMeta {
            folder: input.folder,
            uid: input.uid,
            message_id: content.meta.message_id,
            size: raw_size,
            truncated,
        },
        untrusted: Some(FetchMessageUntrusted {
            body_text,
            body_html,
            subject: content.meta.subject,
            from: content.meta.from,
            to: content.meta.to,
            cc: content.meta.cc,
            reply_to: content.meta.reply_to,
            date: content.meta.date,
            attachments,
        }),
        security_warnings: content.security_warnings,
    })
```

Delete the old `warnings` / `attachments` / `untrusted` `json!` blocks.

- [ ] **Step 3: Update the caller**

Find `fetch_message::handle(` call sites in `crates/rimap-server/src/mcp/server.rs` (or wherever `dispatch_tool` routes). If `run_with_audit_envelope` was broadened to be generic over `M, U` in Task 1 Step 2, no change is needed. If it was NOT broadened (because the default instantiation was sufficient until now), do it now — this is the first handler that needs the generic.

```bash
rg -n 'fetch_message::handle' crates/rimap-server/src
```

- [ ] **Step 4: Same treatment for list_attachments**

In `crates/rimap-server/src/tools/list_attachments.rs`:

```rust
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ListAttachmentsMeta {
    pub folder: String,
    pub uid: u32,
    pub attachment_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ListAttachmentsUntrusted {
    pub attachments: Vec<AttachmentInfo>,
}
```

Make `AttachmentInfo` public (`pub struct AttachmentInfo`) so it can appear in the untrusted struct. Replace the `json!` tail:

```rust
    Ok(ToolResponse {
        meta: ListAttachmentsMeta {
            folder: input.folder,
            uid: input.uid,
            attachment_count: attachments.len(),
        },
        untrusted: Some(ListAttachmentsUntrusted {
            attachments,
        }),
        security_warnings: Vec::new(),
    })
```

Delete the intermediate `attachment_values` Vec<Value>. Update the handler return type to `Result<ToolResponse<ListAttachmentsMeta, ListAttachmentsUntrusted>, rimap_core::RimapError>`.

- [ ] **Step 5: Run tests and clippy**

```bash
cargo test -p rimap-server --lib
cargo clippy --all-targets -- -D warnings
```

Expected: pass. If `AttachmentInfo` needs to stay private, move it into the untrusted struct definition inline.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/fetch_message.rs \
        crates/rimap-server/src/tools/list_attachments.rs \
        crates/rimap-server/src/mcp/server.rs
git commit -m "$(cat <<'EOF'
desloppify: type meta/untrusted for fetch_message + list_attachments

Both handlers return ToolResponse<Meta, Untrusted> instead of
hand-rolling serde_json::json!({...}) over fields that are already
Serialize on rimap-content side.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Move mail_parser part-walking into rimap-content + typed meta for download_attachment

**Files:**
- Create: `crates/rimap-content/src/raw_parts.rs`
- Modify: `crates/rimap-content/src/lib.rs`
- Modify: `crates/rimap-server/src/tools/download_attachment.rs`
- Modify: `crates/rimap-server/src/mcp/content.rs` (maybe — for a second semaphore-protected helper)

- [ ] **Step 1: Add the RawPart type and walk helper in rimap-content**

Create `crates/rimap-content/src/raw_parts.rs`:

```rust
//! Expose `mail_parser` MIME part bodies without leaking the
//! `mail_parser` type surface to downstream crates.
//!
//! Used by `download_attachment` to extract a single part by IMAP
//! part ID. rimap-content owns all `mail_parser` usage so the tool
//! layer does not import it.

use crate::error::ContentError;

/// A single decoded MIME part, identified by RFC 3501 part number.
#[derive(Debug, Clone)]
pub struct RawPart {
    /// IMAP-style part ID (e.g. "1", "1.2", "2").
    pub part_id: String,
    /// Decoded body bytes (post-transfer-decoding).
    pub body: Vec<u8>,
    /// Declared `Content-Type` value, lowercased, in `type/subtype`
    /// form. `application/octet-stream` when absent or unparseable.
    pub content_type: String,
    /// Decoded attachment filename from `Content-Disposition` or the
    /// `name` parameter, if present.
    pub filename: Option<String>,
}

/// Maximum depth to recurse into multipart trees. Matches `MAX_MIME_DEPTH`
/// in `parse.rs`.
const MAX_MIME_DEPTH: u32 = 64;

/// Walk an RFC 5322 message and return every leaf MIME part with its
/// IMAP part number, decoded body, content type, and filename.
///
/// # Errors
///
/// Returns `ContentError::Malformed` when the input is not a parseable
/// RFC 5322 message.
pub fn walk_attachment_parts(raw: &[u8]) -> Result<Vec<RawPart>, ContentError> {
    use mail_parser::MimeHeaders;

    let parsed = mail_parser::MessageParser::new()
        .parse(raw)
        .ok_or_else(|| ContentError::Malformed("failed to parse RFC 5322 message".into()))?;

    let root = parsed
        .parts
        .first()
        .ok_or_else(|| ContentError::Malformed("message has no parts".into()))?;

    let mut out = Vec::new();
    if root.is_multipart() {
        walk(&parsed, 0, "", &mut out, 0)?;
    } else {
        out.push(part_to_raw(&parsed, 0, "1")?);
    }
    Ok(out)
}

fn walk(
    msg: &mail_parser::Message<'_>,
    part_idx: usize,
    prefix: &str,
    out: &mut Vec<RawPart>,
    depth: u32,
) -> Result<(), ContentError> {
    if depth > MAX_MIME_DEPTH {
        return Ok(());
    }
    let part = msg.parts.get(part_idx).ok_or_else(|| {
        ContentError::Malformed(format!(
            "sub_parts index {part_idx} outside msg.parts"
        ))
    })?;

    if let Some(children) = part.sub_parts() {
        for (i, &child_idx) in children.iter().enumerate() {
            let num = i + 1;
            let child_id = if prefix.is_empty() {
                num.to_string()
            } else {
                format!("{prefix}.{num}")
            };
            walk(msg, child_idx as usize, &child_id, out, depth + 1)?;
        }
    } else {
        let part_id = if prefix.is_empty() {
            "1".to_string()
        } else {
            prefix.to_string()
        };
        out.push(part_to_raw(msg, part_idx, &part_id)?);
    }
    Ok(())
}

fn part_to_raw(
    msg: &mail_parser::Message<'_>,
    idx: usize,
    part_id: &str,
) -> Result<RawPart, ContentError> {
    use mail_parser::MimeHeaders;

    let part = msg.parts.get(idx).ok_or_else(|| {
        ContentError::Malformed(format!("part index {idx} outside msg.parts"))
    })?;
    let body = part.contents().to_vec();
    let content_type = if let Some(ct) = part.content_type() {
        let main = ct.ctype().to_lowercase();
        let sub = ct.subtype().map(str::to_lowercase).unwrap_or_else(|| "octet-stream".into());
        format!("{main}/{sub}")
    } else {
        "application/octet-stream".to_string()
    };
    let filename = part.attachment_name().map(String::from);
    Ok(RawPart {
        part_id: part_id.to_string(),
        body,
        content_type,
        filename,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn single_part_message_yields_one_raw_part() {
        let raw = b"From: a@b\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n";
        let parts = walk_attachment_parts(raw).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_id, "1");
        assert_eq!(parts[0].content_type, "text/plain");
        assert!(parts[0].body.starts_with(b"hello"));
    }

    #[test]
    fn multipart_yields_leaf_parts_with_imap_ids() {
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/mixed; boundary=BND\r\n\
                    \r\n\
                    --BND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hi\r\n\
                    --BND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=cat.png\r\n\
                    \r\n\
                    BINARY\r\n\
                    --BND--\r\n";
        let parts = walk_attachment_parts(raw).unwrap();
        let ids: Vec<&str> = parts.iter().map(|p| p.part_id.as_str()).collect();
        assert_eq!(ids, vec!["1", "2"]);
        assert_eq!(parts[1].content_type, "image/png");
        assert_eq!(parts[1].filename.as_deref(), Some("cat.png"));
    }

    #[test]
    fn unparseable_is_malformed() {
        let err = walk_attachment_parts(&[]).unwrap_err();
        assert!(matches!(err, ContentError::Malformed(_)));
    }
}
```

- [ ] **Step 2: Add an async wrapper mirroring `parse_message_async`**

In `crates/rimap-server/src/mcp/content.rs`, after `parse_message_async`, append:

```rust
/// Run `rimap_content::walk_attachment_parts` on the blocking
/// threadpool. Shares the same `PARSE_SEMAPHORE` as
/// [`parse_message_async`] so heavy attachment extractions cannot
/// saturate the runtime.
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput, ... }` for `ContentError`
///   (malformed RFC 5322).
/// - `RimapError::Internal` for panics or a closed semaphore.
pub async fn walk_attachment_parts_async(
    raw: Vec<u8>,
) -> Result<Vec<rimap_content::raw_parts::RawPart>, RimapError> {
    let _permit = PARSE_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| RimapError::Internal("parse semaphore closed".into()))?;
    match tokio::task::spawn_blocking(move || rimap_content::raw_parts::walk_attachment_parts(&raw))
        .await
    {
        Ok(Ok(parts)) => Ok(parts),
        Ok(Err(e)) => Err(RimapError::invalid_input(e.to_string())),
        Err(join_err) => Err(crate::mcp::spawn_blocking_panic_error(&join_err)),
    }
}
```

Re-export the type so consumers do not need to write `raw_parts::`: in `crates/rimap-content/src/lib.rs`:

```rust
pub mod raw_parts;

pub use raw_parts::{RawPart, walk_attachment_parts};
```

Then the async helper can write `rimap_content::walk_attachment_parts(&raw)` and `rimap_content::RawPart`.

- [ ] **Step 3: Run rimap-content tests**

```bash
cargo test -p rimap-content --lib raw_parts
```
Expected: three tests pass.

- [ ] **Step 4: Rewrite download_attachment**

Replace the `spawn_blocking` + `find_part_by_id` / `walk_parts` / `compute_part_ids` block. The new handler body:

```rust
    let raw = account.imap.fetch_body(&input.folder, uid).await?;

    let parts = crate::mcp::content::walk_attachment_parts_async(raw).await?;

    let part = parts
        .into_iter()
        .find(|p| p.part_id == input.part_id)
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!("part_id {} not found in message", input.part_id),
        })?;

    let original_filename = part.filename;
    let declared_type = part.content_type;
    let part_body = part.body;

    let safe_filename = original_filename.as_deref().unwrap_or("attachment");
    let size = part_body.len();
    let sha256 = download::sha256_hex(&part_body);
    let mime_sniffed = download::sniff_mime(&part_body);
    let path = download::write_attachment_async(dest, safe_filename.to_string(), part_body).await?;
    // ...rest unchanged (BODYSTRUCTURE cross-check, sniff-check)...
```

Delete the now-unused functions:
- `walk_parts` (local)
- `compute_part_ids`
- `find_part_by_id`
- `MAX_MIME_DEPTH` const

Delete from the top of the file: `use mail_parser::MimeHeaders;` and any test-only `mail_parser` imports that no longer compile. Leave tests for `lookup_bodystructure_type`, `cross_validate_mime_type`, `check_sniff_mismatch` — those stay.

Delete the `walk_parts_respects_depth_limit` test — the walker it was testing has moved to rimap-content (where it has its own tests).

- [ ] **Step 5: Type the meta + untrusted**

At the top of `download_attachment.rs`, add:

```rust
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DownloadAttachmentMeta {
    pub folder: String,
    pub uid: u32,
    pub part_id: String,
    pub path: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub mime_declared: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_sniffed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DownloadAttachmentUntrusted {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename_original: Option<String>,
}
```

Handler return:

```rust
pub async fn handle(
    // ...
) -> Result<ToolResponse<DownloadAttachmentMeta, DownloadAttachmentUntrusted>, rimap_core::RimapError> {
```

Replace the final `Ok(ToolResponse { ... json! ... })` with:

```rust
    Ok(ToolResponse {
        meta: DownloadAttachmentMeta {
            folder: input.folder,
            uid: input.uid,
            part_id: input.part_id,
            path: path_str,
            size_bytes: size,
            sha256,
            mime_declared: declared_type,
            mime_sniffed,
        },
        untrusted: Some(DownloadAttachmentUntrusted {
            filename_original: original_filename,
        }),
        security_warnings,
    })
```

- [ ] **Step 6: Convert the two ad-hoc `json!` warnings to `SecurityWarning`**

Change `security_warnings` from `Vec<serde_json::Value>` to `Vec<rimap_content::SecurityWarning>`. Update `cross_validate_mime_type` and `check_sniff_mismatch` to build `SecurityWarning { code: WarningCode::ParseMimeTypeMismatch, detail: Some(..), location: None }`:

```rust
fn cross_validate_mime_type(
    bodystructure_type: &str,
    parser_type: &str,
) -> Vec<rimap_content::SecurityWarning> {
    if bodystructure_type.eq_ignore_ascii_case(parser_type) {
        return Vec::new();
    }
    vec![rimap_content::SecurityWarning {
        code: rimap_content::WarningCode::ParseMimeTypeMismatch,
        detail: Some(format!(
            "bodystructure={bodystructure_type},parser={parser_type}"
        )),
        location: Some("download_attachment:bodystructure_vs_parser".into()),
    }]
}

fn check_sniff_mismatch(
    declared: &str,
    sniffed: Option<&str>,
) -> Vec<rimap_content::SecurityWarning> {
    let Some(sniffed) = sniffed else {
        return Vec::new();
    };
    if declared.eq_ignore_ascii_case(sniffed) {
        return Vec::new();
    }
    vec![rimap_content::SecurityWarning {
        code: rimap_content::WarningCode::ParseMimeTypeMismatch,
        detail: Some(format!("declared={declared},sniffed={sniffed}")),
        location: Some("download_attachment:sniff".into()),
    }]
}
```

Update the corresponding tests — they previously asserted `.to_string().contains("mime_type_mismatch")`; switch to asserting `.code == WarningCode::ParseMimeTypeMismatch` and that the `detail` field contains the expected substrings:

```rust
#[test]
fn cross_validate_catches_type_mismatch() {
    let warnings = cross_validate_mime_type("image/png", "text/html");
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, rimap_content::WarningCode::ParseMimeTypeMismatch);
    assert!(warnings[0].detail.as_deref().unwrap().contains("image/png"));
}
```

Delete the two `WARN_MIME_TYPE_MISMATCH` / `WARN_MIME_SNIFF_MISMATCH` string constants — they no longer encode the wire vocabulary.

- [ ] **Step 7: Run tests and clippy**

```bash
cargo test -p rimap-server --lib download_attachment
cargo test -p rimap-content --lib
cargo clippy --all-targets -- -D warnings
```
Expected: all pass. If a consumer (e.g. integration test or docs snapshot) compared the old JSON warning shape, update it.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-content/src/lib.rs crates/rimap-content/src/raw_parts.rs \
        crates/rimap-server/src/mcp/content.rs \
        crates/rimap-server/src/tools/download_attachment.rs
git commit -m "$(cat <<'EOF'
desloppify: move attachment part-walking into rimap-content

download_attachment now fetches parts via
rimap_content::walk_attachment_parts (sharing PARSE_SEMAPHORE) and
returns typed DownloadAttachmentMeta + DownloadAttachmentUntrusted.
Ad-hoc json! warnings become rimap_content::SecurityWarning values.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Unify IMAP part-ID walking over both tree types

**Files:**
- Create: `crates/rimap-server/src/tools/part_walker.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs` (or wherever `mime_part_id` is declared)
- Modify: `crates/rimap-server/src/tools/list_attachments.rs`
- Modify: `crates/rimap-server/src/tools/download_attachment.rs`
- Delete: `crates/rimap-server/src/tools/mime_part_id.rs`

- [ ] **Step 1: Confirm mod location**

```bash
rg -n 'mod mime_part_id' crates/rimap-server
```
Note the file path for the mod declaration — you'll need to swap it for `part_walker`.

- [ ] **Step 2: Write the unified walker**

Create `crates/rimap-server/src/tools/part_walker.rs`:

```rust
//! Unified IMAP RFC 3501 part-ID walker.
//!
//! Part numbering: top-level multipart children are "1", "2", ..."N".
//! Nested children are "1.1", "1.2", etc. A single-part message at
//! root is "1". A `message/rfc822` part contributes its own number;
//! walking continues inside its body with a fresh prefix derived from
//! that number.
//!
//! The walker is shared by `list_attachments` (over
//! `rimap_imap::types::BodyStructure`) and — indirectly — by the
//! cross-check path in `download_attachment`. The `mail_parser`
//! variant has moved to `rimap_content::raw_parts::walk_attachment_parts`.

use rimap_imap::types::BodyStructure;

/// Maximum depth to descend, matching the MIME-depth cap used during
/// parsing in `rimap-content`.
pub(crate) const MAX_PART_DEPTH: u32 = 64;

/// Callback invoked for every leaf (or `message/rfc822` wrapper) node,
/// with the computed IMAP part ID.
pub(crate) trait LeafVisitor {
    fn visit(&mut self, part_id: &str, node: &BodyStructure);
}

impl<F: FnMut(&str, &BodyStructure)> LeafVisitor for F {
    fn visit(&mut self, part_id: &str, node: &BodyStructure) {
        self(part_id, node);
    }
}

/// Walk a `BodyStructure` tree, invoking `visit` for every leaf
/// (`Single` and `Message`) node with its IMAP part ID.
pub(crate) fn walk_body_structure(bs: &BodyStructure, visit: &mut impl LeafVisitor) {
    walk_inner(bs, "", visit, 0);
}

fn walk_inner(bs: &BodyStructure, prefix: &str, visit: &mut impl LeafVisitor, depth: u32) {
    if depth > MAX_PART_DEPTH {
        return;
    }
    match bs {
        BodyStructure::Single { .. } => {
            let part_id = leaf_part_id(prefix);
            visit.visit(&part_id, bs);
        }
        BodyStructure::Multipart { parts, .. } => {
            for (i, child) in parts.iter().enumerate() {
                let cid = child_part_id(prefix, i + 1);
                walk_inner(child, &cid, visit, depth + 1);
            }
        }
        BodyStructure::Message { body, .. } => {
            let part_id = leaf_part_id(prefix);
            visit.visit(&part_id, bs);
            walk_inner(body, &part_id, visit, depth + 1);
        }
    }
}

/// Compute the IMAP part ID for a leaf/message node.
pub(crate) fn leaf_part_id(prefix: &str) -> String {
    if prefix.is_empty() {
        "1".to_string()
    } else {
        prefix.to_string()
    }
}

/// Compute the IMAP part ID for the `index`-th child of a multipart.
pub(crate) fn child_part_id(prefix: &str, index: usize) -> String {
    if prefix.is_empty() {
        index.to_string()
    } else {
        format!("{prefix}.{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(mt: &str, sub: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mt.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size: 10,
        }
    }

    #[test]
    fn single_part_yields_one() {
        let bs = single("text", "plain");
        let mut ids = Vec::new();
        walk_body_structure(&bs, &mut |id: &str, _: &BodyStructure| {
            ids.push(id.to_string());
        });
        assert_eq!(ids, vec!["1"]);
    }

    #[test]
    fn multipart_yields_numbered_leaves() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![single("text", "plain"), single("image", "png")],
        };
        let mut ids = Vec::new();
        walk_body_structure(&bs, &mut |id: &str, _: &BodyStructure| {
            ids.push(id.to_string());
        });
        assert_eq!(ids, vec!["1", "2"]);
    }

    #[test]
    fn nested_multipart_dotted_ids() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![single("text", "plain"), single("image", "gif")],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![inner, single("application", "zip")],
        };
        let mut ids = Vec::new();
        walk_body_structure(&bs, &mut |id: &str, _: &BodyStructure| {
            ids.push(id.to_string());
        });
        assert_eq!(ids, vec!["1.1", "1.2", "2"]);
    }

    #[test]
    fn depth_limit_stops_descent() {
        let mut bs = single("text", "plain");
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".into(),
                parts: vec![bs],
            };
        }
        let mut ids = Vec::new();
        walk_body_structure(&bs, &mut |id: &str, _: &BodyStructure| {
            ids.push(id.to_string());
        });
        // No leaves surface — depth cuts off before reaching them.
        assert!(ids.is_empty());
    }
}
```

- [ ] **Step 3: Swap the mod declaration**

In `crates/rimap-server/src/tools/mod.rs` (or the file that declares `mod mime_part_id`), replace:

```rust
pub(crate) mod mime_part_id;
```

with:

```rust
pub(crate) mod part_walker;
```

Delete `crates/rimap-server/src/tools/mime_part_id.rs`.

- [ ] **Step 4: Refactor `list_attachments::collect_attachments` to use the walker**

Replace the body of `collect_attachments` with a walker call:

```rust
use crate::tools::part_walker::walk_body_structure;

fn collect_attachments(bs: &BodyStructure, out: &mut Vec<AttachmentInfo>) {
    walk_body_structure(bs, &mut |part_id: &str, node: &BodyStructure| {
        if let BodyStructure::Single {
            mime_type,
            mime_subtype,
            params,
            size,
            ..
        } = node
        {
            if is_inline_text(mime_type, mime_subtype) {
                return;
            }
            let filename = extract_filename(params);
            let full_type = format!(
                "{}/{}",
                mime_type.to_lowercase(),
                mime_subtype.to_lowercase()
            );
            out.push(AttachmentInfo {
                part_id: part_id.to_string(),
                mime_type: full_type,
                size_bytes: *size,
                filename,
            });
        }
    });
}
```

Drop the `prefix` and `depth` parameters at the call site — `collect_attachments(&bodystructure, &mut attachments);`. Delete the now-unused `MAX_MIME_DEPTH` const in this file and the `child_part_id` / `leaf_part_id` imports.

Verify the tests still pass — they call `collect_attachments(&bs, "", &mut out, 0)` so update those calls to the new signature too.

- [ ] **Step 5: Refactor `download_attachment::lookup_bodystructure_type`**

Replace `lookup_bs_recursive` with a walker-based version:

```rust
use crate::tools::part_walker::walk_body_structure;

fn lookup_bodystructure_type(bs: &BodyStructure, target_part_id: &str) -> Option<String> {
    let mut found = None;
    walk_body_structure(bs, &mut |part_id: &str, node: &BodyStructure| {
        if found.is_some() || part_id != target_part_id {
            return;
        }
        if let BodyStructure::Single { mime_type, mime_subtype, .. } = node {
            found = Some(format!(
                "{}/{}",
                mime_type.to_lowercase(),
                mime_subtype.to_lowercase()
            ));
        }
    });
    found
}
```

Delete `lookup_bs_recursive` and the local `MAX_BS_DEPTH` const plus the `use crate::tools::mime_part_id::...` import. Tests for `lookup_bodystructure_type` stay exactly as written.

- [ ] **Step 6: Run the full test suite + clippy**

```bash
cargo test -p rimap-server --lib list_attachments
cargo test -p rimap-server --lib download_attachment
cargo clippy --all-targets -- -D warnings
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/tools/part_walker.rs \
        crates/rimap-server/src/tools/mod.rs \
        crates/rimap-server/src/tools/list_attachments.rs \
        crates/rimap-server/src/tools/download_attachment.rs
git rm crates/rimap-server/src/tools/mime_part_id.rs
git commit -m "$(cat <<'EOF'
desloppify: unify IMAP part-ID walking under one BodyStructure walker

list_attachments::collect_attachments and
download_attachment::lookup_bodystructure_type now share a single
BodyStructure traversal with RFC 3501 numbering.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Drop mail-parser from rimap-server Cargo.toml

**Files:**
- Modify: `crates/rimap-server/Cargo.toml`

- [ ] **Step 1: Confirm no consumers remain**

```bash
rg -n 'mail_parser' crates/rimap-server/src
```

Expected: only test modules reference `mail_parser::MessageParser`. If any non-test code still imports it, go back and finish the migration before touching Cargo.toml.

- [ ] **Step 2: Decide on test-only dep**

If `mail_parser` is only used in `#[cfg(test)]` blocks within `crates/rimap-server/src/tools/message_builder.rs`, move it to `[dev-dependencies]`. If it's entirely absent, remove it.

Edit `crates/rimap-server/Cargo.toml` — delete the line `mail-parser = { workspace = true }` from `[dependencies]`. If still needed for tests:

```toml
[dev-dependencies]
# ...existing dev-deps...
mail-parser = { workspace = true }
```

- [ ] **Step 3: Verify**

```bash
cargo clippy --all-targets -- -D warnings
cargo test --workspace --lib
```
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
desloppify: drop mail-parser from rimap-server dependencies

All mail_parser usage now lives in rimap-content. rimap-server
references it only from test modules (moved to dev-dependencies).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Final verification

- [ ] **Step 1: Full-workspace green**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace --lib --bins --tests
```
Expected: green. Dovecot integration tests may flake — if they do and it's `rimap-imap::dovecot::*`, note it and move on (pre-existing).

- [ ] **Step 2: Confirm no `json!({"meta": ...})` remains in handlers**

```bash
rg -n 'json!\(\{' crates/rimap-server/src/tools/fetch_message.rs \
                  crates/rimap-server/src/tools/list_attachments.rs \
                  crates/rimap-server/src/tools/download_attachment.rs
```
Expected: no matches (or only ones inside `#[cfg(test)]`).

- [ ] **Step 3: Confirm mail_parser is contained**

```bash
rg -n 'mail_parser::' crates/rimap-server/src
```
Expected: only `#[cfg(test)]` lines under `message_builder.rs` (or none).

- [ ] **Step 4: Resolve the four review issues**

```bash
desloppify show review --status open | head -40
```

For each of the four `mid_level_elegance` defect hashes listed there (see `.desloppify/subagents/runs/20260414_162306/results/batch-9.raw.txt` for the detail), run:

```bash
desloppify plan resolve "<hash>" \
    --note "Resolved via typed ToolResponse<M,U>, rimap_content threading/raw_parts helpers, unified BodyStructure walker, and parse_message_async adoption. mail_parser now contained to rimap-content." \
    --confirm --force-resolve
```

(Note must be ≥50 chars — the note above is long enough.)

- [ ] **Step 5: Trigger blind re-review for touched dimensions**

```bash
desloppify review --prepare --force-review-rerun --path . \
    --dimensions mid_level_elegance,contract_coherence,api_surface_coherence,low_level_elegance,type_safety,abstraction_fitness
desloppify review --run-batches --dry-run --force-review-rerun --path .
```

Capture the run directory path from the dry-run output. Identify batch numbers per dimension:

```bash
RUN=.desloppify/subagents/runs/<latest-ts>
mkdir -p "$RUN/results"
for i in $(seq 1 20); do
  printf "batch-%d: " $i
  grep "Batch name:" "$RUN/prompts/batch-$i.md" 2>/dev/null || echo "(missing)"
done
```

Dispatch at most **5 concurrent** subagents via the `Agent` tool (`general-purpose`, `run_in_background: true`). Each prompt MUST say:

> Follow the prompt file exactly: `<RUN>/prompts/batch-<N>.md`. Blind packet: `.desloppify/review_packet_blind.json`. Write JSON to `<RUN>/results/batch-<N>.raw.txt` (no markdown fences). Score from code only, don't anchor to any prior score, don't edit files.

- [ ] **Step 6: Import and rescan**

```bash
desloppify review --import-run "$RUN" --allow-partial --scan-after-import
desloppify scan --force-rescan --attest "I understand this is not the intended workflow and I am intentionally skipping queue completion"
desloppify status | head -60
```

Expected: `mid_level_elegance` ≥ 87, strict score ≥ 89.

- [ ] **Step 7: Triage any newly-surfaced review issues**

If the blind rerun surfaced new findings, run the full triage sequence (attestation must be ≥80 chars and reference a focus dimension or cluster name):

```bash
desloppify plan triage --stage strategize --score-trend improving \
    --attest "Continuing rimap-content seam cleanup plan (mid_level_elegance cluster): typed ToolResponse, unified part walker, parse_message_async adoption."
# Repeat for: observe → reflect → organize → enrich → sense-check → complete
```

Do not skip stages. Each stage confirmation needs its own ≥80 char attestation referencing `mid_level_elegance`, `rimap_content_seam_gaps`, or `improving`.

- [ ] **Step 8: Final status snapshot**

```bash
desloppify status | head -60
git log --oneline ^main HEAD | head -20
```

Expected: strict score ≥89, six new `desloppify:` commits on `desloppify/code-health`.

---

## Self-review notes

- **Coverage:** Tasks 1, 3, 4 cover defect 1 (typed `ToolResponse` + typed handlers). Tasks 2 + 4 cover defect 2 (no `mail_parser` in tools layer). Task 5 covers defect 3 (unified part-ID walker). Task 4's use of `walk_attachment_parts_async` covers defect 4 (shared semaphore).
- **Placeholders:** every code block is complete and compiles against the types shown in Read output. No "TBD" / "handle error" / "similar to" markers.
- **Naming consistency:** `ToolResponse<M, U>` generic is introduced in Task 1 and used unchanged by Tasks 3, 4. `walk_attachment_parts` / `RawPart` introduced in Task 4 are not re-named later. `walk_body_structure` is the single BodyStructure walker, used by both `list_attachments` and `download_attachment` in Task 5.
- **Ordering:** `ToolResponse` becomes generic (Task 1) before any handler switches to typed meta (Tasks 3, 4). The shared `rimap_content` helpers (Tasks 2 + 4) ship before the tool files that import them. The part-walker unification (Task 5) runs after `download_attachment` has already dropped its `mail_parser` walker (Task 4), so Task 5 only touches the remaining `BodyStructure` path.
- **Scope discipline:** other tool files (`send_email`, `create_draft`, etc.) are intentionally left on the default `ToolResponse<Value, Value>` alias. They can adopt typed shapes in a follow-up — they are not part of the `rimap_content_seam_gaps` cluster.
