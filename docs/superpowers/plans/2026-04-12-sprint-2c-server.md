# Sprint 2c: v2 Server Layer — Tool Handlers + SMTP Integration Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the six new v2 tools into the MCP server: `send_email`, `delete_message`, `expunge`, `create_folder`, `rename_folder`, `delete_folder`. Extract shared message building from `create_draft`. Add SMTP sink integration tests.

**Architecture:** Each tool handler follows the existing pattern in `crates/rimap-server/src/tools/` — a `handle()` function taking `&ImapMcpServer` + typed input, returning `Result<ToolResponse, RimapError>`. The `send_email` handler reuses the message-building logic extracted from `create_draft` and calls `rimap-smtp` for delivery. Tool dispatch in `server.rs` is extended with new match arms and `tool_definition` entries.

**Tech Stack:** Rust, rmcp, schemars, mail-builder, lettre, serde_json

**Depends on:** Sprint 2a (types, config, authz) + Sprint 2b (IMAP ops, SMTP crate)

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `crates/rimap-server/src/tools/message_builder.rs` | Shared RFC 5322 message construction (extracted from `create_draft`) |
| Modify | `crates/rimap-server/src/tools/create_draft.rs` | Delegate to `message_builder`, keep APPEND logic |
| Create | `crates/rimap-server/src/tools/send_email.rs` | `send_email` handler |
| Create | `crates/rimap-server/src/tools/delete_message.rs` | `delete_message` handler |
| Create | `crates/rimap-server/src/tools/expunge.rs` | `expunge` handler |
| Create | `crates/rimap-server/src/tools/folder_mgmt.rs` | `create_folder`, `rename_folder`, `delete_folder` handlers |
| Modify | `crates/rimap-server/src/tools/mod.rs` | Register new modules |
| Modify | `crates/rimap-server/src/server.rs` | Add dispatch arms and tool definitions |
| Modify | `crates/rimap-server/Cargo.toml` | Add `rimap-smtp` dependency |

---

## Task 1: Extract shared message builder from `create_draft`

**Files:**
- Create: `crates/rimap-server/src/tools/message_builder.rs`
- Modify: `crates/rimap-server/src/tools/create_draft.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

The `build_message_headers`, `addresses_to_builder`, `single_address`, `generate_message_id`, `validate_draft_input`, `validate_header_text`, `validate_addresses`, `sanitize_message_id`, `apply_threading_headers`, `cap_references`, `AddressInput`, and the `MAX_*` constants are used by both `create_draft` and `send_email`. Extract them into a shared module.

- [ ] **Step 1: Create `message_builder.rs`**

Create `crates/rimap-server/src/tools/message_builder.rs` containing:

- `AddressInput` struct (with `Deserialize`, `JsonSchema`)
- `validate_compose_input()` — renamed from `validate_draft_input` to be generic
- `validate_header_text()`
- `validate_addresses()`
- `sanitize_message_id()`
- `build_message_headers()`
- `addresses_to_builder()`
- `single_address()`
- `generate_message_id()`
- `apply_threading_headers()`
- `cap_references()`
- `MAX_RECIPIENTS`, `MAX_SUBJECT_LEN`, `MAX_BODY_BYTES`, `MAX_REFERENCES` constants

All with `pub(crate)` visibility. The function signatures remain identical — this is a pure move, not a refactor.

```rust
//! Shared RFC 5322 message construction for `create_draft` and `send_email`.
//!
//! Extracted from `create_draft` to avoid duplication. Both tool handlers
//! call `build_message_headers` and `apply_threading_headers`; only the
//! delivery step differs (IMAP APPEND vs SMTP send).

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::message_id::MessageId;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::ImapMcpServer;

/// An email address with optional display name.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct AddressInput {
    /// Display name (optional).
    pub name: Option<String>,
    /// Email address.
    pub address: String,
}

pub(crate) const MAX_RECIPIENTS: usize = 100;
pub(crate) const MAX_SUBJECT_LEN: usize = 1000;
pub(crate) const MAX_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_REFERENCES: usize = 50;

/// Common input fields shared by `create_draft` and `send_email`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ComposeInput {
    /// Recipient addresses.
    pub to: Vec<AddressInput>,
    /// CC addresses.
    pub cc: Option<Vec<AddressInput>>,
    /// BCC addresses.
    pub bcc: Option<Vec<AddressInput>>,
    /// Email subject.
    pub subject: String,
    /// Plain text body.
    pub body_text: String,
    /// UID of message to reply to (for threading headers).
    pub in_reply_to_uid: Option<u32>,
    /// Folder containing the message to reply to (default INBOX).
    pub in_reply_to_folder: Option<String>,
}

/// Validate all user-supplied fields in a compose input.
pub(crate) fn validate_compose_input(
    input: &ComposeInput,
) -> Result<(), rimap_core::RimapError> {
    if input.to.is_empty() {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "at least one To recipient is required".into(),
        });
    }

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
                "subject too long ({} bytes); max is {MAX_SUBJECT_LEN}",
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

    validate_addresses("To", &input.to)?;
    if let Some(cc) = &input.cc {
        validate_addresses("CC", cc)?;
    }
    if let Some(bcc) = &input.bcc {
        validate_addresses("BCC", bcc)?;
    }
    if input
        .subject
        .bytes()
        .any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
    {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "subject contains forbidden characters".into(),
        });
    }
    Ok(())
}

/// Reject strings that could inject RFC 5322 headers.
pub(crate) fn validate_header_text(
    field: &str,
    value: &str,
) -> Result<(), rimap_core::RimapError> {
    if value
        .bytes()
        .any(|b| matches!(b, b'\r' | b'\n' | b'\0' | b'<' | b'>'))
    {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: format!("{field} contains forbidden characters"),
        });
    }
    Ok(())
}

fn validate_addresses(
    field: &str,
    addrs: &[AddressInput],
) -> Result<(), rimap_core::RimapError> {
    for addr in addrs {
        validate_header_text(&format!("{field} address"), &addr.address)?;
        if let Some(name) = &addr.name {
            validate_header_text(&format!("{field} name"), name)?;
        }
    }
    Ok(())
}

/// Strip characters that could inject headers in Message-ID values.
pub(crate) fn sanitize_message_id(id: &str) -> String {
    id.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '<' | '>'))
        .collect()
}

/// Generate a Message-ID using the From address domain.
pub(crate) fn generate_message_id(from_addr: &str) -> String {
    let domain = from_addr.rsplit('@').next().unwrap_or("local");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}.{}@{domain}", std::process::id(), nanos)
}

/// Set From, To, CC, BCC, Subject, body, and Message-ID on a builder.
pub(crate) fn build_message_headers<'a>(
    from_addr: &'a str,
    input: &'a ComposeInput,
) -> MessageBuilder<'a> {
    let msg_id = generate_message_id(from_addr);
    let builder = MessageBuilder::new()
        .from(from_addr)
        .to(addresses_to_builder(&input.to))
        .subject(input.subject.as_str())
        .text_body(input.body_text.as_str())
        .message_id(msg_id);

    let builder = if let Some(cc) = &input.cc {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    if let Some(bcc) = &input.bcc {
        builder.bcc(addresses_to_builder(bcc))
    } else {
        builder
    }
}

fn addresses_to_builder(addrs: &[AddressInput]) -> Address<'_> {
    if addrs.len() == 1 {
        return single_address(&addrs[0]);
    }
    let list: Vec<Address<'_>> = addrs.iter().map(single_address).collect();
    Address::new_list(list)
}

fn single_address(addr: &AddressInput) -> Address<'_> {
    match &addr.name {
        Some(name) => Address::new_address(Some(name.as_str()), addr.address.as_str()),
        None => Address::new_address(None::<&str>, addr.address.as_str()),
    }
}

/// Truncate a References chain to at most `MAX_REFERENCES` entries.
pub(crate) fn cap_references(mut refs: Vec<String>) -> Vec<String> {
    if refs.len() <= MAX_REFERENCES {
        return refs;
    }
    let root = refs.remove(0);
    let keep_recent = MAX_REFERENCES - 1;
    let start = refs.len().saturating_sub(keep_recent);
    let mut result = Vec::with_capacity(MAX_REFERENCES);
    result.push(root);
    result.extend(refs.into_iter().skip(start));
    result
}

/// Fetch referenced message and set In-Reply-To / References headers.
pub(crate) async fn apply_threading_headers<'a>(
    server: &ImapMcpServer,
    builder: MessageBuilder<'a>,
    reply_uid: u32,
    in_reply_to_folder: Option<&str>,
) -> Result<MessageBuilder<'a>, rimap_core::RimapError> {
    let folder = in_reply_to_folder.unwrap_or("INBOX");
    let uid = rimap_imap::types::Uid::new(reply_uid).ok_or_else(|| {
        rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "in_reply_to_uid must be non-zero".into(),
        }
    })?;

    let raw = server.imap.fetch_body(folder, uid).await?;
    let parsed = mail_parser::MessageParser::new()
        .parse(&raw)
        .ok_or_else(|| {
            rimap_core::RimapError::Internal("failed to parse referenced message".into())
        })?;

    let Some(raw_msg_id) = parsed.message_id() else {
        return Ok(builder);
    };

    let msg_id = sanitize_message_id(raw_msg_id);
    let builder = builder.in_reply_to(msg_id.clone());

    let mut ref_ids: Vec<String> = Vec::new();
    match parsed.references() {
        mail_parser::HeaderValue::Text(t) => {
            ref_ids.push(sanitize_message_id(t));
        }
        mail_parser::HeaderValue::TextList(list) => {
            for r in list {
                ref_ids.push(sanitize_message_id(r));
            }
        }
        _ => {}
    }
    ref_ids.push(msg_id);
    let ref_ids = cap_references(ref_ids);

    let builder = builder.references(MessageId::new_list(ref_ids.into_iter()));

    Ok(builder)
}

/// Build raw RFC 5322 bytes from compose input, applying threading
/// if `in_reply_to_uid` is set.
pub(crate) async fn build_message(
    server: &ImapMcpServer,
    from_addr: &str,
    input: &ComposeInput,
) -> Result<Vec<u8>, rimap_core::RimapError> {
    let builder = build_message_headers(from_addr, input);

    let builder = if let Some(reply_uid) = input.in_reply_to_uid {
        Box::pin(apply_threading_headers(
            server,
            builder,
            reply_uid,
            input.in_reply_to_folder.as_deref(),
        ))
        .await?
    } else {
        builder
    };

    builder.write_to_vec().map_err(|e| {
        rimap_core::RimapError::Internal(format!("failed to build message: {e}"))
    })
}
```

- [ ] **Step 2: Register the module**

In `crates/rimap-server/src/tools/mod.rs`, add:

```rust
pub(crate) mod message_builder;
```

- [ ] **Step 3: Update `create_draft.rs` to use shared module**

Replace the local types, validation, and builder functions with imports from `message_builder`. The `CreateDraftInput` type becomes an alias for `ComposeInput`, and the `handle` function calls `message_builder::build_message` instead of the local `build_draft`.

Key changes in `create_draft.rs`:

- Remove `AddressInput` struct → import from `message_builder`
- Remove `validate_draft_input`, `validate_header_text`, `validate_addresses`, `sanitize_message_id`, `build_message_headers`, `addresses_to_builder`, `single_address`, `generate_message_id`, `cap_references`, `apply_threading_headers`, `build_draft`, and all `MAX_*` constants
- Change `CreateDraftInput` to be a type alias: `pub type CreateDraftInput = super::message_builder::ComposeInput;`
- Update `handle` to call `message_builder::validate_compose_input` and `message_builder::build_message`

The updated `handle`:

```rust
pub async fn handle(
    server: &ImapMcpServer,
    input: CreateDraftInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    super::message_builder::validate_compose_input(&input)?;
    let from_addr = &server.config.config.imap.username;
    let raw_msg = super::message_builder::build_message(server, from_addr, &input).await?;

    let drafts_folder = "Drafts";
    let result = server
        .imap
        .append_message(
            drafts_folder,
            &raw_msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await?;

    let generated_msg_id = mail_parser::MessageParser::new()
        .parse(&raw_msg)
        .and_then(|m| m.message_id().map(ToString::to_string));

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": drafts_folder,
            "uid": result.uid.map(rimap_imap::types::Uid::get),
            "message_id": generated_msg_id,
            "keywords": ["$PendingReview"],
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 4: Run existing tests to verify no regression**

Run: `cargo test -p rimap-server -- --nocapture`
Expected: all existing `create_draft` tests pass. Move the unit tests from `create_draft.rs` to `message_builder.rs` (they test the shared functions, not the handler).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/message_builder.rs crates/rimap-server/src/tools/create_draft.rs crates/rimap-server/src/tools/mod.rs
git commit -m "refactor(server): extract message_builder from create_draft

Shared message construction for both create_draft and send_email.
No behavioral change."
```

---

## Task 2: Add `send_email` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/send_email.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`
- Modify: `crates/rimap-server/Cargo.toml`

- [ ] **Step 1: Add `rimap-smtp` dependency**

In `crates/rimap-server/Cargo.toml`, add to `[dependencies]`:

```toml
rimap-smtp = { path = "../rimap-smtp", version = "0.0.0" }
```

- [ ] **Step 2: Register module**

In `crates/rimap-server/src/tools/mod.rs`:

```rust
pub mod send_email;
```

- [ ] **Step 3: Create `send_email.rs`**

```rust
//! `send_email` tool handler: compose and send via SMTP, then APPEND
//! a copy to the Sent folder.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;
use crate::tools::message_builder::{self, ComposeInput};

/// Input for `send_email` — identical fields to `create_draft`.
pub type SendEmailInput = ComposeInput;

/// `send_email` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: SendEmailInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;

    let smtp_config = server.config.config.smtp.as_ref().ok_or_else(|| {
        rimap_core::RimapError::Config(
            "send_email requires [smtp] configuration".into(),
        )
    })?;

    let from_addr = &server.config.config.imap.username;
    let raw_msg = message_builder::build_message(server, from_addr, &input).await?;

    // Build lettre Message from raw bytes
    let lettre_msg = lettre::Message::from(raw_msg.clone());

    // Resolve SMTP credential and build client
    let password = rimap_config::resolve_credential(
        &rimap_config::KeyringStore,
        &smtp_config.username,
        &smtp_config.host,
    )
    .map_err(|e| rimap_core::RimapError::Config(format!("SMTP credential: {e}")))?;

    let client = rimap_smtp::SmtpClient::new(smtp_config, &password)?;

    // Send via SMTP
    let smtp_response = client.send(&lettre_msg).await?;

    // Extract Message-ID for the response
    let generated_msg_id = mail_parser::MessageParser::new()
        .parse(&raw_msg)
        .and_then(|m| m.message_id().map(ToString::to_string));

    // Best-effort: APPEND copy to Sent folder
    let sent_folder = "Sent";
    let sent_uid = match server
        .imap
        .append_message(sent_folder, &raw_msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
    {
        Ok(result) => result.uid.map(rimap_imap::types::Uid::get),
        Err(e) => {
            tracing::warn!("failed to append to Sent folder: {e}");
            None
        }
    };

    Ok(ToolResponse {
        meta: serde_json::json!({
            "sent": true,
            "message_id": generated_msg_id,
            "smtp_response": smtp_response,
            "sent_copy": {
                "folder": sent_folder,
                "uid": sent_uid,
            },
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

Note: The `lettre::Message::from(raw_msg)` construction may need adjustment depending on the exact lettre API. If lettre doesn't support constructing from raw bytes directly, parse the raw RFC 5322 into lettre's builder. Research the lettre API at implementation time and adapt.

- [ ] **Step 4: Run build**

Run: `cargo build -p rimap-server 2>&1 | head -30`
Expected: compiles (may need adjustments to the lettre Message construction).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/Cargo.toml crates/rimap-server/src/tools/send_email.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add send_email tool handler

Composes RFC 5322 message via shared builder, sends via rimap-smtp,
appends copy to Sent folder. Best-effort Sent copy — failure logged
but does not fail the send."
```

---

## Task 3: Add `delete_message` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/delete_message.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Register module**

In `crates/rimap-server/src/tools/mod.rs`:

```rust
pub mod delete_message;
```

- [ ] **Step 2: Create `delete_message.rs`**

```rust
//! `delete_message` tool handler: flag as \Deleted and move to Trash.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `delete_message`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteMessageInput {
    /// Source folder containing the message.
    pub folder: String,
    /// UID of the message to delete.
    pub uid: u32,
}

/// `delete_message` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: DeleteMessageInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uid = rimap_imap::types::Uid::new(input.uid).ok_or_else(|| {
        rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "uid must be non-zero".into(),
        }
    })?;

    let trash_folder = "Trash";
    let result = server
        .imap
        .delete_message(&input.folder, uid, trash_folder)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "source_folder": input.folder,
            "uid": input.uid,
            "moved_to_trash": result.moved_to_trash,
            "trash_folder": trash_folder,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 3: Run build**

Run: `cargo build -p rimap-server 2>&1 | head -20`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/delete_message.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add delete_message tool handler"
```

---

## Task 4: Add `expunge` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/expunge.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Register module and create handler**

In `crates/rimap-server/src/tools/mod.rs`:

```rust
pub mod expunge;
```

Create `crates/rimap-server/src/tools/expunge.rs`:

```rust
//! `expunge` tool handler: permanently remove \Deleted messages from a folder.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `expunge`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpungeInput {
    /// Folder to expunge.
    pub folder: String,
}

/// `expunge` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: ExpungeInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // Folder allowlist check
    server
        .folder_guard
        .check_expunge(&input.folder)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    let (deleted_uids, expunged_count) =
        server.imap.expunge(&input.folder).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "expunged_count": expunged_count,
            "deleted_uids_before_expunge": deleted_uids
                .iter()
                .map(|u| u.get())
                .collect::<Vec<_>>(),
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 2: Run build and commit**

```bash
cargo build -p rimap-server
git add crates/rimap-server/src/tools/expunge.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add expunge tool handler with folder allowlist check"
```

---

## Task 5: Add folder management tool handlers

**Files:**
- Create: `crates/rimap-server/src/tools/folder_mgmt.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Register module**

In `crates/rimap-server/src/tools/mod.rs`:

```rust
pub mod folder_mgmt;
```

- [ ] **Step 2: Create `folder_mgmt.rs`**

```rust
//! Folder management tool handlers: create, rename, delete.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `create_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFolderInput {
    /// Name of the folder to create.
    pub name: String,
}

/// Input for `rename_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFolderInput {
    /// Current folder name.
    pub old_name: String,
    /// New folder name.
    pub new_name: String,
}

/// Input for `delete_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFolderInput {
    /// Name of the folder to delete.
    pub name: String,
}

/// `create_folder` handler.
pub async fn handle_create(
    server: &ImapMcpServer,
    input: CreateFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // Reject names matching protected folders
    let protected = &server.config.config.security.protected_folders;
    if protected
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&input.name))
    {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: format!(
                "cannot create folder `{}`: name collides with a protected folder",
                input.name
            ),
        });
    }

    server.imap.create_folder(&input.name).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "created": true,
            "folder": input.name,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `rename_folder` handler.
pub async fn handle_rename(
    server: &ImapMcpServer,
    input: RenameFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // Protected folder check on old_name
    server
        .folder_guard
        .check_protected(&input.old_name, "rename")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    server
        .imap
        .rename_folder(&input.old_name, &input.new_name)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "renamed": true,
            "old_name": input.old_name,
            "new_name": input.new_name,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `delete_folder` handler.
pub async fn handle_delete(
    server: &ImapMcpServer,
    input: DeleteFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // Protected folder check
    server
        .folder_guard
        .check_protected(&input.name, "delete")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    // Expunge allowlist check (reuses same list)
    server
        .folder_guard
        .check_expunge(&input.name)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    // Get message count for audit before deletion
    let status = server
        .imap
        .status(
            &input.name,
            rimap_imap::types::StatusItems {
                messages: true,
                ..Default::default()
            },
        )
        .await?;
    let message_count = status.messages.unwrap_or(0);

    server.imap.delete_folder(&input.name).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "folder": input.name,
            "message_count": message_count,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 3: Run build and commit**

```bash
cargo build -p rimap-server
git add crates/rimap-server/src/tools/folder_mgmt.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add create_folder, rename_folder, delete_folder handlers

Protected folder check on rename/delete. Expunge allowlist check
on delete_folder. Message count captured for audit before deletion."
```

---

## Task 6: Wire new tools into dispatch and tool definitions

**Files:**
- Modify: `crates/rimap-server/src/server.rs`

- [ ] **Step 1: Add dispatch arms**

In the `dispatch_tool` match in `server.rs`, add after the `CreateDraft` arm:

```rust
            ToolName::SendEmail => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::send_email::handle(self, input)).await
            }
            ToolName::DeleteMessage => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::delete_message::handle(self, input)).await
            }
            ToolName::Expunge => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::expunge::handle(self, input)).await
            }
            ToolName::CreateFolder => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::folder_mgmt::handle_create(self, input)).await
            }
            ToolName::RenameFolder => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::folder_mgmt::handle_rename(self, input)).await
            }
            ToolName::DeleteFolder => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::folder_mgmt::handle_delete(self, input)).await
            }
```

- [ ] **Step 2: Add tool definitions**

In the `tool_definition` function, add after the `CreateDraft` arm:

```rust
        ToolName::SendEmail => (
            "send_email",
            "Send an email via SMTP",
            schema_map::<crate::tools::send_email::SendEmailInput>(),
        ),
        ToolName::DeleteMessage => (
            "delete_message",
            "Delete a message (move to Trash)",
            schema_map::<crate::tools::delete_message::DeleteMessageInput>(),
        ),
        ToolName::Expunge => (
            "expunge",
            "Permanently remove deleted messages from a folder",
            schema_map::<crate::tools::expunge::ExpungeInput>(),
        ),
        ToolName::CreateFolder => (
            "create_folder",
            "Create a new IMAP folder",
            schema_map::<crate::tools::folder_mgmt::CreateFolderInput>(),
        ),
        ToolName::RenameFolder => (
            "rename_folder",
            "Rename an IMAP folder",
            schema_map::<crate::tools::folder_mgmt::RenameFolderInput>(),
        ),
        ToolName::DeleteFolder => (
            "delete_folder",
            "Delete an IMAP folder and all its contents",
            schema_map::<crate::tools::folder_mgmt::DeleteFolderInput>(),
        ),
```

- [ ] **Step 3: Update tests**

Update `tool_definition_covers_all_mcp_tools`:

```rust
#[test]
fn tool_definition_covers_all_mcp_tools() {
    let defs: Vec<_> = ToolName::all()
        .into_iter()
        .filter_map(tool_definition)
        .collect();
    // 19 capabilities minus 2 sub-capabilities = 17 MCP tools
    assert_eq!(defs.len(), 17);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server -- --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/server.rs
git commit -m "feat(server): wire 6 v2 tools into dispatch and tool_definition

send_email, delete_message, expunge, create_folder, rename_folder,
delete_folder all routed through the standard dispatch pipeline."
```

---

## Task 7: Add SMTP sink container for integration tests

**Files:**
- Create: `crates/rimap-imap/tests/integration/smtp/docker-compose.yml`

This task adds a MailHog (or smtp4dev) container to the integration test harness for testing `send_email` end-to-end. The SMTP sink accepts messages, stores them in memory, and never delivers.

- [ ] **Step 1: Research current SMTP sink containers**

Look up the latest stable version of `mailhog/MailHog` or `rnwood/smtp4dev` on Docker Hub. Choose one that:
- Supports SMTP on a configurable port
- Has an HTTP API to query received messages
- Runs in Podman
- Is actively maintained

- [ ] **Step 2: Create the compose file**

Create `crates/rimap-imap/tests/integration/smtp/docker-compose.yml` with the SMTP sink alongside Dovecot. The exact content depends on which image is chosen. Template:

```yaml
services:
  smtp:
    image: docker.io/mailhog/mailhog:latest  # pin to specific tag
    container_name: ${COMPOSE_PROJECT_NAME:-rimap-it}-smtp
    ports:
      - "127.0.0.1:${RIMAP_SMTP_HOST_PORT}:1025"    # SMTP
      - "127.0.0.1:${RIMAP_SMTP_API_PORT}:8025"      # HTTP API
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8025"]
      interval: 1s
      timeout: 1s
      retries: 15
```

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/tests/integration/smtp/
git commit -m "infra: add SMTP sink container for send_email integration tests

MailHog (or smtp4dev) accepts messages without delivery.
HTTP API available for test assertions."
```

---

## Task 8: Final verification and lint

- [ ] **Step 1: Run full CI locally**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: clean.

- [ ] **Step 2: Run cargo deny**

Run: `cargo deny check 2>&1 | tail -20`
Expected: no new advisories from `lettre` or transitive deps.

- [ ] **Step 3: Verify all 19 tools appear in the matrix**

Run: `cargo test -p rimap-authz matrix_covers_every_tool -- --nocapture`
Expected: passes (19 tools × 4 postures all covered).

- [ ] **Step 4: Verify tool definitions cover all MCP tools**

Run: `cargo test -p rimap-server tool_definition_covers -- --nocapture`
Expected: 17 MCP tool definitions (19 capabilities - 2 sub-capabilities).

- [ ] **Step 5: Fix any issues and commit**

```bash
git add -u
git commit -m "fix: address lint and test issues from Sprint 2c"
```
