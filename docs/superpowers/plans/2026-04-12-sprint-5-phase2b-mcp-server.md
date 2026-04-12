# Sprint 5 Phase 2b — MCP Server Wiring + Tool Handlers

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the rmcp MCP server with stdio transport, a posture-driven tool dispatch chain, and 9 v1 tool handlers (all except `create_draft`).

**Architecture:** `ImapMcpServer` struct holds config, IMAP connection, authz matrix, rate limiter, circuit breaker, audit writer, and download dir. Tool dispatch follows a shared pipeline: authz → breaker → rate limit → audit ToolStart → execute → audit ToolEnd → response envelope. Each tool handler is a method on the server struct, registered via rmcp's `#[tool]` macro. Tools denied by posture are not registered (not advertised in `list_tools`).

**Tech Stack:** `rmcp 1.4` (stdio MCP server), `schemars 1.0` (input JSON Schema), `infer 0.19` (MIME sniffing), `sha2 0.11` (attachment hashing), `rimap-imap` (IMAP ops from Phase 2a), `rimap-authz` (posture matrix, rate limiter, circuit breaker), `rimap-audit` (ToolStart/ToolEnd records).

**Spec:** [`../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md`](../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md) §3

**Phase 2a handoff:** STORE, MOVE, APPEND ops and `parse_message_async` are implemented and tested.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `Cargo.toml` (root) | Add `rmcp`, `schemars`, `infer` to workspace deps |
| `crates/rimap-server/Cargo.toml` | Add dep references |
| `deny.toml` | Entries for new crates |
| `crates/rimap-server/src/main.rs` | Wire MCP server mode (replace placeholder) |
| `crates/rimap-server/src/server.rs` | `ImapMcpServer` struct, `ServerHandler` impl |
| `crates/rimap-server/src/dispatch.rs` | Shared dispatch pipeline (authz → breaker → rate limit → audit) |
| `crates/rimap-server/src/error.rs` | `RimapError` → rmcp `ErrorData` mapping |
| `crates/rimap-server/src/response.rs` | `meta`/`untrusted`/`security_warnings` envelope types |
| `crates/rimap-server/src/download.rs` | Attachment download sandboxing (tempdir, path validation, MIME sniff, SHA256) |
| `crates/rimap-server/src/tools/mod.rs` | Tool handler module, input/output types |
| `crates/rimap-server/src/tools/list_folders.rs` | `list_folders` tool handler |
| `crates/rimap-server/src/tools/search.rs` | `search` tool handler |
| `crates/rimap-server/src/tools/fetch_message.rs` | `fetch_message` tool handler |
| `crates/rimap-server/src/tools/list_attachments.rs` | `list_attachments` tool handler |
| `crates/rimap-server/src/tools/download_attachment.rs` | `download_attachment` tool handler |
| `crates/rimap-server/src/tools/flags.rs` | `mark_read`, `mark_unread`, `flag`, `unflag` handlers |
| `crates/rimap-server/src/tools/move_message.rs` | `move_message` tool handler |

---

### Task 1: Add workspace dependencies

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/rimap-server/Cargo.toml`
- Modify: `deny.toml`

- [ ] **Step 1: Add dependencies to root `Cargo.toml`**

Read `Cargo.toml` root, then add to `[workspace.dependencies]`:

```toml
rmcp = { version = "1.4", features = ["server", "macros", "transport-io"] }
schemars = "1.0"
infer = "0.19"
```

Note: `sha2` is already in the workspace deps.

- [ ] **Step 2: Add to `crates/rimap-server/Cargo.toml`**

Add under `[dependencies]`:

```toml
rmcp = { workspace = true }
schemars = { workspace = true }
infer = { workspace = true }
rimap-imap = { path = "../rimap-imap", version = "0.0.0" }
```

Note: `rimap-imap` is not yet a dependency of rimap-server — add it.

- [ ] **Step 3: Update `deny.toml`**

Read the existing `deny.toml` to understand the format. Add `skip-tree` entries if rmcp pulls duplicate transitive crates (likely for `http`, `hyper`, etc. from disabled features — verify with `cargo deny check` output). Add license exceptions if needed.

- [ ] **Step 4: Verify**

Run: `cargo check --package rimap-server && cargo deny check`
Expected: compiles, deny check passes.

- [ ] **Step 5: Commit**

```bash
git commit -m "chore(server): add rmcp, schemars, infer workspace dependencies"
```

---

### Task 2: Response envelope types

**Files:**
- Create: `crates/rimap-server/src/response.rs`

- [ ] **Step 1: Create response types**

The MCP tool response envelope has three top-level fields: `meta`, `untrusted`, `security_warnings`. Tools return JSON content via rmcp. Define the envelope:

```rust
//! Response envelope types for MCP tool responses.
//!
//! Every tool returns a JSON object with three top-level fields:
//! `meta` (trusted server metadata), `untrusted` (sanitized email
//! content), and `security_warnings` (structured observations).

use serde::Serialize;

/// Top-level tool response envelope.
#[derive(Debug, Serialize)]
pub struct ToolResponse {
    /// Server-controlled metadata. Trusted.
    pub meta: serde_json::Value,
    /// Sanitized content derived from email data. Untrusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<serde_json::Value>,
    /// Structured security observations. Trusted metadata.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<serde_json::Value>,
}
```

Use `serde_json::Value` for flexibility — tool handlers construct the specific shapes. This avoids a proliferation of per-tool output structs while keeping the envelope consistent.

- [ ] **Step 2: Wire module**

Add `mod response;` to `main.rs`.

- [ ] **Step 3: Verify**

Run: `cargo check --package rimap-server`

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(server): add ToolResponse envelope types"
```

---

### Task 3: Error mapping (RimapError → rmcp ErrorData)

**Files:**
- Create: `crates/rimap-server/src/error.rs`

- [ ] **Step 1: Create error mapping module**

Map `rimap_core::RimapError` to rmcp's `ErrorData`:

```rust
//! Map `RimapError` to rmcp `ErrorData` for MCP tool error responses.

use rimap_core::{ErrorCode, RimapError};
use rmcp::model::ErrorData;

/// Convert a `RimapError` into an rmcp `ErrorData`.
pub fn to_mcp_error(err: &RimapError) -> ErrorData {
    let code = err.code();
    let message = err.to_string();

    // Map ErrorCode to appropriate rmcp error codes.
    // rmcp uses JSON-RPC error codes (-32xxx) plus custom ranges.
    match code {
        ErrorCode::InvalidInput => {
            ErrorData::invalid_params(message, None)
        }
        ErrorCode::PostureDenied => {
            ErrorData::new(-32001, message, None)
        }
        ErrorCode::RateLimited => {
            ErrorData::new(-32002, message, None)
        }
        ErrorCode::CircuitOpen => {
            ErrorData::new(-32003, message, None)
        }
        ErrorCode::NotFound => {
            ErrorData::new(-32004, message, None)
        }
        ErrorCode::ImapProtocol
        | ErrorCode::Tls
        | ErrorCode::Auth
        | ErrorCode::ConnectionLost
        | ErrorCode::Timeout => {
            ErrorData::internal_error(message, None)
        }
        ErrorCode::AttachmentTooLarge => {
            ErrorData::new(-32005, message, None)
        }
        ErrorCode::Config | ErrorCode::Internal => {
            ErrorData::internal_error(message, None)
        }
    }
}
```

Note: read rmcp's `ErrorData` API first to verify the constructor signatures. The above uses `ErrorData::new(code, message, data)`, `ErrorData::invalid_params(message, data)`, and `ErrorData::internal_error(message, data)`. Verify these exist.

- [ ] **Step 2: Wire module**

Add `mod error;` to `main.rs`. Note: this will conflict with the existing error handling via `anyhow`. The `error.rs` module is for MCP error mapping, not the server's own errors. Use a descriptive module name if needed (e.g., `mcp_error.rs`).

- [ ] **Step 3: Verify**

Run: `cargo check --package rimap-server`

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(server): add RimapError to MCP ErrorData mapping"
```

---

### Task 4: Dispatch pipeline

**Files:**
- Create: `crates/rimap-server/src/dispatch.rs`

- [ ] **Step 1: Create the dispatch wrapper**

The dispatch pipeline runs before and after every tool handler:

```rust
//! Shared tool dispatch pipeline.
//!
//! Every tool handler passes through this pipeline:
//! 1. Authz (posture matrix check)
//! 2. Circuit breaker
//! 3. Rate limiter
//! 4. Audit ToolStart
//! 5. Execute handler
//! 6. Audit ToolEnd
//! 7. Format response

use rimap_audit::AuditWriter;
use rimap_audit::record::{ToolEnd, ToolStart, ToolStatus};
use rimap_authz::breaker::CircuitBreaker;
use rimap_authz::guard::AuthzGuard;
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_core::RimapError;
use rimap_core::tool::ToolName;

use crate::response::ToolResponse;

/// Run the pre-call guard chain: posture → breaker → rate limit.
///
/// Returns `Ok(())` if all guards pass, or `Err(RimapError)` with
/// the first failure.
pub fn pre_call_guards(
    matrix: &EffectiveMatrix,
    breaker: &CircuitBreaker<impl rimap_authz::breaker::Clock>,
    governor: &Governor,
    tool: ToolName,
) -> Result<(), RimapError> {
    matrix.check(tool)?;
    breaker.pre_call()?;
    governor.check(tool)?;
    Ok(())
}
```

Note: read the actual `AuthzGuard`, `EffectiveMatrix`, `Governor`, and `CircuitBreaker` APIs to verify the method signatures. The above is a sketch — adapt to match the real types.

The audit ToolStart/ToolEnd records should be written by the server's call_tool method, not in this module. This module provides the guard chain.

- [ ] **Step 2: Wire module**

Add `mod dispatch;` to `main.rs`.

- [ ] **Step 3: Verify**

Run: `cargo check --package rimap-server`

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(server): add pre-call dispatch guard chain"
```

---

### Task 5: `ImapMcpServer` struct and `ServerHandler` impl

**Files:**
- Create: `crates/rimap-server/src/server.rs`

This is the core of Phase 2b. The server struct holds all shared state, and the `ServerHandler` trait impl wires rmcp.

- [ ] **Step 1: Define `ImapMcpServer`**

```rust
//! MCP server core: state, tool registration, and request dispatch.

use std::path::PathBuf;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_authz::breaker::CircuitBreaker;
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::validate::ValidatedConfig;
use rimap_imap::Connection;
use tokio::sync::Mutex;

/// Shared MCP server state.
pub struct ImapMcpServer {
    pub(crate) config: ValidatedConfig,
    pub(crate) imap: Connection,
    pub(crate) matrix: EffectiveMatrix,
    pub(crate) governor: Governor,
    pub(crate) breaker: CircuitBreaker<rimap_authz::breaker::SystemClock>,
    pub(crate) audit: AuditWriter,
    pub(crate) download_dir: PathBuf,
}
```

- [ ] **Step 2: Implement `ServerHandler`**

The `ServerHandler` trait requires `get_info`, `list_tools`, and `call_tool`. For `list_tools`, only advertise tools the posture matrix allows. For `call_tool`, run the dispatch pipeline (guards → audit → execute → audit → response).

Read the rmcp `ServerHandler` trait definition first. The `call_tool` implementation should:
1. Parse the tool name from `request.name`
2. Run `dispatch::pre_call_guards`
3. Write `ToolStart` audit record
4. Match on tool name and dispatch to the handler
5. On success: write `ToolEnd` with success, return the response
6. On error: write `ToolEnd` with error, return the MCP error
7. On breaker/rate-limit failure: report to breaker, return error

For `list_tools`, use `matrix.advertised()` to get allowed tool names, then build `Tool` objects with the tool name, description, and input schema. The input schema comes from `schemars` — each tool's input struct derives `JsonSchema`.

Note: rmcp's `#[tool_router]` macro auto-registers all tools. Since we need posture-driven selective registration, we may need to implement `call_tool` manually instead of using the macro. Read the rmcp API to determine if `ToolRouter` supports filtering, or if we need manual dispatch.

**Alternative approach (likely simpler):** Implement `call_tool` manually with a match on tool name, and `list_tools` manually using `matrix.advertised()`. This avoids fighting the macro system for dynamic registration.

- [ ] **Step 3: Wire module and update `main.rs`**

Add `mod server;` to `main.rs`. Replace the placeholder error in the server mode branch with actual server startup:

```rust
// Server mode: build and start MCP server.
let config_path = resolve_cli_config_path(&cli)?;
let raw = load_from_path(&config_path)
    .with_context(|| format!("loading config {}", config_path.display()))?;
let validated = validate(raw).context("validating config")?;
let audit = audit_init::init_audit_writer(&validated, &config_path)?;

// Build server components
let matrix = EffectiveMatrix::from_validated(&validated);
let governor = Governor::new(
    validated.config.limits.commands_per_second,
    validated.config.limits.drafts_per_minute,
)?;
let breaker = CircuitBreaker::new(SystemClock, BreakerConfig::default());

// Connect to IMAP
let conn_cfg = /* build ConnectionConfig from validated */;
let imap = Connection::new(conn_cfg, audit.clone(), credentials);

// Resolve download dir
let download_dir = if validated.config.attachments.download_dir.is_empty() {
    tempfile::tempdir()?.into_path()
} else {
    PathBuf::from(&validated.config.attachments.download_dir)
};

let server = ImapMcpServer {
    config: validated,
    imap,
    matrix,
    governor,
    breaker,
    audit,
    download_dir,
};

// Start stdio MCP server
let rt = tokio::runtime::Runtime::new()?;
rt.block_on(async {
    let (stdin, stdout) = rmcp::transport::io::stdio();
    rmcp::service::serve_server(server, (stdin, stdout)).await
})?;
```

Note: `main` is currently sync. Either make it `#[tokio::main] async fn main()` or use `rt.block_on`. Read the current `main.rs` and adapt — it currently uses a sync `fn main() -> ExitCode` pattern. The tokio runtime is already a dependency.

- [ ] **Step 4: Verify**

Run: `cargo check --package rimap-server`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(server): add ImapMcpServer struct and ServerHandler impl"
```

---

### Task 6: `list_folders` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/mod.rs`
- Create: `crates/rimap-server/src/tools/list_folders.rs`

- [ ] **Step 1: Create `tools/mod.rs`**

```rust
//! MCP tool handlers. Each module implements one v1 tool.

pub mod list_folders;
```

- [ ] **Step 2: Implement `list_folders` handler**

```rust
//! `list_folders` tool handler.

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::server::ImapMcpServer;
use crate::response::ToolResponse;

/// Input for `list_folders`. No parameters required.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ListFoldersInput {}

/// A single folder in the response.
#[derive(Debug, Serialize)]
struct FolderEntry {
    name: String,
    delimiter: Option<char>,
    flags: Vec<String>,
    exists: Option<u32>,
    unseen: Option<u32>,
    uid_validity: Option<u32>,
}

/// Execute the `list_folders` tool.
pub async fn handle(
    server: &ImapMcpServer,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let folders = server.imap.list_folders("*").await?;

    let mut entries = Vec::with_capacity(folders.len());
    for folder in &folders {
        // Get STATUS for each folder
        let status = server.imap
            .status(
                &folder.name,
                rimap_imap::types::StatusItems::all(),
            )
            .await?;

        entries.push(FolderEntry {
            name: folder.name.clone(),
            delimiter: folder.delimiter,
            flags: folder.attributes.clone(),
            exists: status.messages,
            unseen: status.unseen,
            uid_validity: status.uid_validity,
        });
    }

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folders": serde_json::to_value(&entries)?,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

Note: `serde_json::to_value` returns `Result` — handle the error by mapping to `RimapError::Internal`. Folder names should go through unicode sanitization per the spec — use `rimap_content::unicode::sanitize` if the function is public, or defer to Phase 2d cleanup.

- [ ] **Step 3: Wire module and add `tools` to `main.rs`**

Add `mod tools;` to `main.rs`.

- [ ] **Step 4: Verify**

Run: `cargo check --package rimap-server`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(server): implement list_folders tool handler"
```

---

### Task 7: `search` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/search.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement `search` handler**

Input struct with all fields from spec §5 `search`:
- `folder` (required)
- `from`, `to`, `cc`, `subject`, `body` (optional substring match)
- `since`, `before` (optional ISO dates)
- `seen`, `flagged`, `has_attachment` (optional booleans)
- `advanced_query` (optional raw IMAP SEARCH — requires `full` posture, guarded by `SearchAdvanced` tool check)
- `limit` (optional, default 100, max capped)
- `offset` (optional, default 0)

The handler:
1. Build `StructuredQuery` from input fields
2. If `advanced_query` is present, check `matrix.check(ToolName::SearchAdvanced)` — return `ERR_POSTURE_DENIED` if denied
3. IMAP SEARCH → UIDs
4. FETCH ENVELOPE + FLAGS + SIZE for matched UIDs (paginated)
5. Header-only sanitization via `parse_message_async` or lighter weight header extraction
6. Return response with `meta.total_matched`, `meta.truncated`, `untrusted.messages[]`

Note: search returns headers only, never body content. The handler should use FETCH ENVELOPE (already implemented in rimap-imap) rather than fetching full BODY[] and parsing. The lookalike scan on headers is deferred — it requires fetching the full message for `parse_message`, which is expensive for search results. Start with just ENVELOPE data, formatted into the response.

- [ ] **Step 2: Wire in `tools/mod.rs`**

- [ ] **Step 3: Verify and commit**

```bash
git commit -m "feat(server): implement search tool handler"
```

---

### Task 8: `fetch_message` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/fetch_message.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement `fetch_message` handler**

Input: `folder`, `uid`, `include_html` (optional bool), `max_body_bytes` (optional usize).

The handler:
1. If `include_html=true`, check `matrix.check(ToolName::FetchMessageHtml)` — return `ERR_POSTURE_DENIED` if denied
2. IMAP FETCH BODY[] via `server.imap.fetch_body(folder, uid)`
3. `parse_message_async(raw)` → `Content`
4. Build response from `Content`: meta (folder, uid, message_id, size), untrusted (headers, common_headers, body_text, body_html if allowed, attachments), security_warnings
5. If `max_body_bytes` is set, truncate `body_text` and `body_html` and set `meta.truncated = true`

This is the most complex handler because it uses the full content pipeline.

- [ ] **Step 2: Wire and commit**

```bash
git commit -m "feat(server): implement fetch_message tool handler"
```

---

### Task 9: `list_attachments` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/list_attachments.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement `list_attachments` handler**

Input: `folder`, `uid`.

The handler:
1. IMAP FETCH BODYSTRUCTURE via `server.imap.fetch(folder, &[uid], FetchSpec { bodystructure: true, .. })`
2. Walk the `BodyStructure` tree to extract attachment metadata (part_id, filename, mime_type, size)
3. Filenames through `rimap_content::parse::sanitize_filename` if public, otherwise sanitize in-place
4. Return response with `untrusted.attachments[]`

- [ ] **Step 2: Wire and commit**

```bash
git commit -m "feat(server): implement list_attachments tool handler"
```

---

### Task 10: Attachment download sandboxing

**Files:**
- Create: `crates/rimap-server/src/download.rs`

- [ ] **Step 1: Implement download sandboxing**

```rust
//! Attachment download sandboxing: path validation, filename
//! de-duplication, MIME sniffing, and SHA-256 hashing.

use std::path::{Path, PathBuf};

use rimap_core::RimapError;

/// Resolve and validate the destination path for an attachment download.
///
/// If `dest_dir` is provided, canonicalize it and verify it starts
/// with `allowed_root`. If not provided, use `fallback_dir`.
///
/// Returns `Err(RimapError)` on path traversal attempts.
pub fn resolve_dest_dir(
    dest_dir: Option<&str>,
    allowed_root: &Path,
    fallback_dir: &Path,
) -> Result<PathBuf, RimapError> {
    // ...
}

/// Write `data` to `dir/filename`, de-duplicating on collision.
/// Returns the final path.
pub fn write_attachment(
    dir: &Path,
    filename: &str,
    data: &[u8],
) -> Result<PathBuf, RimapError> {
    // De-duplicate: try filename, then filename_1, filename_2, etc.
    // ...
}

/// MIME-sniff `data` and return the detected type.
pub fn sniff_mime(data: &[u8]) -> Option<String> {
    infer::get(data).map(|t| t.mime_type().to_string())
}

/// SHA-256 hash of `data`, returned as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex::encode(hash)
}
```

- [ ] **Step 2: Add unit tests**

Test `resolve_dest_dir` with:
- Valid path within allowed root
- Path traversal attempt (`../../../etc/passwd`)
- No dest_dir provided (returns fallback)

Test `write_attachment` with:
- Normal write
- Collision de-duplication

Test `sha256_hex` with a known hash.

- [ ] **Step 3: Wire module**

Add `mod download;` to `main.rs`.

- [ ] **Step 4: Verify and commit**

```bash
git commit -m "feat(server): add attachment download sandboxing"
```

---

### Task 11: `download_attachment` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/download_attachment.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement `download_attachment` handler**

Input: `folder`, `uid`, `part_id`, `dest_dir` (optional).

The handler:
1. Resolve destination via `download::resolve_dest_dir`
2. FETCH BODY[part_id] — this requires a new method or using `fetch_body` with a part specifier. Check if rimap-imap supports fetching individual parts. If not, fetch the full BODY[] and extract the part via rimap-content's MIME walk.
3. Get filename from BODYSTRUCTURE metadata → `sanitize_filename`
4. `download::write_attachment` to write to disk
5. `download::sniff_mime` for MIME detection
6. `download::sha256_hex` for integrity hash
7. Return meta (path, size, sha256, mime_type_declared, mime_type_sniffed) + untrusted (filename_original)

Note: FETCH BODY[part_id] is not yet implemented in rimap-imap. Options:
a) Add a `fetch_part(folder, uid, part_id)` method to rimap-imap
b) Fetch the full BODY[] and extract the part in the handler

Option (a) is preferred for efficiency. If time-constrained, option (b) works since the body is already capped by `max_fetch_body_bytes`.

- [ ] **Step 2: Wire and commit**

```bash
git commit -m "feat(server): implement download_attachment tool handler"
```

---

### Task 12: Flag tool handlers (mark_read, mark_unread, flag, unflag)

**Files:**
- Create: `crates/rimap-server/src/tools/flags.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement flag handlers**

All four share the same pattern:

```rust
//! Flag mutation tool handlers: mark_read, mark_unread, flag, unflag.

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use rimap_imap::types::{Flag, FlagAction};

use crate::server::ImapMcpServer;
use crate::response::ToolResponse;

/// Input for flag mutation tools. Accepts a single UID or a batch.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlagInput {
    /// Target folder.
    pub folder: String,
    /// Single UID (mutually exclusive with `uids`).
    pub uid: Option<u32>,
    /// Batch of UIDs (≤100).
    pub uids: Option<Vec<u32>>,
}

pub async fn handle_mark_read(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    handle_flag(server, input, &[Flag::Seen], FlagAction::Add).await
}

pub async fn handle_mark_unread(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    handle_flag(server, input, &[Flag::Seen], FlagAction::Remove).await
}

pub async fn handle_flag(
    server: &ImapMcpServer,
    input: FlagInput,
    flags: &[Flag],
    action: FlagAction,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uids = resolve_uids(&input)?;
    let updated = server.imap
        .store_flags(&input.folder, &uids, flags, action)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uids_updated": updated.iter()
                .map(|u| u.get())
                .collect::<Vec<_>>(),
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Resolve `uid` or `uids` from input to a Vec<Uid>.
fn resolve_uids(input: &FlagInput) -> Result<Vec<rimap_imap::types::Uid>, rimap_core::RimapError> {
    match (&input.uid, &input.uids) {
        (Some(uid), None) => {
            let u = rimap_imap::types::Uid::new(*uid)
                .ok_or_else(|| rimap_core::RimapError::Internal(
                    "UID must be non-zero".into()
                ))?;
            Ok(vec![u])
        }
        (None, Some(uids)) => {
            let mut result = Vec::with_capacity(uids.len());
            for &uid in uids {
                let u = rimap_imap::types::Uid::new(uid)
                    .ok_or_else(|| rimap_core::RimapError::Internal(
                        "UID must be non-zero".into()
                    ))?;
                result.push(u);
            }
            Ok(result)
        }
        (Some(_), Some(_)) => Err(rimap_core::RimapError::Internal(
            "provide uid or uids, not both".into(),
        )),
        (None, None) => Err(rimap_core::RimapError::Internal(
            "provide uid or uids".into(),
        )),
    }
}
```

- [ ] **Step 2: Wire in `tools/mod.rs`**

- [ ] **Step 3: Verify and commit**

```bash
git commit -m "feat(server): implement flag mutation tool handlers"
```

---

### Task 13: `move_message` tool handler

**Files:**
- Create: `crates/rimap-server/src/tools/move_message.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Implement `move_message` handler**

Input: `source_folder`, `dest_folder`, `uid` or `uids` (≤100).

Reuse `resolve_uids` from `flags.rs` (move it to `tools/mod.rs` or a shared module).

```rust
pub async fn handle(
    server: &ImapMcpServer,
    input: MoveInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let results = server.imap
        .move_messages(&input.source_folder, &input.dest_folder, &uids)
        .await?;

    let moves: Vec<_> = results.iter().map(|r| {
        serde_json::json!({
            "old_uid": r.old_uid.get(),
            "new_uid": r.new_uid.map(|u| u.get()),
        })
    }).collect();

    Ok(ToolResponse {
        meta: serde_json::json!({
            "source_folder": input.source_folder,
            "dest_folder": input.dest_folder,
            "moves": moves,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 2: Wire and commit**

```bash
git commit -m "feat(server): implement move_message tool handler"
```

---

### Task 14: Wire tool dispatch in `ServerHandler::call_tool`

**Files:**
- Modify: `crates/rimap-server/src/server.rs`

- [ ] **Step 1: Implement the `call_tool` dispatch**

In the `ServerHandler` impl, `call_tool` matches on the tool name and dispatches to the handler:

```rust
async fn call_tool(
    &self,
    request: CallToolRequestParams,
    context: RequestContext<RoleServer>,
) -> Result<CallToolResult, McpError> {
    let tool_name = ToolName::from_str(&request.name)
        .map_err(|e| McpError::from(
            ErrorData::invalid_params(e.to_string(), None)
        ))?;

    // Pre-call guards
    if let Err(e) = dispatch::pre_call_guards(
        &self.matrix, &self.breaker, &self.governor, tool_name,
    ) {
        self.breaker.on_failure(FailureReason::Authz);
        return Err(McpError::from(error::to_mcp_error(&e)));
    }

    // Parse arguments
    let args = request.arguments.unwrap_or_default();

    // Dispatch to handler
    let result = match tool_name {
        ToolName::ListFolders => {
            tools::list_folders::handle(self).await
        }
        ToolName::Search | ToolName::SearchAdvanced => {
            let input = serde_json::from_value(
                serde_json::Value::Object(args)
            ).map_err(/* ... */)?;
            tools::search::handle(self, input).await
        }
        ToolName::FetchMessage | ToolName::FetchMessageHtml => {
            let input = serde_json::from_value(
                serde_json::Value::Object(args)
            ).map_err(/* ... */)?;
            tools::fetch_message::handle(self, input).await
        }
        // ... etc for all tools
        ToolName::CreateDraft => {
            // Phase 2c — should not be registered
            return Err(McpError::from(
                ErrorData::internal_error("not implemented", None)
            ));
        }
    };

    match result {
        Ok(response) => {
            self.breaker.on_success();
            let json = serde_json::to_string(&response)
                .map_err(/* ... */)?;
            Ok(CallToolResult::text_content(json, None))
        }
        Err(e) => {
            self.breaker.on_failure(FailureReason::Imap);
            Err(McpError::from(error::to_mcp_error(&e)))
        }
    }
}
```

Note: this is a sketch. The exact rmcp types (`CallToolRequestParams`, `CallToolResult`, `McpError`, `RequestContext`) need to be verified against the actual rmcp API. Read the rmcp source to confirm.

- [ ] **Step 2: Implement `list_tools`**

```rust
async fn list_tools(
    &self,
    _request: Option<PaginatedRequestParams>,
    _context: RequestContext<RoleServer>,
) -> Result<ListToolsResult, McpError> {
    let allowed = self.matrix.advertised();
    let tools: Vec<Tool> = allowed.iter()
        .filter_map(|tn| tool_definition(*tn))
        .collect();
    Ok(ListToolsResult::with_all_items(tools))
}
```

Where `tool_definition(tn)` returns a `Tool` with name, description, and input schema. The input schemas come from `schemars` — each tool's input struct can generate its schema via `schemars::schema_for!(InputType)`.

- [ ] **Step 3: Verify and commit**

```bash
git commit -m "feat(server): wire tool dispatch in ServerHandler::call_tool"
```

---

### Task 15: Update `main.rs` for MCP server mode

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Replace the placeholder error with actual server startup**

The current `main.rs` server mode branch returns `Err("MCP server mode is not implemented")`. Replace it with the actual startup sequence from Task 5's outline.

Key decisions:
- Make `fn main()` stay sync, use `tokio::runtime::Runtime::new()?.block_on(...)` for the MCP server
- OR make `main` async with `#[tokio::main]` — this is simpler but changes the existing pattern
- Write `ProcessStart` audit record at startup, `ProcessEnd` at shutdown

- [ ] **Step 2: Handle shutdown gracefully**

On stdin close (MCP client disconnect), write `ProcessEnd` audit record and clean up tempdir if session-created.

- [ ] **Step 3: Verify and commit**

```bash
git commit -m "feat(server): wire MCP server startup in main.rs"
```

---

### Task 16: Run `just ci` and verify

**Files:** none (verification only)

- [ ] **Step 1: Run the full CI suite**

Run: `just ci`
Expected: all tests pass, no warnings, `cargo deny check` clean.

- [ ] **Step 2: Commit any fixups**

Fix formatting, clippy, or deny issues. Commit with `fix:` prefix.

---

## Notes for implementers

### rmcp API patterns

- `ServerHandler` trait requires `get_info()`, `list_tools()`, `call_tool()`
- `CallToolResult::text_content(text, None)` for text responses
- `ErrorData::invalid_params(msg, None)` for input errors
- `ErrorData::internal_error(msg, None)` for server errors
- `rmcp::transport::io::stdio()` returns `(stdin, stdout)` for stdio transport
- `rmcp::service::serve_server(handler, transport)` starts the server

### Posture-driven registration

The key design choice is that tools denied by posture are NOT advertised. `list_tools` only returns tools for which `matrix.check(tool).is_ok()`. Sub-capabilities (`SearchAdvanced`, `FetchMessageHtml`) are checked at call time, not at registration time — the parent tool (`Search`, `FetchMessage`) is registered, and the sub-capability is guarded inside the handler.

### `serde_json::Value` vs typed responses

Use `serde_json::Value` for response construction to avoid a proliferation of output structs. The `ToolResponse` envelope wraps `meta`, `untrusted`, and `security_warnings` as `Value` / `Vec<Value>`. This keeps the code DRY while maintaining the spec's three-field structure.

### Audit records

`ToolStart` and `ToolEnd` records use the existing `rimap_audit::record` types. The `ToolStart` record includes the tool name and redacted arguments. The `ToolEnd` record includes the paired `ToolStart` seq, tool name, status (success/error), and provenance snapshot. Read `crates/rimap-audit/src/record.rs` for exact field shapes.
