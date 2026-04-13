# Sprint 3a: Label Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three IMAP keyword label tools (`add_label`, `remove_label`, `list_labels`) to the MCP server, expanding the tool surface from 19 to 22 variants.

**Architecture:** Labels map to standard IMAP keywords via the existing `STORE +FLAGS`/`-FLAGS` and `FETCH FLAGS` commands. The `rimap-imap` crate already has `store_flags` with `Flag::Keyword(String)` support. New tool handlers in `rimap-server` validate label input, delegate to `Connection::store_flags` or `Connection::fetch`, and filter system flags from results.

**Tech Stack:** Rust, async-imap (via rimap-imap), rmcp, schemars, serde

**Depends on:** Nothing — lands independently on a feature branch off `main`.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-core/src/tool.rs` | Add `AddLabel`, `RemoveLabel`, `ListLabels` variants |
| Modify | `crates/rimap-core/src/posture_matrix.rs` | Expand `POSTURE_MATRIX` to 22 rows |
| Modify | `crates/rimap-authz/src/matrix.rs` | Update test expectations for 22 tools |
| Create | `crates/rimap-server/src/tools/labels.rs` | Label tool handlers + input validation |
| Modify | `crates/rimap-server/src/tools/mod.rs` | Register `labels` module |
| Modify | `crates/rimap-server/src/server.rs` | Add dispatch arms + tool definitions |
| Modify | `crates/rimap-audit/src/redact.rs` | Add redaction schemas for 3 label tools |

---

## Task 1: Add label `ToolName` variants

**Files:**
- Modify: `crates/rimap-core/src/tool.rs`
- Modify: `crates/rimap-core/src/posture_matrix.rs`

- [ ] **Step 1: Add three variants to `ToolName`**

In `crates/rimap-core/src/tool.rs`, add three variants to the `ToolName` enum after `Unflag`:

```rust
    Unflag,
    AddLabel,
    RemoveLabel,
    ListLabels,
    MoveMessage,
```

Add the corresponding `as_str()` arms:

```rust
    Self::AddLabel => "add_label",
    Self::RemoveLabel => "remove_label",
    Self::ListLabels => "list_labels",
```

- [ ] **Step 2: Update `POSTURE_MATRIX` to 22 rows**

In `crates/rimap-core/src/posture_matrix.rs`, change the const array size from 19 to 22 and add three rows after `Unflag`. `add_label` and `remove_label` are metadata mutations (same tier as `flag`), `list_labels` is read-only:

```rust
pub const POSTURE_MATRIX: [(ToolName, [bool; 4]); 22] = [
    // ... existing rows up through Unflag ...
    (ToolName::AddLabel,           [false, true,  true,  true ]),
    (ToolName::RemoveLabel,        [false, true,  true,  true ]),
    (ToolName::ListLabels,         [true,  true,  true,  true ]),
    (ToolName::MoveMessage,        [false, true,  true,  true ]),
    // ... remaining rows unchanged ...
];
```

- [ ] **Step 3: Run `cargo check --workspace` to verify compilation**

Run: `cargo check --workspace`
Expected: compiles successfully. Some tests may fail due to count assertions — that's expected, fixed in next task.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-core/src/tool.rs crates/rimap-core/src/posture_matrix.rs
git commit -m "feat(core): add AddLabel, RemoveLabel, ListLabels tool variants"
```

---

## Task 2: Update authz tests for 22-tool matrix

**Files:**
- Modify: `crates/rimap-authz/src/matrix.rs` (tests)
- Modify: `crates/rimap-server/src/server.rs` (tests)

- [ ] **Step 1: Update matrix test expectations**

In `crates/rimap-authz/src/matrix.rs`, find tests that assert on the number of tools (e.g. `advertised()` count tests). Update expectations:
- `Readonly` advertised count: was 7, now 8 (adds `ListLabels`)
- `DraftSafe` advertised count: was 13, now 16 (adds `AddLabel`, `RemoveLabel`, `ListLabels`)
- `Full` advertised count: was 17, now 20
- `Destructive` advertised count: was 19, now 22

Verify these counts by examining the existing tests. The exact numbers depend on how sub-capabilities (`SearchAdvanced`, `FetchMessageHtml`) are counted in the matrix — they ARE counted since `EffectiveMatrix` stores all 22 `ToolName` variants.

- [ ] **Step 2: Update server test expectations**

In `crates/rimap-server/src/server.rs`, update the `tool_definition_covers_all_mcp_tools` test. `tool_definition` returns `None` for sub-capabilities (`SearchAdvanced`, `FetchMessageHtml`). With 22 total variants minus 2 sub-capabilities = 20 MCP tools:

```rust
#[test]
fn tool_definition_covers_all_mcp_tools() {
    let defs: Vec<_> = ToolName::all()
        .into_iter()
        .filter_map(tool_definition)
        .collect();
    // 22 tool variants minus 2 sub-capabilities = 20
    assert_eq!(defs.len(), 20);
}
```

- [ ] **Step 3: Run `cargo test --workspace`**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-authz/src/matrix.rs crates/rimap-server/src/server.rs
git commit -m "test(authz,server): update expectations for 22-tool posture matrix"
```

---

## Task 3: Write label validation and tool handlers

**Files:**
- Create: `crates/rimap-server/src/tools/labels.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

- [ ] **Step 1: Write the failing tests for label validation**

Create `crates/rimap-server/src/tools/labels.rs` with validation logic and tests:

```rust
//! Label tool handlers: `add_label`, `remove_label`, `list_labels`.
//!
//! Labels are standard IMAP keywords (non-system flags). Validation
//! rejects system flags, backslash-prefixed strings, and IMAP atom
//! syntax violations.

use rimap_core::RimapError;
use rimap_imap::types::{Flag, FlagAction, Uid};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;
use crate::tools::flags::resolve_uids;

/// Maximum label length in bytes.
const MAX_LABEL_BYTES: usize = 256;

/// System flags that must not be set via label tools.
const SYSTEM_FLAGS: &[&str] = &[
    "\\Seen",
    "\\Answered",
    "\\Flagged",
    "\\Deleted",
    "\\Draft",
    "\\Recent",
];

/// Characters forbidden in IMAP atoms (RFC 9051 §4.1).
const ATOM_SPECIALS: &[char] = &[
    '(', ')', '{', ' ', '%', '*', '"', ']', '\\',
];

/// Input for `add_label` and `remove_label`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LabelInput {
    /// IMAP folder name.
    pub folder: String,
    /// Single message UID.
    pub uid: Option<u32>,
    /// Multiple message UIDs (max 100).
    pub uids: Option<Vec<u32>>,
    /// Keyword label to add or remove.
    pub label: String,
}

/// Input for `list_labels`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListLabelsInput {
    /// IMAP folder name.
    pub folder: String,
    /// Message UID.
    pub uid: u32,
}

/// Validate a label string.
fn validate_label(label: &str) -> Result<(), RimapError> {
    if label.is_empty() {
        return Err(RimapError::Internal(
            "label must not be empty".to_string(),
        ));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(RimapError::Internal(format!(
            "label exceeds {MAX_LABEL_BYTES} byte limit: {} bytes",
            label.len(),
        )));
    }
    if label.contains('\0') {
        return Err(RimapError::Internal(
            "label must not contain null bytes".to_string(),
        ));
    }
    if label.starts_with('\\') {
        return Err(RimapError::Internal(
            "label must not start with '\\' (reserved for system flags)"
                .to_string(),
        ));
    }
    if label.chars().any(|c| ATOM_SPECIALS.contains(&c)) {
        return Err(RimapError::Internal(
            "label contains characters invalid in IMAP atoms".to_string(),
        ));
    }
    if label.chars().any(|c| c.is_ascii_control()) {
        return Err(RimapError::Internal(
            "label must not contain control characters".to_string(),
        ));
    }
    for sys in SYSTEM_FLAGS {
        if label.eq_ignore_ascii_case(&sys[1..]) {
            return Err(RimapError::Internal(format!(
                "label '{}' conflicts with system flag {}",
                label, sys,
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_labels_pass() {
        assert!(validate_label("urgent").is_ok());
        assert!(validate_label("project-x").is_ok());
        assert!(validate_label("$PendingReview").is_ok());
        assert!(validate_label("$label1").is_ok());
    }

    #[test]
    fn empty_label_rejected() {
        assert!(validate_label("").is_err());
    }

    #[test]
    fn overlength_label_rejected() {
        let long = "a".repeat(257);
        assert!(validate_label(&long).is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_label("foo\0bar").is_err());
    }

    #[test]
    fn backslash_prefix_rejected() {
        assert!(validate_label("\\Custom").is_err());
    }

    #[test]
    fn system_flag_names_rejected() {
        assert!(validate_label("Seen").is_err());
        assert!(validate_label("seen").is_err());
        assert!(validate_label("Flagged").is_err());
        assert!(validate_label("Deleted").is_err());
        assert!(validate_label("Draft").is_err());
        assert!(validate_label("Answered").is_err());
        assert!(validate_label("Recent").is_err());
    }

    #[test]
    fn atom_special_chars_rejected() {
        assert!(validate_label("foo bar").is_err());
        assert!(validate_label("foo(bar)").is_err());
        assert!(validate_label("foo{bar}").is_err());
        assert!(validate_label("foo%bar").is_err());
        assert!(validate_label("foo*bar").is_err());
        assert!(validate_label("foo\"bar").is_err());
        assert!(validate_label("foo]bar").is_err());
    }

    #[test]
    fn control_chars_rejected() {
        assert!(validate_label("foo\x01bar").is_err());
        assert!(validate_label("foo\tbar").is_err());
    }

    #[test]
    fn max_length_label_accepted() {
        let exact = "a".repeat(256);
        assert!(validate_label(&exact).is_ok());
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/rimap-server/src/tools/mod.rs`, add:

```rust
pub mod labels;
```

- [ ] **Step 3: Run the validation tests**

Run: `cargo test -p rimap-server labels`
Expected: all validation tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/labels.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add label validation with unit tests"
```

---

## Task 4: Implement label tool handler functions

**Files:**
- Modify: `crates/rimap-server/src/tools/labels.rs`

The existing `Connection::store_flags` and `Connection::fetch` methods handle the IMAP layer. The handlers validate input, convert to `Flag::Keyword`, and delegate.

- [ ] **Step 1: Add `handle_add_label` and `handle_remove_label`**

Append to `crates/rimap-server/src/tools/labels.rs`, above the `#[cfg(test)]` block:

```rust
/// Handle `add_label` — STORE +FLAGS with a keyword.
pub async fn handle_add_label(
    server: &ImapMcpServer,
    input: LabelInput,
) -> Result<ToolResponse, RimapError> {
    validate_label(&input.label)?;
    let uids = resolve_uids(input.uid, input.uids)?;
    let flags = vec![Flag::Keyword(input.label.clone())];
    let updated = server
        .imap
        .store_flags(&input.folder, &uids, &flags, FlagAction::Add)
        .await?;
    let updated_ids: Vec<u32> = updated.iter().map(|u| u.0).collect();
    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "label": input.label,
            "uids_updated": updated_ids,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Handle `remove_label` — STORE -FLAGS with a keyword.
pub async fn handle_remove_label(
    server: &ImapMcpServer,
    input: LabelInput,
) -> Result<ToolResponse, RimapError> {
    validate_label(&input.label)?;
    let uids = resolve_uids(input.uid, input.uids)?;
    let flags = vec![Flag::Keyword(input.label.clone())];
    let updated = server
        .imap
        .store_flags(&input.folder, &uids, &flags, FlagAction::Remove)
        .await?;
    let updated_ids: Vec<u32> = updated.iter().map(|u| u.0).collect();
    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "label": input.label,
            "uids_updated": updated_ids,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 2: Add `handle_list_labels`**

`list_labels` fetches FLAGS for a single UID and filters out system flags. The `Connection::fetch` method with `FetchSpec::flags_only()` returns flags. Check how `FetchSpec` works and how flags are returned in `FetchedMessage`. The handler needs to filter to non-system flags:

```rust
/// Handle `list_labels` — fetch FLAGS and return non-system keywords.
pub async fn handle_list_labels(
    server: &ImapMcpServer,
    input: ListLabelsInput,
) -> Result<ToolResponse, RimapError> {
    let uid = Uid(input.uid);
    let messages = server
        .imap
        .fetch(
            &input.folder,
            &[uid],
            rimap_imap::types::FetchSpec::Envelope,
        )
        .await?;
    let msg = messages.into_iter().next().ok_or_else(|| {
        RimapError::Imap {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!(
                "message UID {} not found in {}",
                input.uid, input.folder,
            ),
            source: None,
        }
    })?;
    let labels: Vec<&str> = msg
        .flags
        .iter()
        .filter_map(|f| match f {
            Flag::Keyword(kw) => Some(kw.as_str()),
            _ => None,
        })
        .collect();
    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uid": input.uid,
            "labels": labels,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

Note: the exact `FetchSpec` variant and `FetchedMessage` field names may differ — check `crates/rimap-imap/src/types.rs` during implementation and adjust. The key point is: fetch the message's flags, filter to `Flag::Keyword` variants.

- [ ] **Step 3: Run `cargo check -p rimap-server`**

Run: `cargo check -p rimap-server`
Expected: compiles. May need import adjustments based on exact types in `rimap-imap`.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/labels.rs
git commit -m "feat(server): implement add_label, remove_label, list_labels handlers"
```

---

## Task 5: Wire label tools into dispatch and tool definitions

**Files:**
- Modify: `crates/rimap-server/src/server.rs`

- [ ] **Step 1: Add tool definitions**

In `crates/rimap-server/src/server.rs`, add a new `tool_spec_v3` function (following the `tool_spec_v1`/`tool_spec_v2` pattern):

```rust
/// Return (name, description, schema) for v3 label tools.
fn tool_spec_v3(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::labels::{LabelInput, ListLabelsInput};

    let tuple = match name {
        ToolName::AddLabel => (
            "add_label",
            "Add a keyword label to messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::RemoveLabel => (
            "remove_label",
            "Remove a keyword label from messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::ListLabels => (
            "list_labels",
            "List keyword labels on a message",
            schema_map::<ListLabelsInput>(),
        ),
        _ => return None,
    };
    Some(tuple)
}
```

Update `tool_definition` to chain `tool_spec_v3`:

```rust
fn tool_definition(name: ToolName) -> Option<Tool> {
    let (tool_name, description, schema) = tool_spec_v1(name)
        .or_else(|| tool_spec_v2(name))
        .or_else(|| tool_spec_v3(name))?;
    Some(Tool::new(tool_name, description, Arc::new(schema)))
}
```

- [ ] **Step 2: Add dispatch arms**

In `ImapMcpServer::dispatch_tool`, add three new arms:

```rust
    ToolName::AddLabel => {
        let input = parse_args(args)?;
        Box::pin(crate::tools::labels::handle_add_label(self, input)).await
    }
    ToolName::RemoveLabel => {
        let input = parse_args(args)?;
        Box::pin(crate::tools::labels::handle_remove_label(self, input)).await
    }
    ToolName::ListLabels => {
        let input = parse_args(args)?;
        Box::pin(crate::tools::labels::handle_list_labels(self, input)).await
    }
```

- [ ] **Step 3: Run `cargo test -p rimap-server`**

Run: `cargo test -p rimap-server`
Expected: all tests pass, including the updated `tool_definition_covers_all_mcp_tools` (20 tools).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/server.rs
git commit -m "feat(server): wire label tools into dispatch and tool_definition"
```

---

## Task 6: Add label redaction schemas

**Files:**
- Modify: `crates/rimap-audit/src/redact.rs`

- [ ] **Step 1: Add redaction schemas for label tools**

In the `schemas()` function in `crates/rimap-audit/src/redact.rs`, add three new schemas following the existing pattern. Label arguments are not PII — log them verbatim:

```rust
    RedactionSchema {
        tool: "add_label",
        policies: BTreeMap::from([
            ("folder", FieldPolicy::Verbatim),
            ("uid", FieldPolicy::Verbatim),
            ("uids", FieldPolicy::Verbatim),
            ("label", FieldPolicy::Verbatim),
        ]),
    },
    RedactionSchema {
        tool: "remove_label",
        policies: BTreeMap::from([
            ("folder", FieldPolicy::Verbatim),
            ("uid", FieldPolicy::Verbatim),
            ("uids", FieldPolicy::Verbatim),
            ("label", FieldPolicy::Verbatim),
        ]),
    },
    RedactionSchema {
        tool: "list_labels",
        policies: BTreeMap::from([
            ("folder", FieldPolicy::Verbatim),
            ("uid", FieldPolicy::Verbatim),
        ]),
    },
```

- [ ] **Step 2: Run `cargo test -p rimap-audit`**

Run: `cargo test -p rimap-audit`
Expected: all tests pass. If there's a test asserting schema count, update it.

- [ ] **Step 3: Run `just ci` to verify everything is clean**

Run: `just ci`
Expected: all checks pass (fmt, clippy, test, deny).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/redact.rs
git commit -m "feat(audit): add redaction schemas for label tools"
```
