//! `dump-tool-schemas` test-support CLI subcommand. Emits one JSON
//! Schema per in-scope tool, composing `<Tool>Meta` and (where
//! present) `<Tool>Untrusted` into a single `{meta, untrusted}`
//! envelope schema. Used by the Phase 3 wire-conformance harness
//! (issue #265) to validate every wire response against a per-tool
//! schema regenerated from the Rust output structs.

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value;

/// Emit `{ "<tool>": <schema>, ... }` as pretty-printed JSON to the
/// given writer. Iteration order is deterministic (`BTreeMap`).
///
/// # Errors
///
/// Returns the I/O error if the writer fails or the serializer cannot
/// encode an entry. Schemars produces valid JSON for every derive-using
/// struct in scope; failure indicates a bug, not user input.
pub fn dump_tool_schemas<W: Write>(writer: &mut W) -> std::io::Result<()> {
    let schemas = build_schemas();
    serde_json::to_writer_pretty(&mut *writer, &schemas)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn build_schemas() -> BTreeMap<&'static str, Value> {
    use rimap_server::tools::{
        admin::{
            accounts::{ListAccountsMeta, UseAccountMeta},
            list_folders::ListFoldersMeta,
        },
        compose::create_draft::CreateDraftMeta,
        mailbox::{
            flags::FlagsMeta,
            labels::{LabelsMeta, ListLabelsMeta},
            move_message::MoveMessageMeta,
        },
        retrieval::{
            download_attachment::{DownloadAttachmentMeta, DownloadAttachmentUntrusted},
            fetch_message::{FetchMessageMeta, FetchMessageUntrusted},
            list_attachments::{ListAttachmentsMeta, ListAttachmentsUntrusted},
            search::{SearchMeta, SearchUntrusted},
        },
    };

    let mut out = BTreeMap::<&'static str, Value>::new();

    // meta-only tools (no untrusted payload on the wire)
    out.insert("list_folders", meta_only::<ListFoldersMeta>());
    out.insert("list_accounts", meta_only::<ListAccountsMeta>());
    out.insert("list_labels", meta_only::<ListLabelsMeta>());
    out.insert("mark_read", meta_only::<FlagsMeta>());
    out.insert("mark_unread", meta_only::<FlagsMeta>());
    out.insert("flag", meta_only::<FlagsMeta>());
    out.insert("unflag", meta_only::<FlagsMeta>());
    out.insert("add_label", meta_only::<LabelsMeta>());
    out.insert("remove_label", meta_only::<LabelsMeta>());
    out.insert("move_message", meta_only::<MoveMessageMeta>());
    out.insert("create_draft", meta_only::<CreateDraftMeta>());
    out.insert("use_account", meta_only::<UseAccountMeta>());

    // meta + untrusted tools
    out.insert(
        "search",
        meta_and_untrusted::<SearchMeta, SearchUntrusted>(),
    );
    out.insert(
        "fetch_message",
        meta_and_untrusted::<FetchMessageMeta, FetchMessageUntrusted>(),
    );
    out.insert(
        "list_attachments",
        meta_and_untrusted::<ListAttachmentsMeta, ListAttachmentsUntrusted>(),
    );
    out.insert(
        "download_attachment",
        meta_and_untrusted::<DownloadAttachmentMeta, DownloadAttachmentUntrusted>(),
    );

    out
}

// Top-level wire envelope is `{meta, untrusted?, security_warnings?}`
// per crates/rimap-server/src/mcp/response.rs:14-25. untrusted and
// security_warnings are skip-serialize-if-empty/None, so the schema
// makes them optional, not required.

fn warnings_schema() -> Value {
    let schema = schemars::schema_for!(rimap_content::SecurityWarning);
    serde_json::json!({
        "type": "array",
        "items": schema,
    })
}

fn meta_only<M: schemars::JsonSchema>() -> Value {
    let schema = schemars::schema_for!(M);
    serde_json::json!({
        "type": "object",
        "properties": {
            "meta": schema,
            "security_warnings": warnings_schema(),
        },
        "required": ["meta"],
        "additionalProperties": false,
    })
}

fn meta_and_untrusted<M: schemars::JsonSchema, U: schemars::JsonSchema>() -> Value {
    let m = schemars::schema_for!(M);
    let u = schemars::schema_for!(U);
    serde_json::json!({
        "type": "object",
        "properties": {
            "meta": m,
            "untrusted": u,
            "security_warnings": warnings_schema(),
        },
        "required": ["meta", "untrusted"],
        "additionalProperties": false,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn dump_emits_one_key_per_in_scope_tool() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();

        for name in [
            "list_folders",
            "list_accounts",
            "list_labels",
            "list_attachments",
            "download_attachment",
            "search",
            "fetch_message",
            "mark_read",
            "mark_unread",
            "flag",
            "unflag",
            "add_label",
            "remove_label",
            "move_message",
            "create_draft",
            "use_account",
        ] {
            assert!(parsed.contains_key(name), "missing schema for {name}");
            let entry = &parsed[name];
            assert_eq!(entry["type"], "object");
            assert!(
                entry["properties"]["meta"].is_object(),
                "{name}.meta must be a JSON Schema object"
            );
        }
    }

    #[test]
    fn meta_and_untrusted_tools_include_untrusted_key() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();
        for name in [
            "search",
            "fetch_message",
            "list_attachments",
            "download_attachment",
        ] {
            assert!(
                parsed[name]["properties"]["untrusted"].is_object(),
                "{name} must declare an untrusted schema"
            );
        }
    }
}
