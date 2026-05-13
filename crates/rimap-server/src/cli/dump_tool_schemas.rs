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

/// Strip the `$defs` block from `value` and return the extracted defs.
/// `value` is mutated in place: after the call it no longer carries a
/// `$defs` key at its top level. Returns an empty `Map` if there were
/// no defs to hoist.
fn extract_defs(value: &mut Value) -> serde_json::Map<String, Value> {
    let Some(obj) = value.as_object_mut() else {
        return serde_json::Map::new();
    };
    match obj.remove("$defs") {
        Some(Value::Object(defs)) => defs,
        _ => serde_json::Map::new(),
    }
}

/// Merge `from` into `into`. Panics if any key in `from` already
/// exists in `into` with a different value — that would be a real
/// name collision and we want to surface it loudly rather than
/// silently keep one side. For Phase 3's struct set this should
/// never trigger; schemars uses the Rust type's identifier as the
/// def key and the four root types we compose don't share inner
/// types with different shapes.
#[expect(
    clippy::panic,
    reason = "programmer error: schemars $defs key collision"
)]
fn merge_defs(into: &mut serde_json::Map<String, Value>, from: serde_json::Map<String, Value>) {
    for (key, value) in from {
        match into.get(&key) {
            None => {
                into.insert(key, value);
            }
            Some(existing) if existing == &value => { /* identical, skip */ }
            Some(existing) => {
                panic!(
                    "duplicate $defs key {key:?} with conflicting shapes:\n\
                     existing: {existing}\nincoming: {value}"
                );
            }
        }
    }
}

/// `Vec<rimap_content::SecurityWarning>` schema, with its nested $defs
/// hoisted into the caller's accumulator.
#[expect(
    clippy::expect_used,
    reason = "schemars always produces serializable output; failure is a bug"
)]
fn warnings_schema(defs: &mut serde_json::Map<String, Value>) -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(rimap_content::SecurityWarning))
        .expect("SecurityWarning schema serializes");
    merge_defs(defs, extract_defs(&mut schema));
    serde_json::json!({
        "type": "array",
        "items": schema,
    })
}

#[expect(
    clippy::expect_used,
    reason = "schemars always produces serializable output; failure is a bug"
)]
fn meta_only<M: schemars::JsonSchema>() -> Value {
    let mut meta = serde_json::to_value(schemars::schema_for!(M)).expect("meta schema serializes");
    let mut defs = extract_defs(&mut meta);
    let warnings = warnings_schema(&mut defs);

    let mut envelope = serde_json::json!({
        "type": "object",
        "properties": {
            "meta": meta,
            "security_warnings": warnings,
        },
        "required": ["meta"],
        "additionalProperties": false,
    });
    if !defs.is_empty() {
        envelope
            .as_object_mut()
            .expect("envelope is object")
            .insert("$defs".to_string(), Value::Object(defs));
    }
    envelope
}

#[expect(
    clippy::expect_used,
    reason = "schemars always produces serializable output; failure is a bug"
)]
fn meta_and_untrusted<M: schemars::JsonSchema, U: schemars::JsonSchema>() -> Value {
    let mut meta = serde_json::to_value(schemars::schema_for!(M)).expect("meta schema serializes");
    let mut untrusted =
        serde_json::to_value(schemars::schema_for!(U)).expect("untrusted schema serializes");
    let mut defs = extract_defs(&mut meta);
    merge_defs(&mut defs, extract_defs(&mut untrusted));
    let warnings = warnings_schema(&mut defs);

    let mut envelope = serde_json::json!({
        "type": "object",
        "properties": {
            "meta": meta,
            "untrusted": untrusted,
            "security_warnings": warnings,
        },
        "required": ["meta", "untrusted"],
        "additionalProperties": false,
    });
    if !defs.is_empty() {
        envelope
            .as_object_mut()
            .expect("envelope is object")
            .insert("$defs".to_string(), Value::Object(defs));
    }
    envelope
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
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

    #[test]
    fn search_schema_hoists_defs_to_envelope_root() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();

        let search = &parsed["search"];
        assert!(
            search.get("$defs").is_some(),
            "search schema must hoist nested $defs to envelope root: {search}"
        );
        let defs = search["$defs"].as_object().expect("$defs is an object");
        assert!(
            defs.contains_key("SearchResultEntry"),
            "envelope $defs must include SearchResultEntry: {defs:?}"
        );

        // No nested $defs anywhere under properties.
        let props = search["properties"].as_object().expect("properties");
        for (name, sub) in props {
            assert!(
                sub.get("$defs").is_none(),
                "tool subschema {name} must not carry its own $defs after hoist: {sub}"
            );
        }
    }
}
