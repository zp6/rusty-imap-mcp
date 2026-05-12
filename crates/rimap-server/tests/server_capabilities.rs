//! Regression test: `get_info()` must advertise the `tools` and
//! `resources` capabilities. Without them, spec-strict MCP clients
//! (e.g. `bobshell`) refuse to call `tools/list` and report "No
//! prompts or tools found on the server."

#![expect(clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_server::boot::registry::AccountRegistry;
use rimap_server::mcp::server::ImapMcpServer;
use rmcp::handler::server::ServerHandler;
use tempfile::TempDir;

fn build_test_server() -> (ImapMcpServer, TempDir) {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let audit = AuditWriter::open(&AuditOptions {
        path: audit_path,
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("audit open");

    let registry = AccountRegistry::new(BTreeMap::new());
    let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
    let server = ImapMcpServer::new(registry, audit, cancellation_sender);
    (server, audit_dir)
}

#[test]
fn get_info_declares_tools_capability() {
    let (server, _audit_dir) = build_test_server();
    let info = server.get_info();

    let tools = info
        .capabilities
        .tools
        .as_ref()
        .expect("tools capability must be declared so spec-strict clients call tools/list");
    assert_eq!(
        tools.list_changed,
        Some(true),
        "tools.list_changed must be true to match the notifications/tools/list_changed \
         emission after use_account",
    );
}

#[test]
fn get_info_declares_resources_capability() {
    let (server, _audit_dir) = build_test_server();
    let info = server.get_info();

    assert!(
        info.capabilities.resources.is_some(),
        "resources capability must be declared because list_resources/read_resource are \
         implemented in ImapMcpServer",
    );
}

#[test]
fn get_info_omits_prompts_capability() {
    let (server, _audit_dir) = build_test_server();
    let info = server.get_info();

    assert!(
        info.capabilities.prompts.is_none(),
        "prompts capability must NOT be declared because no prompts surface is implemented",
    );
}

#[test]
fn get_info_serializes_tools_in_capabilities_payload() {
    // Spec-strict clients inspect the JSON shape of `capabilities`. This
    // test guards against a future field-rename or
    // `skip_serializing_if = "Option::is_none"` regression that would
    // emit `"capabilities": {}` on the wire.
    let (server, _audit_dir) = build_test_server();
    let info = server.get_info();
    let json = serde_json::to_value(&info.capabilities).expect("serialize capabilities");

    assert!(
        json.get("tools").is_some(),
        "capabilities JSON must contain a `tools` key on the wire; got {json}",
    );
    assert!(
        json.get("resources").is_some(),
        "capabilities JSON must contain a `resources` key on the wire; got {json}",
    );
    assert!(
        json.get("prompts").is_none(),
        "capabilities JSON must omit `prompts` (not implemented); got {json}",
    );
}
