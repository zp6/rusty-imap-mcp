//! Compile-time enforcement of the audit envelope (#110).
//!
//! `execute_tool_for_test` composes the full dispatch pipeline
//! (posture → `pre_dispatch` → audit envelope → handler). This test
//! invokes it against the `list_accounts` infrastructure tool — no
//! IMAP connection is required — and asserts that both the
//! `tool_start` and `tool_end` envelope records landed in the audit
//! log. If a future refactor lets a caller bypass
//! `run_with_audit_envelope`, these records are absent and the test
//! fails.

#![expect(clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_core::tool::ToolName;
use rimap_server::boot::registry::AccountRegistry;
use rimap_server::mcp::server::ImapMcpServer;
use serde_json::json;
use tempfile::TempDir;

struct TestFixture {
    server: ImapMcpServer,
    audit_path: std::path::PathBuf,
    _audit_dir: TempDir,
}

fn build_test_server() -> TestFixture {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let audit = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
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

    TestFixture {
        server,
        audit_path,
        _audit_dir: audit_dir,
    }
}

fn read_audit_records(path: &std::path::Path) -> Vec<serde_json::Value> {
    let contents = std::fs::read_to_string(path).expect("read audit log");
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse record"))
        .collect()
}

#[tokio::test]
async fn execute_tool_for_test_emits_audit_envelope() {
    let fixture = build_test_server();

    // `list_accounts` is an infrastructure tool and needs no IMAP
    // connection. If the envelope were bypassed, the tool_start /
    // tool_end records below would be missing.
    let _result = fixture
        .server
        .execute_tool_for_test(None, ToolName::ListAccounts, json!({}))
        .await
        .expect("execute_tool_for_test should succeed");

    // Drop the server to flush the audit writer.
    drop(fixture.server);

    let records = read_audit_records(&fixture.audit_path);

    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts"),
        "tool_start record missing; dispatch must not bypass the envelope. records={records:#?}",
    );
    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts"),
        "tool_end record missing. records={records:#?}",
    );

    let start = records
        .iter()
        .find(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts")
        .expect("tool_start record");
    let end = records
        .iter()
        .find(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts")
        .expect("tool_end record");

    assert_eq!(
        start["seq"], end["start_seq"],
        "tool_end.start_seq must correlate back to tool_start.seq; otherwise the envelope's pairing guarantee is broken",
    );
}
