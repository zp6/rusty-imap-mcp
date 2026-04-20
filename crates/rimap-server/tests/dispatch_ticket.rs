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

#[tokio::test]
async fn use_account_rejected_spoof_is_not_in_audit_log() {
    let fixture = build_test_server();

    // Spoofed account name containing RLO (U+202E) and ZWSP (U+200B).
    // After rejection, the audit log must contain neither the raw
    // account string nor the JSON-escaped form of the spoof codepoints —
    // only the `<redacted:N>` placeholder.
    let _ = fixture
        .server
        .execute_tool_for_test(
            None,
            ToolName::UseAccount,
            serde_json::json!({ "account": "work\u{202e}\u{200b}cnyS" }),
        )
        .await;

    drop(fixture.server);

    let raw = std::fs::read_to_string(&fixture.audit_path).expect("read audit log");

    // serde_json may or may not escape non-ASCII as \uXXXX depending on
    // configuration. Check both the literal UTF-8 bytes AND the JSON-escape
    // forms so a regression is caught regardless of serializer behavior.
    assert!(
        !raw.contains('\u{202e}'),
        "RTL-override literal codepoint leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains('\u{200b}'),
        "zero-width-space literal codepoint leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\\u202e"),
        "RTL-override escape form leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\\u200b"),
        "zero-width-space escape form leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\"work"),
        "raw account string prefix leaked into audit log: {raw}",
    );

    // Walk the structured records. The `tool_start` for `use_account`
    // must carry the redacted placeholder in `arguments_redacted.account`,
    // proving the `RedactString` policy is active.
    let start = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|r| r["kind"] == "tool_start" && r["tool"] == "use_account")
        .expect("tool_start record for use_account");
    let account_field = start
        .pointer("/arguments_redacted/account")
        .expect("tool_start must expose arguments_redacted.account")
        .as_str()
        .expect("arguments_redacted.account must be a string");
    assert!(
        account_field.starts_with("<redacted:"),
        "account field must be redacted placeholder, got: {account_field:?}",
    );
}
