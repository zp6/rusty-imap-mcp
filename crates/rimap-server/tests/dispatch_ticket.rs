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
use std::sync::Arc;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_core::tool::ToolName;
use rimap_server::boot::registry::AccountRegistry;
use rimap_server::daemon::state::{DaemonState, SessionState};
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
    let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();
    let download_dir: Arc<std::path::Path> = Arc::from(std::path::Path::new("/tmp/test-downloads"));
    let daemon_state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
    });
    let session_state = Arc::new(SessionState::new(rimap_core::SessionId::new()));
    let server = ImapMcpServer::new(daemon_state, session_state);

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

/// Drop the outer dispatch future while a tool body is still awaiting.
/// The `AuditEnvelopeGuard::Drop` path must fire, enqueue a synthetic
/// cancellation `tool_end`, and the drainer must persist it to disk.
///
/// Regression test for the closure form of `run_with_audit_envelope`:
/// the guard lives inside the closure's future, so if a future refactor
/// disarms the guard above the `body(ticket).await`, cancellation would
/// silently lose its `tool_end` — the unit test at `audit_envelope.rs`
/// only exercises the guard in isolation, not the closure wiring.
#[tokio::test]
async fn drop_during_body_enqueues_cancellation_tool_end() {
    use rimap_audit::spawn_drainer;
    use std::sync::Arc;
    use tokio::time::Duration;

    let audit_dir = tempfile::TempDir::new().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let audit = rimap_audit::AuditWriter::open(&rimap_audit::AuditOptions {
        path: audit_path.clone(),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .expect("audit open");

    let registry =
        rimap_server::boot::registry::AccountRegistry::new(std::collections::BTreeMap::new());
    let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
    let drainer = spawn_drainer(cancellation_rx, audit.clone());
    let download_dir_2: Arc<std::path::Path> =
        Arc::from(std::path::Path::new("/tmp/test-downloads"));
    let daemon_state_2 = Arc::new(rimap_server::daemon::state::DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir: download_dir_2,
        cancellation_tx,
        started_at: std::time::Instant::now(),
    });
    let session_state_2 = Arc::new(rimap_server::daemon::state::SessionState::new(
        rimap_core::SessionId::new(),
    ));
    let server = Arc::new(rimap_server::mcp::server::ImapMcpServer::new(
        daemon_state_2,
        session_state_2,
    ));

    // Use a never-resolving body so the abort reliably lands mid-body.
    // Real infrastructure tools (ListAccounts) complete synchronously —
    // no yield point exists between guard creation and `guard.disarm()`,
    // so aborting at a yield point always lands outside the guarded
    // window. Injecting `std::future::pending()` guarantees the abort
    // fires while the body is suspended, which is exactly the state
    // where `AuditEnvelopeGuard::drop` must enqueue the cancellation
    // `tool_end`.
    //
    // The invariant: every `tool_start` must be paired with a `tool_end`.
    // Aborting mid-body exercises the cancellation path: the guard's
    // `Drop` fires and enqueues the `tool_end` via the drainer channel.
    // A bad refactor that disarms the guard ABOVE `body(ticket).await`
    // breaks this: the `Drop` is a no-op, no `tool_end` is enqueued,
    // and counts diverge.
    let server_clone = Arc::clone(&server);
    let task = tokio::spawn(async move {
        server_clone
            .run_envelope_with_body_for_test(
                ToolName::ListAccounts,
                std::future::pending::<Result<serde_json::Value, rimap_core::RimapError>>(),
            )
            .await
    });

    // Give the envelope time to emit `tool_start` and enter the body's
    // pending await before aborting. The `spawn_blocking` for `tool_start`
    // is the only real work before the body; 50ms gives comfortable headroom
    // on loaded CI runners without approaching the test's total budget.
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    let _ = task.await; // wait for the abort to settle

    // Give the drainer time to flush the queued cancellation record.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(server);
    // Await the drainer after dropping server (which drops the last sender)
    // so it exits cleanly after flushing remaining records.
    drainer.await.expect("drainer task should not panic");

    let records = read_audit_records(&audit_path);

    let starts = records.iter().filter(|r| r["kind"] == "tool_start").count();
    let ends = records.iter().filter(|r| r["kind"] == "tool_end").count();

    assert_eq!(
        starts, ends,
        "tool_start count must equal tool_end count (no orphans); records={records:#?}",
    );
    assert!(
        starts >= 1,
        "at least one dispatch envelope must have fired; records={records:#?}",
    );
}
