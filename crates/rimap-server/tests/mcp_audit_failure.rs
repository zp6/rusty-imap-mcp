//! Audit fail-closed boundary tests (issue #266, Phase 4 §4.3).
//!
//! Arms the production `AuditWriter`'s `force_next_write_failure()`
//! hook via the `test-support`-gated env var
//! `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1`, then exercises
//! the wire. The next audit write — `tool_start` for the first
//! `tools/call` — takes the real lock/append/error-mapping path
//! and fails. The server must respond with an error envelope
//! rather than silently proceeding.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "support/mod.rs"]
mod support;

use serde_json::json;
use tempfile::TempDir;

use support::wire::harness::Harness;

/// With the audit writer armed for one forced write failure,
/// `tools/call use_account` must return an error envelope. Tests
/// the real `AuditWriter` path (lock/append/error-mapping), not a
/// swappable sink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_write_failure_fails_closed_for_tools_call() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path();
    let config = format!(
        r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
fail_open = false
"#,
        audit_path.display(),
        allowed_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "use_account",
                "arguments": { "account": "nonexistent" },
            }),
        )
        .await;

    // The contract is "fails closed" — the server must NOT
    // silently succeed when the audit write fails.
    let is_envelope_error = response.get("error").is_some();
    let is_tool_error = response["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        is_envelope_error || is_tool_error,
        "tools/call with armed audit-write failure must fail closed, got {response}",
    );
}

/// Initialize handshake must succeed (or fail cleanly) regardless
/// of audit failure arming. `initialize` doesn't write an audit
/// record by itself, so this test pins that the env-var hook
/// doesn't accidentally break the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_write_failure_does_not_block_initialize() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path();
    let config = format!(
        r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
fail_open = false
"#,
        audit_path.display(),
        allowed_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let response = harness.initialize_handshake().await;
    assert!(
        response["result"].is_object(),
        "initialize must succeed even with audit failure armed, got {response}",
    );
}
