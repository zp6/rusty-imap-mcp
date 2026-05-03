//! Pins the cross-link from `AuditError::Locked`'s Display string
//! (`docs/audit-log.md#running-multiple-mcp-clients`) to the heading that
//! defines that anchor. If `docs/audit-log.md` is reorganized and the
//! heading is renamed without a coordinated update to the error message,
//! this test fails.

#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::path::PathBuf;

#[test]
fn audit_log_md_defines_running_multiple_mcp_clients_heading() {
    // CARGO_MANIFEST_DIR points at crates/rimap-audit/. Walk up two levels
    // to reach the workspace root, then read docs/audit-log.md.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root must exist two levels above crate dir")
        .to_path_buf();
    let docs_path = workspace_root.join("docs").join("audit-log.md");

    let content = std::fs::read_to_string(&docs_path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", docs_path.display());
    });

    assert!(
        content.contains("\n## Running multiple MCP clients\n"),
        "docs/audit-log.md must define the `## Running multiple MCP clients` \
         heading referenced by AuditError::Locked. Did the heading get renamed?",
    );
}
