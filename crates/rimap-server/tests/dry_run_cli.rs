//! End-to-end CLI test: invoke the compiled binary with `--dry-run` against a
//! temp-file config and assert exit code + stdout contents.

#![expect(clippy::unwrap_used, reason = "tests")]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Tempdir whose mode is forced to 0700 — `AuditWriter::open` rejects looser
/// modes after #147 and `tempfile::TempDir::new()` may inherit the system
/// `umask` (often 0755).
fn tight_tempdir() -> TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn write_config(dir: &TempDir) -> std::path::PathBuf {
    let audit = dir.path().join("audit.jsonl");
    let path = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
posture = "readonly"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
        audit.display(),
        dir.path().display()
    );
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn dry_run_exits_zero_and_prints_matrix() {
    let dir = tight_tempdir();
    let config = write_config(&dir);
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("readonly"))
        .stdout(predicate::str::contains("[ok ] list_folders"))
        .stdout(predicate::str::contains("[deny] create_draft"))
        .stdout(predicate::str::contains("Capabilities"));
}

#[test]
fn missing_config_exits_non_zero_with_error_log() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("absent.toml");
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&missing)
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("loading config"));
}

#[test]
fn unknown_tool_override_exits_non_zero() {
    let dir = tight_tempdir();
    let audit = dir.path().join("audit.jsonl");
    let config = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security.tools]
nuke_inbox = "deny"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
        audit.display(),
        dir.path().display()
    );
    std::fs::write(&config, body).unwrap();
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nuke_inbox"));
}
