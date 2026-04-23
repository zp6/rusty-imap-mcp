//! Integration test: the shim exits non-zero with actionable guidance when
//! the daemon is not running.
#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

use std::os::unix::fs::PermissionsExt as _;

use assert_cmd::Command;
use tempfile::TempDir;

/// Verify that `rusty-imap-mcp shim` fails with a non-zero exit code and emits
/// a stderr message that:
///   1. Names the resolved socket path (so users know where the daemon should be).
///   2. Includes actionable guidance for starting the daemon via systemd or
///      the bare `rusty-imap-mcp daemon` command.
#[test]
fn shim_exits_with_actionable_message_when_daemon_absent() {
    let tmp = TempDir::new().expect("tempdir");
    // XDG_RUNTIME_DIR is required to be 0700 and owned by the current user
    // (freedesktop spec; enforced by `daemon::socket_path::verify_runtime_dir`).
    // `TempDir::new()` creates with 0700 on Linux, but on hosts with a looser
    // umask or BSD defaults it may be 0755; narrow it explicitly so the
    // resolver accepts our test path rather than falling back.
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700");

    let mut cmd = Command::cargo_bin("rusty-imap-mcp").expect("binary");
    cmd.env("XDG_RUNTIME_DIR", tmp.path())
        // Remove TMPDIR so Linux falls through to XDG_RUNTIME_DIR rather than
        // a uid-suffixed TMPDIR fallback, giving us a predictable socket path.
        .env_remove("TMPDIR")
        .arg("shim");

    let out = cmd.output().expect("spawn shim");

    assert!(
        !out.status.success(),
        "shim must exit non-zero when the daemon is absent; got: {:?}",
        out.status
    );

    let stderr = String::from_utf8_lossy(&out.stderr);

    // The resolved socket path must appear in the error so the user can
    // inspect or configure the correct location.
    let expected_sock = tmp
        .path()
        .join("rusty-imap-mcp")
        .join("daemon.sock")
        .to_string_lossy()
        .into_owned();
    assert!(
        stderr.contains(&expected_sock),
        "stderr must name the resolved socket path ({expected_sock}); got:\n{stderr}"
    );

    // At least one of the two actionable hints must be present.
    let has_systemd_hint = stderr.contains("systemctl --user enable --now rusty-imap-mcp.service");
    let has_bare_daemon_hint = stderr.contains("rusty-imap-mcp daemon");
    assert!(
        has_systemd_hint || has_bare_daemon_hint,
        "stderr must guide the user to start the daemon; got:\n{stderr}"
    );
}
