//! Integration tests for the `epvme_runner` binary.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

/// Resolve the path to the `epvme_runner` binary built by cargo.
fn cargo_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    // test binary lives in target/debug/deps/; go up to target/debug/
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("epvme_runner");
    path
}

fn write_eml(dir: &Path, name: &str, body: &str) {
    let content = format!(
        "From: test@example.com\r\n\
         To: test@example.com\r\n\
         Subject: Test\r\n\
         \r\n\
         {body}\r\n"
    );
    fs::write(dir.join(name), content.as_bytes()).unwrap();
}

#[test]
fn normal_run_two_files() {
    let tmp = TempDir::new().unwrap();
    write_eml(tmp.path(), "a.eml", "Hello");
    write_eml(tmp.path(), "b.eml", "World");

    let output = Command::new(cargo_bin()).arg(tmp.path()).output().unwrap();

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Discovered .eml files: 2"),
        "stdout missing file count:\n{stdout}",
    );
    assert!(
        stdout.contains("Processed files: 2"),
        "stdout missing processed count:\n{stdout}",
    );
    assert!(
        stdout.contains("Parsed successfully: 2"),
        "stdout missing ok count:\n{stdout}",
    );
}

#[test]
fn missing_directory_exits_nonzero() {
    let output = Command::new(cargo_bin())
        .arg("/tmp/rimap-nonexistent-dir-for-test")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "expected non-zero exit for missing directory",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist"),
        "stderr should mention missing path:\n{stderr}",
    );
}

#[test]
fn limit_flag_caps_processing() {
    let tmp = TempDir::new().unwrap();
    write_eml(tmp.path(), "a.eml", "one");
    write_eml(tmp.path(), "b.eml", "two");
    write_eml(tmp.path(), "c.eml", "three");

    let output = Command::new(cargo_bin())
        .args([tmp.path().as_os_str(), "--limit".as_ref(), "2".as_ref()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Discovered .eml files: 3"),
        "should discover all 3 files:\n{stdout}",
    );
    assert!(
        stdout.contains("Processed files: 2"),
        "should process only 2 files:\n{stdout}",
    );
    assert!(
        stdout.contains("Limit: 2"),
        "should display the limit:\n{stdout}",
    );
}

#[test]
fn json_out_writes_valid_json() {
    let tmp = TempDir::new().unwrap();
    write_eml(tmp.path(), "sample.eml", "JSON test body");

    let json_path = tmp.path().join("report.json");

    let output = Command::new(cargo_bin())
        .args([
            tmp.path().as_os_str(),
            "--json-out".as_ref(),
            json_path.as_os_str(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(json_path.exists(), "JSON report file should exist");

    let raw = fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

    assert_eq!(parsed["discovered_files"], 1);
    assert_eq!(parsed["processed_files"], 1);
    assert_eq!(parsed["ok_count"], 1);
    assert_eq!(parsed["parse_error_count"], 0);
    assert_eq!(parsed["panic_count"], 0);
}

#[test]
fn no_args_exits_nonzero() {
    let output = Command::new(cargo_bin()).output().unwrap();

    assert!(
        !output.status.success(),
        "expected non-zero exit with no arguments",
    );
}

#[test]
fn help_flag_exits_zero_kills_mutant_delete_help_arm() {
    let output = Command::new(cargo_bin()).arg("--help").output().unwrap();
    assert!(
        output.status.success(),
        "expected exit 0 for --help, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn short_help_flag_exits_zero_kills_mutant_delete_help_arm() {
    let output = Command::new(cargo_bin()).arg("-h").output().unwrap();
    assert!(
        output.status.success(),
        "expected exit 0 for -h, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn unknown_flag_exits_nonzero_with_message_kills_mutant_flag_guard() {
    let output = Command::new(cargo_bin()).arg("--bogus").output().unwrap();
    assert!(
        !output.status.success(),
        "expected non-zero exit for unknown flag --bogus, got {:?}",
        output.status.code(),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown flag: --bogus"),
        "stderr should contain 'unknown flag: --bogus':\n{stderr}",
    );
}
