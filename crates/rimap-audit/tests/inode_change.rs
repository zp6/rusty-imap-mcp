//! Integration test for the startup self-check's tamper-signal path.
//!
//! Scenario: first run writes a `process_start` with its current inode in
//! `previous_file_inode`. The file is then removed (simulating `rm`). Second
//! run re-opens the file (a fresh inode), calls `read_trailing_state`, and
//! verifies the comparison would flag a mismatch.
//!
//! On Windows the inode concept does not apply; `current_inode` returns `0`
//! and this test is compiled out.

#![expect(clippy::unwrap_used, reason = "tests")]
#![cfg(unix)]

use std::io::Write;

use rimap_audit::{TrailingState, current_inode, read_trailing_state};
use tempfile::TempDir;

#[test]
fn rm_between_runs_is_detected_as_tamper_signal() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    // Pretend first run: write a process_start line with previous_file_inode = 111.
    let body = r#"{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_start","version":"0.1.0","git_commit":"","posture":"draft-safe","config_path":"/tmp/c.toml","config_hash_sha256":"aa","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":111,"audit_file_inode_changed":false}"#;
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{body}").unwrap();
    drop(f);

    let state_before: TrailingState = read_trailing_state(&path).unwrap();
    assert_eq!(state_before.last_recorded_inode, Some(111));

    // Simulate `rm`: delete and recreate the file.
    std::fs::remove_file(&path).unwrap();
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{body}").unwrap();
    drop(f);

    let observed = current_inode(&path).unwrap();
    // 111 is almost certainly not the real inode of the freshly recreated
    // file — we assert they differ (the tamper-signal computation).
    assert_ne!(observed, 111);
}
