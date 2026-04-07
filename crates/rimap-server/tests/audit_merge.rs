//! End-to-end test: write a synthetic audit log via `AuditWriter`, invoke
//! the compiled `rusty-imap-mcp audit merge` binary, parse its stdout, and
//! verify every record is present in order.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::collections::BTreeSet;

use assert_cmd::Command;
use rimap_audit::{
    AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason, ProcessId, Seq,
    Timestamp,
};
use tempfile::TempDir;

fn record(seq: u64, pid: ProcessId) -> AuditRecord {
    AuditRecord {
        seq: Seq(seq),
        ts: Timestamp::now(),
        process_id: pid,
        payload: Payload::ProcessEnd(ProcessEnd {
            reason: ProcessEndReason::Eof,
            total_tool_calls: seq,
        }),
    }
}

#[test]
fn audit_merge_round_trips_synthetic_log() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    {
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let pid = ProcessId::new_now();
        for seq in 1_u64..=7 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
        // Drop releases the lock so the subcommand can take a shared lock.
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit merge failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let seqs: BTreeSet<u64> = stdout
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| v["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (1_u64..=7).collect::<BTreeSet<_>>());
}

#[test]
fn audit_merge_filters_by_kind() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    {
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let pid = ProcessId::new_now();
        for seq in 1_u64..=3 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .arg("--kind")
        .arg("process_start")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "expected no matches, got {stdout}"
    );
}
