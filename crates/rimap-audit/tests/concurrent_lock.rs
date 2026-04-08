//! Integration test: a second `AuditWriter` against the same path fails with
//! `AuditError::Locked`, matching the Sprint 2 exit criterion.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use rimap_audit::{AuditError, AuditOptions, AuditWriter};
use tempfile::TempDir;

#[test]
fn concurrent_open_fails_fast_with_locked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let _first = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        rotate_keep: 0,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .unwrap();

    let err = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        rotate_keep: 0,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .unwrap_err();
    match err {
        AuditError::Locked { path: p } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn lock_released_after_drop_allows_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    {
        let _first = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            fail_open: false,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .unwrap();
    }
    let _second = AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 0,
        rotate_keep: 0,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .unwrap();
}
