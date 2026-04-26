//! Integration test: a second `AuditWriter` against the same path fails with
//! `AuditError::Locked`, matching the Sprint 2 exit criterion.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use rimap_audit::{AuditError, AuditOptions, AuditWriter};
use std::os::unix::fs::PermissionsExt as _;
use tempfile::TempDir;

/// Tempdir whose mode is forced to 0700. Required because `AuditWriter::open`
/// (post-#147) refuses parent directories with looser permissions, and
/// `tempfile::TempDir::new()` may create with 0755 depending on the system
/// `umask`. Each integration test that uses `dir.path()` directly as the
/// audit parent must build the tempdir through this helper.
fn tight_tempdir() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn concurrent_open_fails_fast_with_locked() {
    let dir = tight_tempdir();
    let path = dir.path().join("audit.jsonl");
    let _first = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .unwrap();

    let err = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
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
    let dir = tight_tempdir();
    let path = dir.path().join("audit.jsonl");
    {
        let _first = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .unwrap();
    }
    let _second = AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .unwrap();
}
