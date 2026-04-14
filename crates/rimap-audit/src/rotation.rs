//! Rotation-under-lock logic. See design spec §10 "File handling & locking".

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use time::OffsetDateTime;

use crate::error::AuditError;

/// Compute the rotation destination path: `<active>.<rfc3339-timestamp>`.
/// Example: `audit.jsonl.2026-04-07T14-22-01.000Z`.
#[must_use]
pub fn rotated_path(active: &Path, now: OffsetDateTime) -> PathBuf {
    let stamp = format!(
        "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    );
    let mut name = active.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(stamp);
    active.with_file_name(name)
}

/// Resolve a non-colliding rotation destination, trying the millisecond-stamped
/// path first and appending `-1`, `-2`, … on collision. Returns the first path
/// that does not yet exist.
///
/// Two rotations within the same millisecond — possible on fast hardware with
/// a small `rotate_bytes` — would otherwise clobber each other because
/// `std::fs::rename` overwrites the destination on Unix. The collision counter
/// makes the rename safe regardless of timestamp resolution.
fn unique_rotated_path(active: &Path, now: OffsetDateTime) -> PathBuf {
    let base = rotated_path(active, now);
    if !base.exists() {
        return base;
    }
    let base_name = base.file_name().unwrap_or_default().to_os_string();
    for counter in 1_u32..=u32::MAX {
        let mut candidate_name = base_name.clone();
        candidate_name.push(format!("-{counter}"));
        let candidate = base.with_file_name(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    // u32::MAX rotations within one millisecond is implausible; fall back to
    // the base name (overwriting) rather than panicking.
    base
}

/// Perform the rename + new-file dance, then prune rotated siblings down to
/// `keep` newest. Returns the freshly-locked `File` for the new active path
/// (with an empty `BufWriter` wrapping it).
///
/// Pruning failures are logged via `tracing::warn!` and never propagated as
/// errors — a stale rotated file is not a write failure.
///
/// # Errors
/// Any I/O error during `rename`, `open`, or `try_lock_exclusive` surfaces as
/// [`AuditError::Rotate`] with a descriptive `reason`.
pub fn rotate_file(
    active: &Path,
    keep: u32,
    retention_seconds: Option<u64>,
) -> Result<(BufWriter<File>, u64), AuditError> {
    let dst = unique_rotated_path(active, OffsetDateTime::now_utc());
    std::fs::rename(active, &dst).map_err(|source| AuditError::Rotate {
        path: active.to_path_buf(),
        reason: format!("rename to {}: {source}", dst.display()),
    })?;

    let new_file = crate::fs_ext::writer_open_options()
        .open(active)
        .map_err(|source| AuditError::Rotate {
            path: active.to_path_buf(),
            reason: format!("open fresh file: {source}"),
        })?;

    crate::writer::set_file_mode_0600(&new_file);

    // Race window: between `open` and `try_lock_exclusive` a concurrent
    // AuditWriter::open on the same path could grab the fresh inode's lock
    // first, in which case our try_lock_exclusive returns Ok(false) and we
    // surface AuditError::Rotate. This is the documented failure mode and is
    // expected to be rare (only relevant if a supervisor restarts the server
    // mid-rotation).
    match FileExt::try_lock_exclusive(&new_file) {
        Ok(true) => {}
        Ok(false) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: "fresh file unexpectedly locked by another process".to_string(),
            });
        }
        Err(e) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: format!("lock fresh file: {e}"),
            });
        }
    }

    // Prune old rotated siblings best-effort. Failures here are logged
    // but never propagated — a stale file is not a write failure.
    prune_rotated_siblings(active, keep, retention_seconds);

    Ok((BufWriter::new(new_file), 0))
}

/// Enumerate sibling files matching `<active_filename>.*`, sort by mtime
/// descending, and delete all but the `keep` newest. `keep == 0` deletes
/// every rotated sibling.
fn prune_rotated_siblings(active: &Path, keep: u32, retention_seconds: Option<u64>) {
    let parent = match active.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let Some(active_name) = active.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    let prefix = format!("{active_name}.");

    let entries = match std::fs::read_dir(parent) {
        Ok(it) => it,
        Err(err) => {
            tracing::warn!(
                parent = %parent.display(),
                error = %err,
                "audit rotate: read_dir failed during prune",
            );
            return;
        }
    };

    let mut siblings: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        if path == active {
            continue;
        }
        // Use symlink_metadata so that symlinks themselves are inspected
        // (not their targets). Skip anything that is not a regular file —
        // directories, symlinks, FIFOs, sockets, device nodes. A planted
        // symlink named "audit.jsonl.evil" whose target's mtime ranks it
        // above a real rotated file could otherwise cause us to delete
        // the real audit file. (LOCAL-FS-05)
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            tracing::warn!(
                path = %path.display(),
                "audit rotate: skipping non-regular sibling during prune",
            );
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        siblings.push((mtime, path));
    }

    // Sort newest-first.
    siblings.sort_by(|a, b| b.0.cmp(&a.0));

    let keep_usize = usize::try_from(keep).unwrap_or(usize::MAX);
    let cutoff = retention_seconds.map(|secs| {
        std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(secs))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    for (idx, (mtime, path)) in siblings.into_iter().enumerate() {
        let beyond_count = idx >= keep_usize;
        let beyond_time = cutoff.is_some_and(|c| mtime < c);
        if (beyond_count || beyond_time)
            && let Err(err) = std::fs::remove_file(&path)
        {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "audit rotate: failed to delete stale rotated sibling",
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::Path;
    use std::thread::sleep;
    use std::time::Duration;

    use tempfile::TempDir;
    use time::macros::datetime;

    use crate::rotation::{rotate_file, rotated_path, unique_rotated_path};

    #[test]
    fn rotated_path_appends_utc_stamp() {
        let active = Path::new("/tmp/audit.jsonl");
        let now = datetime!(2026-04-07 14:22:01.234 UTC);
        let r = rotated_path(active, now);
        assert_eq!(
            r.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z",
        );
    }

    #[test]
    fn unique_rotated_path_appends_counter_when_base_exists() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        let now = datetime!(2026-04-07 14:22:01.234 UTC);

        // Pre-create the base rotated path so the first call has to skip it.
        let base = rotated_path(&active, now);
        std::fs::write(&base, b"existing").unwrap();

        let p1 = unique_rotated_path(&active, now);
        assert_eq!(
            p1.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z-1",
        );

        // Pre-create -1 too; next call should pick -2.
        std::fs::write(&p1, b"existing").unwrap();
        let p2 = unique_rotated_path(&active, now);
        assert_eq!(
            p2.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z-2",
        );
    }

    #[test]
    fn rotate_file_prunes_to_keep_newest_siblings() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");

        std::fs::write(&active, b"first\n").unwrap();

        for _ in 0..7 {
            std::fs::write(&active, b"x\n").unwrap();
            let (_buf, _len) = rotate_file(&active, 3, None).unwrap();
            sleep(Duration::from_millis(2));
        }

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl"))
            })
            .collect();
        let rotated = entries
            .iter()
            .filter(|e| e.file_name() != std::ffi::OsStr::new("audit.jsonl"))
            .count();
        assert_eq!(rotated, 3, "expected exactly 3 rotated siblings");
        assert!(active.exists(), "active file still present");
    }

    #[test]
    fn rotate_file_with_keep_zero_deletes_all_siblings() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        std::fs::write(&active, b"x\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 0, None).unwrap();

        let rotated = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl."))
            })
            .count();
        assert_eq!(rotated, 0, "keep=0 should leave no rotated siblings");
    }

    #[test]
    #[cfg(unix)]
    fn rotate_file_skips_symlinked_siblings_during_prune() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");

        // Create a real rotated sibling that should be kept.
        std::fs::write(&active, b"x\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 5, None).unwrap();

        // Plant a symlink whose name matches the rotated-sibling prefix.
        // Its target is an arbitrary file (here, /etc/hostname — any
        // readable file will do). The mtime of the target is likely
        // newer than the rotated file's mtime on CI hosts, which would
        // cause the old pruner to rank the symlink above the real file.
        let symlink_path = dir.path().join("audit.jsonl.evil");
        std::os::unix::fs::symlink("/etc/hostname", &symlink_path).unwrap();

        // Trigger another rotation with keep=1. The pruner should:
        //   - keep the most recent real rotated file
        //   - skip the symlink entirely (not delete it and not rank it)
        std::fs::write(&active, b"y\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 1, None).unwrap();

        // The symlink must still exist — we never touched it.
        assert!(
            std::fs::symlink_metadata(&symlink_path).is_ok(),
            "planted symlink was deleted by prune"
        );

        // And exactly 1 real rotated sibling must remain (keep=1).
        let real_rotated = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("audit.jsonl.") || name == "audit.jsonl" {
                    return false;
                }
                // Exclude the symlink itself; only count real files.
                let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                    return false;
                };
                meta.file_type().is_file()
            })
            .count();
        assert_eq!(real_rotated, 1, "expected exactly 1 real rotated sibling");
    }

    #[test]
    fn prune_respects_retention_seconds() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");

        // Create two rotated siblings (milliseconds old).
        std::fs::write(&active, b"x\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 10, None).unwrap();
        sleep(Duration::from_millis(10));

        std::fs::write(&active, b"y\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 10, None).unwrap();
        sleep(Duration::from_millis(10));

        // Both siblings are milliseconds old. Rotate with retention_seconds=0
        // (raw function level — config validation rejects 0, but the function
        // handles it). With retention 0, cutoff = now, so everything with
        // mtime < now is expired.
        std::fs::write(&active, b"z\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 10, Some(0)).unwrap();

        let rotated = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl."))
            })
            .count();
        // The two older siblings should be expired by time. The newest one
        // (just created by the third rotate_file) is racing with "now" so
        // it may or may not survive. At most 1 should remain.
        assert!(
            rotated <= 1,
            "expected at most 1 rotated sibling, got {rotated}"
        );
    }

    #[test]
    fn retention_none_preserves_count_only_behavior() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");

        for _ in 0..5 {
            std::fs::write(&active, b"x\n").unwrap();
            let (_buf, _len) = rotate_file(&active, 3, None).unwrap();
            sleep(Duration::from_millis(2));
        }

        let rotated = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl."))
            })
            .count();
        assert_eq!(rotated, 3, "without retention_seconds, count-only applies");
    }

    #[test]
    fn rotate_file_preserves_content_in_rotated_sibling() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        std::fs::write(&active, b"record-1\nrecord-2\n").unwrap();

        let (_buf, new_len) = rotate_file(&active, 5, None).unwrap();
        assert_eq!(new_len, 0, "new active file should start empty");

        // The rotated sibling must still hold the pre-rotation bytes.
        let siblings: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl."))
            })
            .collect();
        assert_eq!(siblings.len(), 1, "expected exactly one rotated sibling");
        let rotated_bytes = std::fs::read(siblings[0].path()).unwrap();
        assert_eq!(rotated_bytes, b"record-1\nrecord-2\n");
    }

    #[test]
    fn rotate_file_new_active_file_is_writable_and_lockable() {
        use std::io::Write as _;

        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        std::fs::write(&active, b"pre\n").unwrap();

        let (buf, _len) = rotate_file(&active, 3, None).unwrap();
        // The returned BufWriter wraps the newly-opened file; it must be
        // writable (we won't fsync here; just exercise write + flush).
        let mut buf = buf;
        buf.write_all(b"post-rotation\n").unwrap();
        buf.flush().unwrap();
        drop(buf);
        // Active file exists and now contains only the new line.
        let contents = std::fs::read_to_string(&active).unwrap();
        assert_eq!(contents, "post-rotation\n");
    }

    #[test]
    fn rotate_file_keep_zero_also_removes_base_rotation_just_created() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        std::fs::write(&active, b"initial\n").unwrap();

        rotate_file(&active, 0, None).unwrap();

        // With keep=0 the prune loop should remove every rotated sibling,
        // including the one just created by this rotation.
        let siblings: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("audit.jsonl."))
            })
            .collect();
        assert_eq!(siblings.len(), 0, "keep=0 wipes all rotated siblings");
        assert!(active.exists(), "active file still present after rotation");
    }
}
