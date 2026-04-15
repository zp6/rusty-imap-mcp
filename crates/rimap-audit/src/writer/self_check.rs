//! Startup self-check: inspect the previous run's trailing state before
//! writing a new `process_start`.
//!
//! The check is read-only and runs *after* the writer has acquired the
//! exclusive lock, so the file is stable for the duration. It streams the
//! file forward, tolerates a partial trailing line (mid-write crash), and
//! tracks both the last parseable record (for `seq` / `process_id`
//! continuation) and the last `process_start` (for the tamper-inode signal).

use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Deserialize;

use crate::AuditError;
use crate::record::ids::{ProcessId, Seq};

/// Hard cap on the file size the self-check will read. Files larger than
/// this cause the self-check to return default state with a `tracing::warn!`.
/// The default `rotate_bytes` is 10 MiB so this has headroom for legitimate
/// use; adversarial files are rejected.
const MAX_SELF_CHECK_BYTES: u64 = 32 * 1024 * 1024;

/// Hard cap on any single line. Longer lines cause the self-check to skip
/// the overflowing line (treated as tampered).
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Result of reading the trailing state of an existing audit file. Every
/// field is `None` when the file is empty or the last line cannot be parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrailingState {
    /// `seq` of the last valid record.
    pub last_seq: Option<Seq>,
    /// `process_id` of the last valid record.
    pub last_process_id: Option<ProcessId>,
    /// Inode reported by the most recent `process_start` record, if any.
    /// Compared against the current file's inode to detect tampering.
    pub last_recorded_inode: Option<u64>,
}

/// Shape we peel off each line. Unused fields are ignored via `#[serde]`.
#[derive(Debug, Deserialize)]
struct TailEnvelope {
    seq: Seq,
    process_id: ProcessId,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    previous_file_inode: Option<u64>,
}

/// Scan the audit file forward and return the parsed trailing state.
///
/// The scan tracks the last parseable record (for `seq`/`process_id`
/// continuation) AND the last parseable `process_start` (for the
/// `previous_file_inode` tamper signal). A malformed trailing line (from a
/// mid-record crash) is silently skipped. A file larger than
/// `MAX_SELF_CHECK_BYTES` is treated as tampered and default state is
/// returned.
///
/// # Errors
/// I/O errors from metadata or reading the file (other than oversize, which
/// is handled internally).
pub fn read_trailing_state(path: &Path) -> Result<TrailingState, AuditError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TrailingState::default());
        }
        Err(source) => {
            return Err(AuditError::Read {
                path: path.to_path_buf(),
                line: None,
                source,
            });
        }
    };
    if meta.len() == 0 {
        return Ok(TrailingState::default());
    }
    if meta.len() > MAX_SELF_CHECK_BYTES {
        tracing::warn!(
            path = %path.display(),
            len = meta.len(),
            cap = MAX_SELF_CHECK_BYTES,
            "audit file exceeds self-check size cap; treating as tampered",
        );
        return Ok(TrailingState::default());
    }

    let file = crate::fs::reader_open_options()
        .open(path)
        .map_err(|source| AuditError::Read {
            path: path.to_path_buf(),
            line: None,
            source,
        })?;

    let mut reader = BufReader::new(file);
    let mut last_seq: Option<Seq> = None;
    let mut last_process_id: Option<ProcessId> = None;
    let mut last_recorded_inode: Option<u64> = None;
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let n = match reader.read_line(&mut line_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(source) => {
                return Err(AuditError::Read {
                    path: path.to_path_buf(),
                    line: None,
                    source,
                });
            }
        };

        // A line without a trailing newline is a partial/truncated trailing
        // line; skip it regardless of parseability.
        if !line_buf.ends_with('\n') {
            tracing::warn!(
                path = %path.display(),
                "self-check skipping partial trailing line",
            );
            break;
        }

        // Enforce the per-line cap. Lines at the cap are treated as
        // tampered: skip and continue (rather than abort) so one bad line
        // doesn't hide a good prior inode.
        if n > MAX_LINE_BYTES {
            tracing::warn!(
                path = %path.display(),
                bytes = n,
                cap = MAX_LINE_BYTES,
                "self-check skipping oversize line",
            );
            continue;
        }

        let trimmed = line_buf.trim_end_matches('\n').trim_end_matches('\r');
        let Ok(envelope) = serde_json::from_str::<TailEnvelope>(trimmed) else {
            // Malformed but newline-terminated line: skip quietly.
            continue;
        };

        last_seq = Some(envelope.seq);
        last_process_id = Some(envelope.process_id);
        if envelope.kind == "process_start" {
            last_recorded_inode = envelope.previous_file_inode;
        }
    }

    Ok(TrailingState {
        last_seq,
        last_process_id,
        last_recorded_inode,
    })
}

/// Returns the current inode of `path`. On Unix, this is the POSIX `ino`
/// from `stat`. On Windows, this is the NTFS file reference number from
/// `MetadataExt::file_index`, which is stable across re-opens of the same
/// file. `ReFS`, `FAT32`, and some network filesystems do not provide a
/// stable file index — `file_index` returns `None` and this function
/// returns `0`, which the tamper-signal logic interprets as "unknown, do
/// not flag". Returns `0` on platforms that are neither Unix nor Windows.
///
/// # Errors
/// I/O error reading metadata.
pub fn current_inode(path: &Path) -> Result<u64, AuditError> {
    let meta = std::fs::metadata(path).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        line: None,
        source,
    })?;
    Ok(inode_of(&meta))
}

#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(windows)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    // file_index is the NTFS file reference number — stable across
    // re-opens of the same file. Returns Option<u64>; None on
    // filesystems that don't support file indices (ReFS, FAT32, some
    // network filesystems). Treat None as 0 = "unknown", which the
    // tamper-signal logic interprets as "do not flag".
    meta.file_index().unwrap_or(0)
}

#[cfg(not(any(unix, windows)))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use crate::writer::self_check::{TrailingState, read_trailing_state};

    fn write_file(dir: &TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body).unwrap();
        path
    }

    #[test]
    fn nonexistent_file_returns_default_state() {
        let dir = TempDir::new().unwrap();
        let state = read_trailing_state(&dir.path().join("nope.jsonl")).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn empty_file_returns_default_state() {
        let dir = TempDir::new().unwrap();
        let path = write_file(&dir, "a.jsonl", b"");
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn extracts_last_seq_and_process_id_from_trailing_line() {
        let dir = TempDir::new().unwrap();
        let body = concat!(
            "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",",
            "\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",",
            "\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",",
            "\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",",
            "\"previous_last_seq\":null,\"previous_process_id\":null,",
            "\"previous_file_inode\":1234,\"audit_file_inode_changed\":false}\n",
            "{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",",
            "\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_end\",",
            "\"reason\":\"eof\",\"total_tool_calls\":0}\n",
        );
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_seq.unwrap().get(), 2);
        assert!(state.last_process_id.is_some());
        // process_start inode is recorded from scanning forward even though
        // the last record is process_end.
        assert_eq!(state.last_recorded_inode, Some(1234));
    }

    #[test]
    fn records_inode_when_last_line_is_process_start() {
        let dir = TempDir::new().unwrap();
        let body = "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":9999,\"audit_file_inode_changed\":false}\n";
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_recorded_inode, Some(9999));
    }

    #[test]
    fn partial_trailing_line_is_ignored_in_favor_of_prior_line() {
        let dir = TempDir::new().unwrap();
        let body = concat!(
            "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":12345,\"audit_file_inode_changed\":false}\n",
            "{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",\"process",
        );
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_seq.unwrap().get(), 1);
        assert_eq!(state.last_recorded_inode, Some(12345));
    }

    #[test]
    fn completely_unparsable_trailing_line_returns_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(&dir, "a.jsonl", b"not json at all\n");
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn records_most_recent_process_start_inode_after_process_end() {
        // Scenario: process_start (inode=9999) then process_end. The
        // tamper-inode signal should still surface 9999 because we scan
        // for the last process_start, not just the last line.
        let dir = TempDir::new().unwrap();
        let body = concat!(
            "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":9999,\"audit_file_inode_changed\":false}\n",
            "{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_end\",\"reason\":\"eof\",\"total_tool_calls\":0}\n",
        );
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_seq.unwrap().get(), 2);
        assert_eq!(state.last_recorded_inode, Some(9999));
    }

    #[test]
    fn file_exceeding_size_cap_returns_default_state() {
        // Write a file just over 32 MiB. Forward scan should refuse and
        // return TrailingState::default() with a warn.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("big.jsonl");
        // Cheapest way to create a 32 MiB+ file: set_len via File.
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(33 * 1024 * 1024).unwrap();
        drop(f);
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn oversize_line_is_skipped_but_prior_record_still_parsed() {
        // First a valid process_start, then a 2 MiB single line, then no
        // trailing newline. Expect the process_start's inode to survive.
        let dir = TempDir::new().unwrap();
        let first = "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":5555,\"audit_file_inode_changed\":false}\n";
        let oversize = "x".repeat(2 * 1024 * 1024);
        let mut body = String::new();
        body.push_str(first);
        body.push_str(&oversize);
        body.push('\n');
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_recorded_inode, Some(5555));
    }
}
