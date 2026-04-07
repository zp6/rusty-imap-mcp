//! Startup self-check: inspect the previous run's trailing state before
//! writing a new `process_start`.
//!
//! The check is read-only and runs *after* the writer has acquired the
//! exclusive lock, so the file is stable for the duration.

use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::Path;

use serde::Deserialize;

use crate::error::AuditError;
use crate::ids::{ProcessId, Seq};

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

/// Shape we peel off the last line. Unused fields are ignored via `#[serde]`.
#[derive(Debug, Deserialize)]
struct TailEnvelope {
    seq: Seq,
    process_id: ProcessId,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    previous_file_inode: Option<u64>,
}

/// Scan the audit file from the end and return the parsed trailing state.
///
/// A partial trailing line (from a mid-record crash) is silently skipped —
/// the next-to-last newline is treated as "end of valid data". An empty or
/// nonexistent file yields `Ok(TrailingState::default())`.
///
/// # Errors
/// Any I/O error from reading the file.
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

    let file = crate::fs_ext::reader_open_options()
        .open(path)
        .map_err(|source| AuditError::Read {
            path: path.to_path_buf(),
            line: None,
            source,
        })?;
    let last_line = read_last_complete_line(&file).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        line: None,
        source,
    })?;
    let Some(last_line) = last_line else {
        return Ok(TrailingState::default());
    };
    let Ok(envelope) = serde_json::from_str::<TailEnvelope>(&last_line) else {
        return Ok(TrailingState::default());
    };
    let last_recorded_inode = if envelope.kind == "process_start" {
        envelope.previous_file_inode
    } else {
        None
    };
    Ok(TrailingState {
        last_seq: Some(envelope.seq),
        last_process_id: Some(envelope.process_id),
        last_recorded_inode,
    })
}

/// Returns the current inode of `path`. Returns `0` on non-Unix platforms
/// (Windows inode-equivalent is best-effort and not required for the spec's
/// tamper signal, which specifically says "if a manual `rm` occurred between
/// runs").
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

#[cfg(not(unix))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Reads the last line of a newline-terminated file by walking backwards in
/// 4 KiB chunks until a `\n` is found. Tolerates a partial trailing line
/// (no final `\n`) by using that partial line as the result if no earlier
/// newline exists, otherwise returning the *previous* line.
fn read_last_complete_line(file: &File) -> std::io::Result<Option<String>> {
    const CHUNK: u64 = 4096;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let mut reader = BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = len;
    loop {
        let read_from = pos.saturating_sub(CHUNK);
        let to_read = usize::try_from(pos - read_from)
            .unwrap_or_else(|_| unreachable!("chunk <= 4096 bytes"));
        reader.seek(SeekFrom::Start(read_from))?;
        let mut chunk = vec![0_u8; to_read];
        std::io::Read::read_exact(&mut reader, &mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;

        // Step 1: identify the "complete" prefix — everything up to and
        // including the last `\n` in the buffer. Anything after the last
        // `\n` is either empty (file ended with `\n`) or a partial trailing
        // line (mid-write crash) we will discard.
        let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else {
            // No newline found yet in the portion we've read.
            if read_from == 0 {
                // Entire file is one partial line. Return it as-is; the
                // caller will try to parse it and fall back to default
                // state if it's truncated.
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
            }
            pos = read_from;
            continue;
        };

        // `buf[..last_nl]` is the content that ends at a valid line boundary.
        // The LAST COMPLETE LINE is what sits between the PRIOR `\n` and
        // `last_nl`.
        let complete = &buf[..last_nl];
        if let Some(prior_nl) = complete.iter().rposition(|&b| b == b'\n') {
            let line = &complete[prior_nl + 1..];
            return Ok(Some(String::from_utf8_lossy(line).into_owned()));
        }

        // Only one newline in the buffer so far. The last complete line
        // might start earlier in the file — keep reading backwards.
        if read_from == 0 {
            // We've read the whole file and only found one `\n`. The complete
            // line runs from byte 0 up to `last_nl`.
            return Ok(Some(String::from_utf8_lossy(complete).into_owned()));
        }
        pos = read_from;
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use crate::self_check::{TrailingState, read_trailing_state};

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
        // last line is process_end → no recorded inode
        assert_eq!(state.last_recorded_inode, None);
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
    fn handles_last_line_longer_than_chunk_size() {
        let dir = TempDir::new().unwrap();
        // First a short process_start record, then a process_end record
        // whose total length exceeds CHUNK (4096 bytes). The last line
        // has to be parsed even though it spans multiple 4 KiB chunks.
        let first = "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":7777,\"audit_file_inode_changed\":false}\n";
        // Build a valid-shape process_end record padded with a long reason
        // field to push past 4 KiB.
        let padding = "x".repeat(5000);
        let second = format!(
            "{{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_end\",\"reason\":\"{padding}\",\"total_tool_calls\":0}}\n"
        );
        let mut body = String::new();
        body.push_str(first);
        body.push_str(&second);
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        // The last line is ~5 KiB — must be fully read and parsed.
        assert_eq!(state.last_seq.unwrap().get(), 2);
        // process_end → no recorded inode
        assert_eq!(state.last_recorded_inode, None);
    }
}
