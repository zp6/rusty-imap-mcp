//! Shared-lock JSONL reader for `audit merge` and external tools.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use fs4::fs_std::FileExt;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::record::{AuditRecord, Payload};

/// Filter predicate for `audit merge`. Empty fields mean "no constraint".
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Inclusive lower bound on `ts`.
    pub since: Option<OffsetDateTime>,
    /// Inclusive upper bound on `ts`.
    pub until: Option<OffsetDateTime>,
    /// If set, only `tool_start` / `tool_end` records whose `tool` field
    /// exactly matches are returned. All other payload kinds
    /// (`process_start`, `process_end`, `auth`, `config`) are excluded.
    pub tool: Option<String>,
    /// Required `kind` field (exact match).
    pub kind: Option<String>,
    /// Required `process_id` (canonical ULID string).
    pub process: Option<String>,
}

impl Filter {
    /// Whether `record` passes this filter.
    #[must_use]
    pub fn matches(&self, record: &AuditRecord) -> bool {
        if let Some(since) = self.since
            && record.ts.offset() < since
        {
            return false;
        }
        if let Some(until) = self.until
            && record.ts.offset() > until
        {
            return false;
        }
        if let Some(ref want) = self.process
            && record.process_id.to_string() != *want
        {
            return false;
        }
        if let Some(ref want) = self.kind
            && kind_of(&record.payload) != want
        {
            return false;
        }
        if let Some(ref want) = self.tool {
            let got = match &record.payload {
                Payload::ToolStart(t) => Some(&t.tool),
                Payload::ToolEnd(t) => Some(&t.tool),
                Payload::ProcessStart(_)
                | Payload::ProcessEnd(_)
                | Payload::Auth(_)
                | Payload::Config(_) => None,
            };
            match got {
                Some(name) if name == want => {}
                Some(_) | None => return false,
            }
        }
        true
    }
}

fn kind_of(payload: &Payload) -> &'static str {
    match payload {
        Payload::ProcessStart(_) => "process_start",
        Payload::ProcessEnd(_) => "process_end",
        Payload::Auth(_) => "auth",
        Payload::ToolStart(_) => "tool_start",
        Payload::ToolEnd(_) => "tool_end",
        Payload::Config(_) => "config",
    }
}

/// Open the audit file with a shared lock.
///
/// # Errors
/// - [`AuditError::Open`] on I/O failure.
/// - [`AuditError::Locked`] when the file is held exclusively by another
///   process (e.g. a running server).
pub fn open_shared(path: &Path) -> Result<File, AuditError> {
    let file = crate::fs_ext::reader_open_options()
        .open(path)
        .map_err(|source| AuditError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    match FileExt::try_lock_shared(&file) {
        Ok(true) => Ok(file),
        Ok(false) => Err(AuditError::Locked {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(AuditError::Open {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Stream records from `path` through `filter` into `on_record`. A partial
/// trailing line emits a single `tracing::warn!` and is skipped. Any other
/// parse failure aborts with [`AuditError::Read`] containing the offending
/// line number.
///
/// # Errors
/// I/O error from reading the file, or a JSON parse failure on a
/// non-trailing line.
pub fn stream_records<F>(
    path: &Path,
    filter: &Filter,
    mut on_record: F,
) -> Result<usize, AuditError>
where
    F: FnMut(&AuditRecord) -> Result<(), AuditError>,
{
    let file = open_shared(path)?;
    let reader = BufReader::new(file);
    let mut lines: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|source| AuditError::Read {
            path: path.to_path_buf(),
            line: None,
            source,
        })?;
        lines.push(line);
    }

    let mut count = 0_usize;
    let total = lines.len();
    for (idx, line) in lines.into_iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let parsed: Result<AuditRecord, _> = serde_json::from_str(&line);
        match parsed {
            Ok(rec) => {
                if filter.matches(&rec) {
                    on_record(&rec)?;
                    count += 1;
                }
            }
            Err(err) if idx + 1 == total => {
                tracing::warn!(
                    path = %path.display(),
                    line = idx + 1,
                    error = %err,
                    "skipping malformed trailing line in audit file",
                );
            }
            Err(err) => {
                return Err(AuditError::Read {
                    path: path.to_path_buf(),
                    line: Some(idx + 1),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
                });
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;
    use time::macros::datetime;

    use crate::ids::{ProcessId, Timestamp};
    use crate::reader::{Filter, stream_records};
    use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

    fn sample(seq: u64, pid: ProcessId) -> AuditRecord {
        AuditRecord {
            seq: crate::ids::Seq(seq),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: seq,
            }),
        }
    }

    fn write_lines(dir: &TempDir, name: &str, lines: &[String]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        path
    }

    #[test]
    fn streams_all_records_with_empty_filter() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut seen = Vec::new();
        let count = stream_records(&path, &Filter::default(), |rec| {
            seen.push(rec.seq.get());
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn malformed_trailing_line_is_skipped_with_warning() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let mut lines: Vec<String> = (1_u64..=2)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        lines.push("{\"seq\":3,\"kind\":\"xxx".to_string());
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut count = 0;
        stream_records(&path, &Filter::default(), |_rec| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn malformed_non_trailing_line_is_an_error() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let good = serde_json::to_string(&sample(1, pid)).unwrap();
        let good2 = serde_json::to_string(&sample(2, pid)).unwrap();
        let lines = vec!["not json".to_string(), good, good2];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let err = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap_err();
        assert!(format!("{err}").contains("line "));
    }

    #[test]
    fn filter_by_kind_matches_exact_string() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            kind: Some("process_end".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 3);

        let filter = Filter {
            kind: Some("process_start".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn filter_by_process_id_matches() {
        let dir = TempDir::new().unwrap();
        let pid_a = ProcessId::new_now();
        let pid_b = ProcessId::new_now();
        let lines = vec![
            serde_json::to_string(&sample(1, pid_a)).unwrap(),
            serde_json::to_string(&sample(2, pid_b)).unwrap(),
            serde_json::to_string(&sample(3, pid_a)).unwrap(),
        ];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            process: Some(pid_a.to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn empty_file_streams_zero_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        std::fs::File::create(&path).unwrap();
        let count = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn tool_filter_excludes_non_tool_records() {
        use crate::record::ToolStart;

        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let tool_rec = AuditRecord {
            seq: crate::ids::Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ToolStart(ToolStart {
                tool: "read_email".to_string(),
                posture_effective: "draft-safe".to_string(),
                arguments_redacted: serde_json::json!({}),
                arguments_hash_sha256: "0".repeat(64),
            }),
        };
        let proc_rec = sample(2, pid);
        let lines = vec![
            serde_json::to_string(&tool_rec).unwrap(),
            serde_json::to_string(&proc_rec).unwrap(),
        ];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            tool: Some("read_email".to_string()),
            ..Filter::default()
        };
        let mut seen_kinds = Vec::new();
        let count = stream_records(&path, &filter, |rec| {
            seen_kinds.push(match &rec.payload {
                Payload::ToolStart(_) => "tool_start",
                Payload::ToolEnd(_) => "tool_end",
                Payload::ProcessStart(_) => "process_start",
                Payload::ProcessEnd(_) => "process_end",
                Payload::Auth(_) => "auth",
                Payload::Config(_) => "config",
            });
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(seen_kinds, vec!["tool_start"]);
    }

    #[test]
    fn filter_by_since_and_until_restricts_range() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines = vec![serde_json::to_string(&sample(1, pid)).unwrap()];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            since: Some(datetime!(2027-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            until: Some(datetime!(2020-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            since: Some(datetime!(2026-01-01 00:00:00.000 UTC)),
            until: Some(datetime!(2026-12-31 23:59:59.999 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 1);
    }
}
