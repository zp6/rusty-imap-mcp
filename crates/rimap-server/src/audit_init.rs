//! Initialize the audit writer for a long-running process: pre-scan trailing
//! state, open the writer, capture the current inode, emit `process_start`.

use std::path::Path;

use rimap_audit::{AuditError, AuditOptions, AuditWriter, ProcessStartInputs, Seq};
use rimap_config::ValidatedConfig;
use sha2::{Digest, Sha256};

/// Open the audit writer, run the pre-flight self-check, and emit the
/// `process_start` record. Returns the writer ready for production use.
///
/// # Errors
/// Propagates any `AuditError` from the trailing-state read, open, inode
/// fetch, or `process_start` write.
pub fn init_audit_writer(
    cfg: &ValidatedConfig,
    config_file_path: &Path,
) -> Result<AuditWriter, AuditError> {
    let audit_path = &cfg.config.audit.path;
    let trailing = rimap_audit::read_trailing_state(audit_path)?;
    let initial_seq = trailing.last_seq.map_or(Seq::FIRST, Seq::next);

    let writer = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
        rotate_bytes: cfg.config.audit.rotate_bytes,
        rotate_keep: cfg.config.audit.rotate_keep,
        retention_seconds: cfg.config.audit.retention_seconds,
        fail_open: cfg.config.audit.fail_open,
        initial_seq,
    })?;

    if let Some(parent) = writer.path().parent() {
        rimap_audit::backup_exclude::exclude_from_backup(parent);
    }

    let current = rimap_audit::current_inode(audit_path)?;
    let config_hash = compute_config_hash(config_file_path);

    writer.log_process_start(ProcessStartInputs {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: String::new(),
        posture: Some(cfg.config.security.posture.to_string()),
        accounts: None,
        config_path: config_file_path.to_path_buf(),
        config_hash_sha256: config_hash,
        trailing,
        current_inode: current,
    })?;

    Ok(writer)
}

fn compute_config_hash(path: &Path) -> String {
    // Intentional: if the config file disappears between load and hash,
    // record an empty hash rather than panic. The config was already
    // successfully loaded earlier in the boot sequence; this is a startup
    // hot path, not user-facing input validation.
    let bytes = std::fs::read(path).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    use super::init_audit_writer;

    fn write_config(dir: &TempDir) -> std::path::PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
posture = "readonly"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit.display(),
            dir.path().display()
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    #[test]
    fn process_start_emitted_as_first_record() {
        use sha2::{Digest, Sha256};

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);

        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate(raw).unwrap();

        // Scope the writer so the file lock is released before reading.
        let audit_path = validated.config.audit.path.clone();
        {
            init_audit_writer(&validated, &config_path).unwrap();
        }
        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let first_line = contents.lines().next().unwrap();
        let first: serde_json::Value = serde_json::from_str(first_line).unwrap();

        assert_eq!(first["kind"], "process_start");
        assert_eq!(first["seq"], 1);
        assert_eq!(first["posture"], "readonly");

        // config_path in the record must be the TOML file, not the audit log.
        assert_eq!(
            first["config_path"].as_str().unwrap(),
            config_path.to_str().unwrap()
        );

        // config_hash_sha256 must be the hash of the config file contents.
        let config_bytes = std::fs::read(&config_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&config_bytes);
        let expected_hash = hex::encode(hasher.finalize());
        assert_eq!(first["config_hash_sha256"].as_str().unwrap(), expected_hash);
    }

    #[test]
    fn process_end_writes_after_start() {
        use rimap_audit::ProcessEndReason;

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate(raw).unwrap();
        let audit_path = validated.config.audit.path.clone();

        {
            let writer = init_audit_writer(&validated, &config_path).unwrap();
            writer.log_process_end(ProcessEndReason::Eof, 0).unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["kind"], "process_start");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["kind"], "process_end");
        assert_eq!(second["seq"], 2);
    }

    #[test]
    fn seq_continues_from_trailing_state() {
        use rimap_audit::{
            AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason,
            ProcessId, Seq, Timestamp,
        };

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate(raw).unwrap();
        let audit_path = validated.config.audit.path.clone();

        // Pre-populate the audit file with some records so trailing state is non-empty.
        {
            let writer = AuditWriter::open(&AuditOptions {
                path: audit_path.clone(),
                rotate_bytes: 0,
                rotate_keep: 0,
                retention_seconds: None,
                fail_open: false,
                initial_seq: Seq::FIRST,
            })
            .unwrap();
            let pid = ProcessId::new_now();
            writer
                .write_record(&AuditRecord {
                    seq: Seq(1),
                    ts: Timestamp::now(),
                    process_id: pid,
                    payload: Payload::ProcessEnd(ProcessEnd {
                        reason: ProcessEndReason::Eof,
                        total_tool_calls: 0,
                    }),
                })
                .unwrap();
        }

        // init_audit_writer should resume from seq 2.
        {
            init_audit_writer(&validated, &config_path).unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert!(lines.len() >= 2, "expected at least 2 records");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["kind"], "process_start");
        assert_eq!(second["seq"], 2);
    }
}
