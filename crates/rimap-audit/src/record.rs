//! Audit record schema per design spec §10. Every record carries the shared
//! header (`seq`, `ts`, `process_id`, `kind`) plus a kind-specific payload.
//! Serialization uses `#[serde(tag = "kind")]` to produce a flat JSON object
//! per line (JSONL).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ids::{ProcessId, Seq, Timestamp};

/// Why a process exited. Best-effort: only the SIGINT/SIGTERM/EOF paths set
/// this; a hard crash will simply leave the last record as `tool_end` or
/// whatever else was most recently flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEndReason {
    /// SIGINT received (Ctrl-C).
    SignalInt,
    /// SIGTERM received.
    SignalTerm,
    /// Stdin EOF on the MCP transport.
    Eof,
    /// Fatal error path (e.g. config load failure after first record).
    Error,
}

/// Payload of the `process_start` kind. Fields chosen to chain history across
/// restarts (see spec §10 startup self-check).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStart {
    /// Semver of the running binary.
    pub version: String,
    /// Git commit SHA embedded at build (via `vergen` when wired in Sprint 5;
    /// populated as an empty string until then).
    pub git_commit: String,
    /// Effective base posture at startup.
    pub posture: String,
    /// Absolute path of the loaded config file.
    pub config_path: PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Sequence number of the last record in the file at startup, if any.
    pub previous_last_seq: Option<Seq>,
    /// Process ID of the previous run, if the file was non-empty.
    pub previous_process_id: Option<ProcessId>,
    /// The inode of the audit file as this process observed it on open.
    /// On Windows this field stores `0` (inode concept does not apply).
    pub previous_file_inode: u64,
    /// Whether the observed inode differs from the inode recorded in the most
    /// recent prior `process_start`. Tamper signal.
    pub audit_file_inode_changed: bool,
}

/// Payload of the `process_end` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEnd {
    /// Why the process exited.
    pub reason: ProcessEndReason,
    /// Number of tool calls dispatched in this process.
    pub total_tool_calls: u64,
}

/// Top-level audit record enum. One variant per `kind` discriminator.
/// Serialized as a flat JSON object per line with `seq`, `ts`, `process_id`,
/// `kind`, and the kind-specific fields merged in via `#[serde(flatten)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Per-process monotonic sequence number.
    pub seq: Seq,
    /// Millisecond-precision UTC timestamp.
    pub ts: Timestamp,
    /// Per-process ULID.
    pub process_id: ProcessId,
    /// The kind-specific payload. `#[serde(flatten)]` + the inner `tag = "kind"`
    /// produces a single flat object with a `kind` discriminator.
    #[serde(flatten)]
    pub payload: Payload,
}

/// Outcome of an IMAP authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Credential resolved and server accepted it.
    Success,
    /// Credential resolved but server rejected it.
    Failure,
}

/// Payload of the `auth` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// Outcome.
    pub result: AuthResult,
    /// IMAP host attempted.
    pub host: String,
    /// IMAP port attempted.
    pub port: u16,
    /// IMAP login identity (typically a username or email address).
    ///
    /// **This field MUST NEVER carry a password, OAuth / SASL token, auth
    /// blob, or any other credential material.** Sprint 3's rimap-imap
    /// wiring is required to populate this from the config-resolved
    /// principal only; a copy-paste typo that lands a secret here leaks
    /// it to disk via the audit log.
    pub username: String,
    /// Observed TLS certificate fingerprint (SHA-256 hex, lowercase, no colons).
    /// `None` if the connection never reached TLS handshake completion.
    pub tls_fingerprint_sha256: Option<String>,
    /// Whether the observed fingerprint matched `imap.tls_fingerprint_sha256`
    /// from the config. `None` means the config did not pin a fingerprint.
    pub fingerprint_match: Option<bool>,
    /// On failure, the stable error code (`ERR_TLS`, `ERR_AUTH`, …); `None`
    /// on success.
    pub error_code: Option<String>,
}

/// Payload of the `tool_start` kind. Recorded before dispatch begins so a
/// crash mid-call still leaves a breadcrumb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStart {
    /// The v1 tool name as a string (matches `ToolName::as_str`).
    pub tool: String,
    /// Effective posture at dispatch time (after any config-override merge).
    pub posture_effective: String,
    /// Redacted arguments object produced by `redact::Redactor`.
    pub arguments_redacted: serde_json::Value,
    /// SHA-256 of the canonical JSON serialization of the *unredacted* payload,
    /// hex-encoded. Enables integrity checks without leaking content.
    pub arguments_hash_sha256: String,
}

/// Outcome status for a tool call. `Ok` means a structured result was
/// returned; `Error` means dispatch failed and `error_code` is populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Tool call succeeded.
    Ok,
    /// Tool call failed.
    Error,
}

/// A coarse summary of what a tool returned. Structured so reviewers can
/// reconstruct activity without reading message bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResultSummary {
    /// RFC 822 `Message-ID` values returned to the caller.
    #[serde(default)]
    pub message_ids_returned: Vec<String>,
    /// Approximate bytes returned to the caller (post-truncation).
    #[serde(default)]
    pub bytes_returned: u64,
    /// Whether the server truncated the result to fit a limit.
    #[serde(default)]
    pub truncated: bool,
    /// Security warning codes emitted alongside the payload (e.g.
    /// `LOOKALIKE_SENDER_MIXED_SCRIPT`). Sprint 4 populates this.
    #[serde(default)]
    pub security_warnings_emitted: Vec<String>,
}

/// Snapshot of the provenance ring buffer at `tool_end` time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Configured window in seconds.
    pub window_seconds: u32,
    /// Message IDs read by this process within the window, oldest to newest.
    pub message_ids_recently_read: Vec<String>,
}

/// Payload of the `tool_end` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEnd {
    /// `seq` of the paired `tool_start` record.
    pub start_seq: Seq,
    /// Tool name (duplicated from `tool_start` for self-contained log lines).
    pub tool: String,
    /// Outcome.
    pub status: ToolStatus,
    /// On `status = Error`, the stable error code; `None` on success.
    pub error_code: Option<String>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Coarse result summary.
    pub result_summary: ResultSummary,
    /// Provenance snapshot at end-of-call time.
    pub provenance: Provenance,
}

/// Payload of the `config` kind. Declared now so Sprint 5 can emit it; no
/// code path writes it yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigEvent {
    /// Path the config was loaded from.
    pub path: PathBuf,
    /// SHA-256 of the config file contents, hex-encoded.
    pub hash_sha256: String,
}

/// Payload enum discriminated by the `kind` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Process startup event — always the first record of a given `process_id`.
    ProcessStart(ProcessStart),
    /// Process shutdown event — best-effort.
    ProcessEnd(ProcessEnd),
    /// IMAP authentication attempt.
    Auth(Auth),
    /// A tool call has entered the dispatch chain.
    ToolStart(ToolStart),
    /// A tool call has exited the dispatch chain.
    ToolEnd(ToolEnd),
    /// Config-related event (declared for Sprint 5; not emitted in Sprint 2).
    Config(ConfigEvent),
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use crate::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart};

    fn sample_start() -> AuditRecord {
        AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessStart(ProcessStart {
                version: "0.1.0".to_string(),
                git_commit: String::new(),
                posture: "draft-safe".to_string(),
                config_path: PathBuf::from("/tmp/config.toml"),
                config_hash_sha256: "abcd".repeat(16),
                previous_last_seq: None,
                previous_process_id: None,
                previous_file_inode: 12345,
                audit_file_inode_changed: false,
            }),
        }
    }

    #[test]
    fn process_start_serializes_with_flat_kind_discriminator() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_start");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["posture"], "draft-safe");
        assert!(v["ts"].is_string());
        assert_eq!(v["previous_file_inode"], 12345);
        assert_eq!(v["audit_file_inode_changed"], false);
    }

    #[test]
    fn process_start_round_trips_through_serde() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_end_round_trips() {
        let rec = AuditRecord {
            seq: Seq(9999),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::SignalInt,
                total_tool_calls: 42,
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert_eq!(v["reason"], "signal_int");
        assert_eq!(v["total_tool_calls"], 42);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_end_reason_serializes_snake_case() {
        let json = serde_json::to_string(&ProcessEndReason::SignalTerm).unwrap();
        assert_eq!(json, "\"signal_term\"");
    }

    #[test]
    fn auth_record_round_trips_and_uses_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Auth(crate::record::Auth {
                result: crate::record::AuthResult::Success,
                host: "127.0.0.1".to_string(),
                port: 1143,
                username: "alice@example.test".to_string(),
                tls_fingerprint_sha256: Some("ab".repeat(32)),
                fingerprint_match: Some(true),
                error_code: None,
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["port"], 1143);
        assert_eq!(v["fingerprint_match"], true);
        assert!(v["error_code"].is_null());
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn auth_result_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::AuthResult::Failure).unwrap(),
            "\"failure\"",
        );
    }

    #[test]
    fn tool_start_round_trips_with_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(10),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolStart(crate::record::ToolStart {
                tool: "fetch_message".to_string(),
                posture_effective: "draft-safe".to_string(),
                arguments_redacted: serde_json::json!({
                    "folder": "INBOX",
                    "uid": 12345,
                    "include_html": false,
                }),
                arguments_hash_sha256: "de".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_start");
        assert_eq!(v["tool"], "fetch_message");
        assert_eq!(v["arguments_redacted"]["folder"], "INBOX");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_end_round_trips_with_provenance_and_summary() {
        let rec = AuditRecord {
            seq: Seq(11),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolEnd(crate::record::ToolEnd {
                start_seq: Seq(10),
                tool: "fetch_message".to_string(),
                status: crate::record::ToolStatus::Ok,
                error_code: None,
                duration_ms: 47,
                result_summary: crate::record::ResultSummary {
                    message_ids_returned: vec!["<abc@example>".to_string()],
                    bytes_returned: 4821,
                    truncated: false,
                    security_warnings_emitted: vec![],
                },
                provenance: crate::record::Provenance {
                    window_seconds: 60,
                    message_ids_recently_read: vec!["<abc@example>".to_string()],
                },
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_end");
        assert_eq!(v["start_seq"], 10);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["result_summary"]["bytes_returned"], 4821);
        assert_eq!(v["provenance"]["window_seconds"], 60);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn config_event_serializes_as_config_kind() {
        let rec = AuditRecord {
            seq: Seq(3),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Config(crate::record::ConfigEvent {
                path: PathBuf::from("/tmp/config.toml"),
                hash_sha256: "aa".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "config");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::ToolStatus::Error).unwrap(),
            "\"error\"",
        );
    }
}
