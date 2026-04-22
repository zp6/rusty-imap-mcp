//! Audit record schema per design spec §10. Every record carries the shared
//! header (`seq`, `ts`, `process_id`, `kind`) plus a kind-specific payload.
//! Serialization uses `#[serde(tag = "kind")]` to produce a flat JSON object
//! per line (JSONL).

use std::path::PathBuf;

use rimap_core::{ErrorCode, Posture, WarningCode, tool::ToolName};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) mod error;
pub mod ids;
pub mod peer_identity;

pub use peer_identity::PeerIdentity;

use crate::record::ids::{ProcessId, Seq, Timestamp};

/// The effective posture recorded on a `tool_start` record.
///
/// `Account` carries the per-account posture that governed dispatch;
/// `Infrastructure` marks records for infra-level tools (`use_account`,
/// `list_accounts`) that bypass per-account posture gating by design.
///
/// The serde form is a flat JSON string that matches the historical
/// on-disk representation: `Posture::as_str()` (kebab-case) for account
/// postures and the literal `"infrastructure"` for the infra variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureEffective {
    /// Per-account posture effective at dispatch time.
    Account(Posture),
    /// Infra-level tool dispatch; no per-account posture applies.
    Infrastructure,
}

impl PostureEffective {
    /// Stable string form used on disk.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account(p) => p.as_str(),
            Self::Infrastructure => "infrastructure",
        }
    }

    /// Build from an optional posture: `None` maps to `Infrastructure`.
    #[must_use]
    pub fn from_optional(posture: Option<Posture>) -> Self {
        match posture {
            Some(p) => Self::Account(p),
            None => Self::Infrastructure,
        }
    }
}

impl Serialize for PostureEffective {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PostureEffective {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::str::FromStr;
        let s = String::deserialize(deserializer)?;
        if s == "infrastructure" {
            return Ok(Self::Infrastructure);
        }
        Posture::from_str(&s)
            .map(Self::Account)
            .map_err(serde::de::Error::custom)
    }
}

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

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// Client cleanly closed its end of the socket.
    Eof,
    /// Session ended due to an error (see `last_error` on `SessionEnd`).
    Error,
    /// Daemon received a shutdown signal and is terminating all sessions.
    DaemonShutdown,
    /// Peer UID did not match the daemon's UID (scope A enforcement).
    PeerUidRejected,
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod session_end_reason_tests {
    use super::SessionEndReason;

    #[test]
    fn serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&SessionEndReason::DaemonShutdown).expect("ser"),
            r#""daemon_shutdown""#
        );
        assert_eq!(
            serde_json::to_string(&SessionEndReason::PeerUidRejected).expect("ser"),
            r#""peer_uid_rejected""#
        );
        assert_eq!(
            serde_json::to_string(&SessionEndReason::Eof).expect("ser"),
            r#""eof""#
        );
        assert_eq!(
            serde_json::to_string(&SessionEndReason::Error).expect("ser"),
            r#""error""#
        );
    }
}

/// Per-account summary for multi-account `process_start` records.
///
/// `posture` serializes via [`rimap_core::Posture`]'s kebab-case serde,
/// which matches [`rimap_core::Posture::as_str`] byte-for-byte so the
/// on-disk form is identical to the prior string-typed field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummary {
    /// Account name from config.
    pub name: String,
    /// Effective posture for this account.
    pub posture: Posture,
    /// IMAP host for this account.
    pub imap_host: String,
}

impl AccountSummary {
    /// Construct an `AccountSummary` from typed parts.
    #[must_use]
    pub fn new(name: String, posture: Posture, imap_host: String) -> Self {
        Self {
            name,
            posture,
            imap_host,
        }
    }
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
    /// Effective base posture at startup (single-account mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<Posture>,
    /// Per-account summaries (multi-account mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<AccountSummary>>,
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

/// `session_start`: emitted on daemon-accepting-a-client. One per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStart {
    /// Per-connection identifier.
    pub session_id: rimap_core::SessionId,
    /// Peer identity observed at accept time.
    pub peer_identity: crate::record::PeerIdentity,
    /// Resolved absolute socket / named-pipe path.
    pub socket_path: String,
}

/// `session_end`: emitted when a client disconnects or daemon shuts down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    /// The session being closed.
    pub session_id: rimap_core::SessionId,
    /// Why the session ended.
    pub reason: SessionEndReason,
    /// Wall-clock milliseconds from `session_start` to this record.
    pub duration_ms: u64,
    /// Tool calls completed in this session.
    pub total_tool_calls: u64,
    /// Last error seen, if any. `None` unless `reason = Error`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_error: Option<String>,
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

// `Auth` and `AuthResult` were moved to `rimap_core::auth_event` so
// `rimap-imap` can build them without depending on this crate. They
// are re-exported below at their historical names for compatibility
// with existing call sites and on-disk format tests.
pub use rimap_core::auth_event::{AuthEvent as Auth, AuthResult};

/// Payload of the `tool_start` kind. Recorded before dispatch begins so a
/// crash mid-call still leaves a breadcrumb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStart {
    /// Account name this tool call targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The v1 tool name. Serializes via [`ToolName::as_str`].
    pub tool: ToolName,
    /// Effective posture at dispatch time (after any config-override merge).
    pub posture_effective: PostureEffective,
    /// Redacted arguments object produced by `redact::Redactor`.
    pub arguments_redacted: serde_json::Value,
    /// SHA-256 of the canonical JSON serialization of the *unredacted* payload,
    /// hex-encoded. Enables integrity checks without leaking content.
    pub arguments_hash_sha256: String,
    /// Per-session identifier when emitted from a session context.
    /// `None` for daemon-level emission (e.g. emitted before any session
    /// exists, or from a pre-session context).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<rimap_core::SessionId>,
}

/// Outcome status for a tool call. `Ok` means a structured result was
/// returned; `Error` means dispatch failed and `error_code` is populated;
/// `Cancelled` means the tool call was cancelled (e.g. client disconnect, runtime shutdown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Tool call succeeded.
    Ok,
    /// Tool call failed.
    Error,
    /// Tool call was cancelled (e.g. client disconnect, runtime shutdown).
    /// Written by the cancellation drop-guard on future drop; see #99.
    Cancelled,
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
    /// `lookalike_mixed_script`). Serialized as `snake_case` strings
    /// via [`WarningCode`]'s serde impl, matching the on-disk form
    /// the field carried when it was typed `Vec<String>`.
    #[serde(default)]
    pub security_warnings_emitted: Vec<WarningCode>,
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
    /// Account name this tool call targeted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// `seq` of the paired `tool_start` record.
    pub start_seq: Seq,
    /// Tool name (duplicated from `tool_start` for self-contained log lines).
    pub tool: ToolName,
    /// Outcome.
    pub status: ToolStatus,
    /// On `status = Error`, the stable error code; `None` on success.
    pub error_code: Option<ErrorCode>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Coarse result summary.
    pub result_summary: ResultSummary,
    /// Provenance snapshot at end-of-call time.
    pub provenance: Provenance,
    /// Per-session identifier when emitted from a session context.
    /// `None` for daemon-level emission (e.g. emitted before any session
    /// exists, or from a pre-session context).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<rimap_core::SessionId>,
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
    /// `session_start` payload.
    SessionStart(SessionStart),
    /// `session_end` payload.
    SessionEnd(SessionEnd),
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod session_record_tests {
    use super::{AuditRecord, Payload, PeerIdentity, SessionEnd, SessionEndReason, SessionStart};
    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use rimap_core::SessionId;

    #[test]
    fn session_start_serializes_with_all_fields() {
        let id = SessionId::new();
        let s = SessionStart {
            session_id: id,
            peer_identity: PeerIdentity::Unix {
                uid: 1000,
                pid: Some(42),
            },
            socket_path: "/run/user/1000/rusty-imap-mcp/daemon.sock".to_string(),
        };
        let j: serde_json::Value = serde_json::to_value(&s).expect("ser");
        assert_eq!(j["session_id"], serde_json::Value::String(id.to_string()));
        assert_eq!(j["peer_identity"]["platform"], "unix");
        assert_eq!(j["peer_identity"]["uid"], 1000);
        assert_eq!(
            j["socket_path"],
            "/run/user/1000/rusty-imap-mcp/daemon.sock"
        );
    }

    #[test]
    fn session_end_omits_last_error_when_none() {
        let s = SessionEnd {
            session_id: SessionId::new(),
            reason: SessionEndReason::Eof,
            duration_ms: 12_345,
            total_tool_calls: 7,
            last_error: None,
        };
        let j = serde_json::to_string(&s).expect("ser");
        assert!(
            !j.contains("last_error"),
            "last_error should be omitted when None; got {j}"
        );
    }

    #[test]
    fn session_end_includes_last_error_when_some() {
        let s = SessionEnd {
            session_id: SessionId::new(),
            reason: SessionEndReason::Error,
            duration_ms: 99,
            total_tool_calls: 0,
            last_error: Some("ioerr: EPIPE".to_string()),
        };
        let j: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).expect("ser")).expect("parse");
        assert_eq!(j["last_error"], "ioerr: EPIPE");
    }

    #[test]
    fn session_start_serializes_as_session_start_kind() {
        let id = SessionId::new();
        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::SessionStart(SessionStart {
                session_id: id,
                peer_identity: PeerIdentity::Unix {
                    uid: 501,
                    pid: Some(99),
                },
                socket_path: "/run/user/501/rusty-imap-mcp/daemon.sock".to_string(),
            }),
        };
        let json = serde_json::to_string(&rec).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["kind"], "session_start");
        assert_eq!(v["session_id"], serde_json::Value::String(id.to_string()));
        assert_eq!(v["peer_identity"]["platform"], "unix");
        assert_eq!(v["peer_identity"]["uid"], 501);
        assert_eq!(v["socket_path"], "/run/user/501/rusty-imap-mcp/daemon.sock");
        let back: AuditRecord = serde_json::from_str(&json).expect("deser");
        assert_eq!(back, rec);
    }

    #[test]
    fn session_end_serializes_as_session_end_kind() {
        let id = SessionId::new();
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::SessionEnd(SessionEnd {
                session_id: id,
                reason: SessionEndReason::Error,
                duration_ms: 8_500,
                total_tool_calls: 3,
                last_error: Some("ioerr: EPIPE".to_string()),
            }),
        };
        let json = serde_json::to_string(&rec).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["kind"], "session_end");
        assert_eq!(v["session_id"], serde_json::Value::String(id.to_string()));
        assert_eq!(v["reason"], "error");
        assert_eq!(v["duration_ms"], 8_500);
        assert_eq!(v["total_tool_calls"], 3);
        assert_eq!(v["last_error"], "ioerr: EPIPE");
        let back: AuditRecord = serde_json::from_str(&json).expect("deser");
        assert_eq!(back, rec);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use rimap_core::{Posture, tool::ToolName};

    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{
        AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart, ToolStatus,
    };

    fn sample_start() -> AuditRecord {
        AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessStart(ProcessStart {
                version: "0.1.0".to_string(),
                git_commit: String::new(),
                posture: Some(Posture::DraftSafe),
                accounts: None,
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
        assert!(v["accounts"].is_null(), "accounts should be omitted");
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
                account: None,
                result: crate::record::AuthResult::Success,
                host: "127.0.0.1".to_string(),
                port: 1143,
                username: "alice@example.test".to_string(),
                tls_fingerprint_sha256: Some("ab".repeat(32)),
                fingerprint_match: Some(true),
                error_code: None,
                credential_source: None,
                session_id: None,
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
                account: None,
                tool: ToolName::FetchMessage,
                posture_effective: crate::record::PostureEffective::Account(Posture::DraftSafe),
                arguments_redacted: serde_json::json!({
                    "folder": "INBOX",
                    "uid": 12345,
                    "include_html": false,
                }),
                arguments_hash_sha256: "de".repeat(32),
                session_id: None,
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
                account: None,
                start_seq: Seq(10),
                tool: ToolName::FetchMessage,
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
                session_id: None,
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

    #[test]
    fn tool_status_cancelled_serializes_as_snake_case() {
        let j = serde_json::to_string(&ToolStatus::Cancelled).unwrap();
        assert_eq!(j, "\"cancelled\"");
        let back: ToolStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ToolStatus::Cancelled);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod session_id_threading_tests {
    use crate::record::{PostureEffective, ToolStart};
    use rimap_core::{SessionId, tool::ToolName};

    #[test]
    fn tool_start_with_session_id_serializes_it() {
        let sid = SessionId::new();
        let t = build_tool_start(Some(sid));
        let j = serde_json::to_value(&t).expect("ser");
        assert_eq!(j["session_id"], sid.to_string());
    }

    #[test]
    fn tool_start_without_session_id_omits_it() {
        let t = build_tool_start(None);
        let j = serde_json::to_value(&t).expect("ser");
        assert!(
            j.get("session_id").is_none(),
            "None should be omitted, got {j}"
        );
    }

    fn build_tool_start(session_id: Option<SessionId>) -> ToolStart {
        ToolStart {
            account: None,
            tool: ToolName::FetchMessage,
            posture_effective: PostureEffective::Account(rimap_core::Posture::DraftSafe),
            arguments_redacted: serde_json::json!({
                "folder": "INBOX",
                "uid": 12345,
                "include_html": false,
            }),
            arguments_hash_sha256: "de".repeat(32),
            session_id,
        }
    }
}
