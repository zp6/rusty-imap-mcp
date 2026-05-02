//! `SessionAuditSink`: a handle that automatically injects `session_id`
//! into every audit record it emits. Constructed per-session; the raw
//! `AuditWriter` is never exposed to session-scoped code.

use rimap_audit::record::ids::Seq;
use rimap_audit::{AuditError, AuditWriter, ToolEndInputs, ToolStartInputs};
use rimap_core::SessionId;

/// Session-scoped audit emitter. Construct via [`SessionAuditSink::new`];
/// every emitted record carries `session_id = Some(self.session_id)`.
#[derive(Clone)]
pub struct SessionAuditSink {
    writer: AuditWriter,
    session_id: SessionId,
}

impl SessionAuditSink {
    /// Build from a shared `AuditWriter` and a `SessionId`.
    #[must_use]
    pub fn new(writer: AuditWriter, session_id: SessionId) -> Self {
        Self { writer, session_id }
    }

    /// The session this sink emits on behalf of.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Emit a `tool_start`, injecting `session_id`.
    ///
    /// If the caller supplies a non-`None` `session_id` that differs from
    /// this sink's `session_id`, a warning is logged and the supplied value
    /// is overridden. The sink's `session_id` is authoritative.
    ///
    /// # Errors
    /// Propagates any error from the underlying audit writer.
    pub fn log_tool_start(&self, mut inputs: ToolStartInputs) -> Result<Seq, AuditError> {
        if let Some(supplied) = inputs.session_id
            && supplied != self.session_id
        {
            tracing::warn!(
                supplied = %supplied,
                actual = %self.session_id,
                "SessionAuditSink overriding caller-supplied session_id",
            );
        }
        inputs.session_id = Some(self.session_id);
        self.writer.log_tool_start(inputs)
    }

    /// Emit a `tool_end`, injecting `session_id`.
    ///
    /// If the caller supplies a non-`None` `session_id` that differs from
    /// this sink's `session_id`, a warning is logged and the supplied value
    /// is overridden. The sink's `session_id` is authoritative.
    ///
    /// # Errors
    /// Propagates any error from the underlying audit writer.
    pub fn log_tool_end(&self, mut inputs: ToolEndInputs) -> Result<Seq, AuditError> {
        if let Some(supplied) = inputs.session_id
            && supplied != self.session_id
        {
            tracing::warn!(
                supplied = %supplied,
                actual = %self.session_id,
                "SessionAuditSink overriding caller-supplied session_id",
            );
        }
        inputs.session_id = Some(self.session_id);
        self.writer.log_tool_end(inputs)
    }
}

// Unix-only: tests use `PermissionsExt::from_mode` for the audit-writer
// parent-mode check (#147). Cross-platform helper tracked in #219.
#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::SessionAuditSink;
    use rimap_audit::record::ids::Seq;
    use rimap_audit::{
        AuditOptions, AuditWriter, Provenance, ResultSummary, ToolEndInputs, ToolStartInputs,
        ToolStatus,
    };
    use rimap_core::{SessionId, tool::ToolName};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn tight_tempdir() -> TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn fresh_writer() -> (TempDir, AuditWriter, PathBuf) {
        let dir = tight_tempdir();
        let path = dir.path().join("a.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();
        (dir, writer, path)
    }

    #[test]
    fn log_tool_start_injects_session_id_even_if_caller_sets_none() {
        let (_dir, writer, path) = fresh_writer();
        let sid = SessionId::new();
        let sink = SessionAuditSink::new(writer, sid);
        sink.log_tool_start(ToolStartInputs {
            tool: ToolName::ListAccounts,
            posture_effective: None,
            account: None,
            arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
            arguments_hash_sha256: "0".repeat(64),
            session_id: None,
        })
        .unwrap();
        drop(sink);
        let contents = std::fs::read_to_string(&path).unwrap();
        let last = contents.lines().last().unwrap();
        let v: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(v["kind"], "tool_start");
        assert_eq!(v["session_id"], sid.to_string());
    }

    #[test]
    fn log_tool_end_injects_session_id_even_if_caller_sets_none() {
        let (_dir, writer, path) = fresh_writer();
        let sid = SessionId::new();
        let sink = SessionAuditSink::new(writer, sid);
        let start_seq = sink
            .log_tool_start(ToolStartInputs {
                tool: ToolName::ListAccounts,
                posture_effective: None,
                account: None,
                arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
                arguments_hash_sha256: "0".repeat(64),
                session_id: None,
            })
            .unwrap();
        sink.log_tool_end(ToolEndInputs {
            start_seq,
            tool: ToolName::ListAccounts,
            account: None,
            status: ToolStatus::Ok,
            error_code: None,
            duration_ms: 1,
            result_summary: ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
            session_id: None,
        })
        .unwrap();
        drop(sink);
        let contents = std::fs::read_to_string(&path).unwrap();
        let last_tool_end = contents
            .lines()
            .rfind(|line| line.contains("\"tool_end\""))
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(last_tool_end).unwrap();
        assert_eq!(v["kind"], "tool_end");
        assert_eq!(v["session_id"], sid.to_string());
    }

    #[test]
    fn log_tool_start_overrides_caller_provided_session_id() {
        let (_dir, writer, path) = fresh_writer();
        let sid_a = SessionId::new();
        let sid_b = SessionId::new();
        let sink = SessionAuditSink::new(writer, sid_a);
        sink.log_tool_start(ToolStartInputs {
            tool: ToolName::ListAccounts,
            posture_effective: None,
            account: None,
            arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
            arguments_hash_sha256: "0".repeat(64),
            session_id: Some(sid_b),
        })
        .unwrap();
        drop(sink);
        let contents = std::fs::read_to_string(&path).unwrap();
        let last = contents.lines().last().unwrap();
        let v: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(v["kind"], "tool_start");
        assert_eq!(v["session_id"], sid_a.to_string());
        assert_ne!(v["session_id"], sid_b.to_string());
    }
}
