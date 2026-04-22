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
    /// # Errors
    /// Propagates any error from the underlying audit writer.
    pub fn log_tool_start(&self, mut inputs: ToolStartInputs) -> Result<Seq, AuditError> {
        inputs.session_id = Some(self.session_id);
        self.writer.log_tool_start(inputs)
    }

    /// Emit a `tool_end`, injecting `session_id`.
    ///
    /// # Errors
    /// Propagates any error from the underlying audit writer.
    pub fn log_tool_end(&self, mut inputs: ToolEndInputs) -> Result<Seq, AuditError> {
        inputs.session_id = Some(self.session_id);
        self.writer.log_tool_end(inputs)
    }

    /// The underlying writer, for emitting records that are explicitly
    /// NOT session-scoped (e.g. `process_start` / `process_end`).
    /// Call sites must justify their non-session status.
    #[must_use]
    pub fn raw_writer(&self) -> &AuditWriter {
        &self.writer
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::SessionAuditSink;
    use rimap_audit::record::ids::Seq;
    use rimap_audit::{
        AuditOptions, AuditWriter, Provenance, ResultSummary, ToolEndInputs, ToolStartInputs,
        ToolStatus,
    };
    use rimap_core::{SessionId, tool::ToolName};
    use tempfile::TempDir;

    fn fresh_writer() -> (TempDir, AuditWriter) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();
        (dir, writer)
    }

    #[test]
    fn log_tool_start_injects_session_id_even_if_caller_sets_none() {
        let (_dir, writer) = fresh_writer();
        let sid = SessionId::new();
        let sink = SessionAuditSink::new(writer, sid);
        let seq = sink
            .log_tool_start(ToolStartInputs {
                tool: ToolName::ListAccounts,
                posture_effective: None,
                account: None,
                arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
                arguments_hash_sha256: "0".repeat(64),
                session_id: None,
            })
            .unwrap();
        let _ = seq;
        assert_eq!(sink.session_id(), sid);
    }

    #[test]
    fn log_tool_end_injects_session_id_even_if_caller_sets_none() {
        let (_dir, writer) = fresh_writer();
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
        assert_eq!(sink.session_id(), sid);
    }
}
