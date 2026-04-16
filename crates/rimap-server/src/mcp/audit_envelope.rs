//! Audit envelope wrapping every tool dispatch.
//!
//! [`ImapMcpServer::run_with_audit_envelope`] redacts+hashes arguments,
//! emits a `tool_start` record, runs the provided body future, then
//! emits a `tool_end` record with the resulting status and error code.
//! The helpers [`ImapMcpServer::emit_tool_start`] and
//! [`ImapMcpServer::emit_tool_end`] offload the blocking writer calls
//! onto `spawn_blocking` and surface panics/join errors as
//! `RimapError::Internal`.

use rimap_audit::record::{Provenance, ResultSummary, ToolStatus};
use rimap_audit::redact::{Redactor, hash_arguments};
use rimap_core::tool::ToolName;
use rmcp::model::{CallToolResult, ErrorData};

use crate::mcp::dispatch::PostureContext;
use crate::mcp::server::ImapMcpServer;

impl ImapMcpServer {
    /// Wrap an inner dispatch `body` in the full audit envelope:
    /// redact+hash args, emit `tool_start`, time the body, emit
    /// `tool_end` with the status/error code derived from the body's
    /// result. Returns the MCP-shaped `CallToolResult` or `ErrorData`.
    pub(super) async fn run_with_audit_envelope<F>(
        &self,
        tool: ToolName,
        audit_account: Option<String>,
        posture: PostureContext,
        args: &serde_json::Map<String, serde_json::Value>,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = self.redact_tool_args(tool, &args_value);
        let hash = hash_arguments(&args_value);

        let start_seq = self
            .emit_tool_start(tool, audit_account.clone(), posture, redacted, hash)
            .await?;
        let start_time = std::time::Instant::now();

        let result = body.await;

        let duration_ms = start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let (status, error_code) = match &result {
            Ok(_) => (ToolStatus::Ok, None),
            Err(e) => (ToolStatus::Error, Some(e.code())),
        };
        self.emit_tool_end(
            start_seq,
            tool,
            audit_account,
            status,
            error_code,
            duration_ms,
        )
        .await;

        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
        }
    }

    /// Apply the registered [`rimap_audit::redact::Redactor`] schema for
    /// `tool`. If no schema matches, returns an empty object and emits
    /// a `warn!` — the schema registry is expected to cover every
    /// advertised tool.
    fn redact_tool_args(&self, tool: ToolName, args: &serde_json::Value) -> serde_json::Value {
        if let Some(schema) = self.redaction_schemas.get(&tool) {
            Redactor::new(schema, self.redaction_salt.as_ref()).apply(args)
        } else {
            tracing::warn!(
                tool = tool.as_str(),
                "no redaction schema for tool; recording empty arguments_redacted",
            );
            serde_json::Value::Object(serde_json::Map::new())
        }
    }

    /// Emit a `tool_start` audit record via `spawn_blocking`. Returns the
    /// allocated `seq` on success; on audit failure emits a `warn!` and
    /// returns a synthetic `Seq::FIRST` so the call can proceed.
    ///
    /// Errors bubble up only when `fail_open = false` AND the write fails:
    /// in that case the tool call MUST fail because the audit trail is
    /// broken. `fail_open = true` deployments swallow the error inside
    /// the writer and return `Ok`.
    async fn emit_tool_start(
        &self,
        tool: ToolName,
        account: Option<String>,
        posture: PostureContext,
        redacted: serde_json::Value,
        hash: String,
    ) -> Result<rimap_audit::Seq, ErrorData> {
        let audit = self.audit.clone();
        let posture_effective = posture.posture();
        let join = tokio::task::spawn_blocking(move || {
            audit.log_tool_start(tool, account.as_deref(), posture_effective, redacted, hash)
        })
        .await;
        match join {
            Ok(Ok(seq)) => Ok(seq),
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_start audit write failed");
                Err(ErrorData::internal_error(
                    format!("audit write failed: {audit_err}"),
                    None,
                ))
            }
            Err(join_err) => {
                tracing::error!(error = %join_err, "tool_start join error");
                let rimap_err = crate::mcp::spawn_blocking_panic_error(&join_err);
                Err(crate::mcp::error::to_mcp_error(&rimap_err))
            }
        }
    }

    /// Emit a `tool_end` audit record via `spawn_blocking`. Failures are
    /// logged but not propagated — at end-of-call the tool has already
    /// finished and the caller sees its original result.
    async fn emit_tool_end(
        &self,
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        status: ToolStatus,
        error_code: Option<rimap_core::ErrorCode>,
        duration_ms: u64,
    ) {
        let audit = self.audit.clone();
        // The provenance ring buffer is not yet wired for multi-account.
        // Record an empty snapshot with the window placeholder until a
        // per-account buffer lands.
        let provenance = Provenance {
            window_seconds: 60,
            message_ids_recently_read: Vec::new(),
        };
        let summary = ResultSummary::default();
        let inputs = rimap_audit::ToolEndInputs {
            start_seq,
            tool,
            account,
            status,
            error_code,
            duration_ms,
            result_summary: summary,
            provenance,
        };
        let join = tokio::task::spawn_blocking(move || audit.log_tool_end(inputs)).await;
        match join {
            Ok(Ok(_)) => {}
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_end audit write failed");
            }
            Err(join_err) => {
                let rimap_err = crate::mcp::spawn_blocking_panic_error(&join_err);
                tracing::error!(error = %rimap_err, "tool_end join error");
            }
        }
    }
}
