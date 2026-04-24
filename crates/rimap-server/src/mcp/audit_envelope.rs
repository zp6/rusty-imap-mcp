//! Audit envelope wrapping every tool dispatch.
//!
//! [`ImapMcpServer::run_with_audit_envelope`] takes precomputed redacted
//! and hashed arguments (see [`ImapMcpServer::compute_tool_args_artifacts`]),
//! emits a `tool_start` record, runs the provided body future, then emits
//! a `tool_end` record with the resulting status and error code. The
//! helpers [`ImapMcpServer::emit_tool_start`] and
//! [`ImapMcpServer::emit_tool_end`] offload the blocking writer calls
//! onto `spawn_blocking` and surface panics/join errors as
//! `RimapError::Internal`.
//!
//! **Hash-timing invariant (MCP-INJ-02):** callers must compute the
//! redaction/hash BEFORE any step that mutates the argument map — most
//! notably the `"account"` key that `resolve_account_for_call` consumes
//! on the account-scoped dispatch path. Hashing post-removal diverges
//! from the on-wire JSON-RPC request and breaks replay auditing.
//!
//! [`AuditEnvelopeGuard`] is a drop-guard that synthesizes a cancellation
//! `tool_end` if the enclosing future is dropped between `tool_start`
//! emission and the normal `emit_tool_end` call (#71, #99).
//!
//! **Ordering invariant (MCP-AUD-01):** the guard must remain armed across
//! `emit_tool_end.await`, and only be disarmed AFTER that await returns.
//! Disarming first would leave a window in which a dropped dispatch future
//! produces neither a normal `tool_end` nor a cancellation `tool_end`,
//! resulting in silent audit-record loss.

use std::sync::atomic::{AtomicU64, Ordering};

use rimap_audit::record::{Provenance, ResultSummary, ToolStatus};
use rimap_audit::redact::{Redactor, ToolRedactionSchema, hash_arguments};
use rimap_audit::{CancelledToolEndSender, ToolEndInputs, ToolStartInputs};
use rimap_core::tool::ToolName;
use rmcp::model::{CallToolResult, ErrorData};

use crate::mcp::dispatch::{DispatchTicket, PostureContext};
use crate::mcp::server::ImapMcpServer;

/// Count of `tool_end` cancellation records that could not be enqueued
/// (channel full or drainer already exited). Exposed for observability;
/// a non-zero value indicates audit-record loss that operators should
/// investigate. See `AuditEnvelopeGuard::drop`.
static DROPPED_CANCELLATIONS: AtomicU64 = AtomicU64::new(0);

/// Read the running count of dropped cancellation records.
#[must_use]
#[expect(
    dead_code,
    reason = "observability hook exposed for tests / ops metrics; \
              no in-crate caller today but surface is intentionally kept"
)]
pub fn dropped_cancellation_count() -> u64 {
    DROPPED_CANCELLATIONS.load(Ordering::Relaxed)
}

impl ImapMcpServer {
    /// Wrap an inner dispatch `body` in the full audit envelope: emit
    /// `tool_start`, time the body, emit `tool_end` with the status/error
    /// code derived from the body's result. Returns the MCP-shaped
    /// `CallToolResult` or `ErrorData`.
    ///
    /// `arguments_redacted` and `arguments_hash_sha256` must be precomputed
    /// from the on-wire request arguments via
    /// [`ImapMcpServer::compute_tool_args_artifacts`] BEFORE any step that
    /// mutates the args map (e.g. `resolve_account_for_call` consuming the
    /// `"account"` key) — otherwise the audit record's hash diverges from
    /// the JSON-RPC request as seen by the client. See review finding
    /// MCP-INJ-02.
    pub(super) async fn run_with_audit_envelope<F, Fut>(
        &self,
        tool: ToolName,
        audit_account: Option<String>,
        posture: PostureContext,
        arguments_redacted: serde_json::Value,
        arguments_hash_sha256: String,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(DispatchTicket) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        self.session
            .tool_call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let start_seq = self
            .emit_tool_start(ToolStartInputs {
                tool,
                account: audit_account.clone(),
                posture_effective: posture.posture(),
                arguments_redacted,
                arguments_hash_sha256,
                session_id: None,
            })
            .await?;
        let start_time = std::time::Instant::now();

        let mut guard = AuditEnvelopeGuard::new(
            start_seq,
            tool,
            audit_account.clone(),
            start_time,
            self.state.cancellation_tx.clone(),
            self.audit.session_id(),
        );

        // Mint a `DispatchTicket` only now that the envelope is open.
        // Consuming it by value inside `dispatch_tool` makes "forgot
        // the envelope" a compile error.
        let ticket = DispatchTicket::new();
        let result = body(ticket).await;

        // DO NOT disarm yet — keep the guard armed across `emit_tool_end.await`
        // so that a drop of this future between body completion and end emission
        // still produces a cancellation record (not a silent loss). See review
        // finding MCP-AUD-01.

        let duration_ms = crate::duration_ms_since(start_time);
        let (status, error_code) = match &result {
            Ok(_) => (ToolStatus::Ok, None),
            Err(e) => (ToolStatus::Error, Some(e.code())),
        };
        self.emit_tool_end(ToolEndInputs {
            start_seq,
            tool,
            account: audit_account,
            status,
            error_code,
            duration_ms,
            result_summary: ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
            session_id: None,
        })
        .await;

        // Normal tool_end is on the wire. Disarm now so our own Drop doesn't
        // produce a duplicate cancellation record.
        guard.disarm();

        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
        }
    }

    /// Compute the `(redacted, hash)` pair for `args` against `tool`'s
    /// redaction schema and canonical hash.
    ///
    /// Callers MUST invoke this BEFORE any step that mutates `args` (e.g.
    /// `resolve_account_for_call` removing `"account"`), so the resulting
    /// audit record reflects the on-wire request. See review finding
    /// MCP-INJ-02.
    ///
    /// The redaction dispatch via [`ToolRedactionSchema::redaction_schema`]
    /// is exhaustive, so a missing schema is a compile error rather than
    /// a runtime warn-and-drop.
    pub(super) fn compute_tool_args_artifacts(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> (serde_json::Value, String) {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref())
            .apply(&args_value);
        let hash = hash_arguments(&args_value);
        (redacted, hash)
    }

    /// Emit a `tool_start` audit record via `spawn_blocking`. Returns the
    /// allocated `seq` on success.
    ///
    /// Errors bubble up only when `fail_open = false` AND the write fails:
    /// in that case the tool call MUST fail because the audit trail is
    /// broken. `fail_open = true` deployments swallow the error inside
    /// the writer and return `Ok`.
    async fn emit_tool_start(
        &self,
        inputs: ToolStartInputs,
    ) -> Result<rimap_audit::Seq, ErrorData> {
        let sink = self.audit.clone();
        let join = tokio::task::spawn_blocking(move || sink.log_tool_start(inputs)).await;
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
                let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
                Err(crate::mcp::error::to_mcp_error(&rimap_err))
            }
        }
    }

    /// Emit a `tool_end` audit record via `spawn_blocking`. Failures are
    /// logged but not propagated — at end-of-call the tool has already
    /// finished and the caller sees its original result.
    async fn emit_tool_end(&self, inputs: ToolEndInputs) {
        let sink = self.audit.clone();
        let join = tokio::task::spawn_blocking(move || sink.log_tool_end(inputs)).await;
        match join {
            Ok(Ok(_)) => {}
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_end audit write failed");
            }
            Err(join_err) => {
                let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
                tracing::error!(error = %rimap_err, "tool_end join error");
            }
        }
    }
}

/// RAII guard that emits a cancellation `tool_end` record if dropped
/// undisarmed. Used inside `run_with_audit_envelope` to pair every
/// `tool_start` with a `tool_end` even when the outer MCP dispatch
/// future is dropped mid-call (#71, #99).
struct AuditEnvelopeGuard {
    inner: Option<GuardInner>,
}

struct GuardInner {
    start_seq: rimap_audit::Seq,
    tool: ToolName,
    account: Option<String>,
    start_time: std::time::Instant,
    sender: CancelledToolEndSender,
    session_id: rimap_core::SessionId,
}

impl AuditEnvelopeGuard {
    fn new(
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        start_time: std::time::Instant,
        sender: CancelledToolEndSender,
        session_id: rimap_core::SessionId,
    ) -> Self {
        Self {
            inner: Some(GuardInner {
                start_seq,
                tool,
                account,
                start_time,
                sender,
                session_id,
            }),
        }
    }

    /// Mark the guard as completed normally. `Drop` becomes a no-op.
    fn disarm(&mut self) {
        self.inner = None;
    }
}

impl Drop for AuditEnvelopeGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let duration_ms = crate::duration_ms_since(inner.start_time);
        // ToolName is Copy; capture it for the warning log before try_send
        // consumes the payload.
        let tool = inner.tool;
        let cancellation = ToolEndInputs {
            start_seq: inner.start_seq,
            tool,
            account: inner.account,
            status: rimap_audit::record::ToolStatus::Cancelled,
            error_code: Some(rimap_core::ErrorCode::Cancelled),
            duration_ms,
            result_summary: rimap_audit::record::ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
            session_id: Some(inner.session_id),
        };
        if let Err(e) = inner.sender.try_send(cancellation) {
            DROPPED_CANCELLATIONS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                error = %e,
                tool = tool.as_str(),
                total_dropped = DROPPED_CANCELLATIONS.load(Ordering::Relaxed),
                "cancellation tool_end drop: failed to enqueue (channel full or closed)",
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_audit::writer::AuditOptions;
    use rimap_audit::{AuditWriter, Seq, ToolStartInputs, cancellation_channel, spawn_drainer};
    use rimap_core::SessionId;
    use rimap_core::tool::ToolName;
    use tempfile::tempdir;

    use super::AuditEnvelopeGuard;

    fn test_writer(path: std::path::PathBuf) -> AuditWriter {
        AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap()
    }

    /// Dropping an `AuditEnvelopeGuard` without disarming enqueues a
    /// cancellation record with `status = cancelled`,
    /// `error_code = ERR_CANCELLED`, and the guard's `session_id`.
    /// The drainer writes it to the audit file.
    /// This is the core invariant for #71, #99, and the `session_id` fix.
    #[tokio::test]
    async fn dropped_guard_enqueues_cancellation_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        let session_id = SessionId::new();

        // Prime a tool_start so the resulting tool_end references a real seq.
        let start_seq = writer
            .log_tool_start(ToolStartInputs {
                tool: ToolName::Search,
                account: Some("test".to_string()),
                posture_effective: Some(rimap_core::Posture::Readonly),
                arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
                arguments_hash_sha256: "0".repeat(64),
                session_id: None,
            })
            .unwrap();

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());

        {
            let _guard = AuditEnvelopeGuard::new(
                start_seq,
                ToolName::Search,
                Some("test".to_string()),
                std::time::Instant::now(),
                tx.clone(),
                session_id,
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            // Implicit drop of `_guard` here — undisarmed, so cancellation fires.
        }

        drop(tx); // Close the channel so the drainer can exit.
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert!(
            lines.len() >= 2,
            "expected >= 2 records (tool_start + cancellation tool_end), got: {contents}",
        );
        let last = lines.last().unwrap();
        assert!(
            last.contains(r#""status":"cancelled""#),
            "last record should be cancellation tool_end: {last}",
        );
        assert!(
            last.contains(r#""error_code":"ERR_CANCELLED""#),
            "last record should carry ERR_CANCELLED: {last}",
        );
        assert!(
            last.contains(&format!(r#""start_seq":{start_seq}"#)),
            "last record should reference primed tool_start seq {start_seq}: {last}",
        );
        let v: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(
            v["session_id"],
            serde_json::Value::String(session_id.to_string()),
            "cancellation tool_end must carry the guard's session_id: {last}",
        );
    }

    /// A disarmed guard's drop is a no-op: no cancellation record is written.
    #[tokio::test]
    async fn disarmed_guard_does_not_enqueue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());

        {
            let mut guard = AuditEnvelopeGuard::new(
                Seq::FIRST,
                ToolName::Search,
                Some("test".to_string()),
                std::time::Instant::now(),
                tx.clone(),
                SessionId::new(),
            );
            guard.disarm();
            // Drop here — disarmed, so no cancellation is enqueued.
        }

        drop(tx);
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !contents.contains(r#""status":"cancelled""#),
            "disarmed guard must not write a cancellation record: {contents}",
        );
    }

    /// `compute_tool_args_artifacts` must hash the FULL args map as
    /// provided, including any keys (like `"account"`) that the dispatch
    /// pipeline may later consume. A replaying auditor must be able to
    /// reproduce the on-wire hash from the client's original JSON-RPC
    /// request. See review finding MCP-INJ-02.
    #[tokio::test]
    async fn compute_artifacts_hashes_full_map_including_account_key() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use rimap_audit::{AuditOptions, AuditWriter, Seq, redact::hash_arguments};

        use crate::boot::registry::AccountRegistry;
        use crate::daemon::state::{DaemonState, SessionState};
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();
        let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();
        let download_dir: Arc<std::path::Path> =
            Arc::from(std::path::Path::new("/tmp/test-downloads"));
        let daemon_state = Arc::new(DaemonState {
            registry: Arc::new(AccountRegistry::new(BTreeMap::new())),
            audit,
            download_dir,
            cancellation_tx,
            started_at: std::time::Instant::now(),
            session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
            total_tool_calls: std::sync::atomic::AtomicU64::new(0),
        });
        let session_state = Arc::new(SessionState::new(rimap_core::SessionId::new()));
        let server = ImapMcpServer::new(daemon_state, session_state);

        // Build an args map as it would arrive on the wire for an
        // account-scoped call: BEFORE `resolve_account_for_call` consumes
        // the `"account"` key.
        let mut args = serde_json::Map::new();
        args.insert(
            "account".to_string(),
            serde_json::Value::String("test".to_string()),
        );
        args.insert(
            "foo".to_string(),
            serde_json::Value::Number(serde_json::Number::from(42)),
        );

        let (_redacted, computed_hash) =
            server.compute_tool_args_artifacts(ToolName::Search, &args);

        // Expected: hash of the full pre-removal map.
        let expected_hash = hash_arguments(&serde_json::Value::Object(args.clone()));
        assert_eq!(
            computed_hash, expected_hash,
            "hash must cover the full on-wire map including `account`",
        );

        // The post-removal hash must differ — this is the regression
        // guard. If someone reintroduces "hash after removal", the two
        // values would coincide only by accident and this assertion
        // would catch the drift.
        let mut post_removal = args.clone();
        post_removal.remove("account");
        let post_removal_hash = hash_arguments(&serde_json::Value::Object(post_removal));
        assert_ne!(
            computed_hash, post_removal_hash,
            "pre-removal and post-removal hashes must differ (if they \
             matched, the regression guard is useless)",
        );
    }
}
