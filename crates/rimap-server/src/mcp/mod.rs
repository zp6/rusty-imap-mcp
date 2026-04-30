//! MCP runtime: server handler, response/error types, content parsing.

pub(crate) mod audit_envelope;
pub mod content;
pub(crate) mod dispatch;
pub mod error;
pub(crate) mod posture_context;
pub mod response;
pub mod server;
pub(crate) mod tool_catalog;
pub(crate) mod tool_name;

/// Render a `tokio::task::JoinError` from `spawn_blocking` as
/// `RimapError::InternalSourced`. Shared by every `mcp/*` async wrapper so
/// panics in the blocking threadpool always surface with the same code
/// and message prefix — infrastructure failure, not user input. The
/// original `JoinError` is preserved via the `#[source]` chain so
/// tracing subscribers can walk to the underlying panic payload.
pub(crate) fn spawn_blocking_panic_error(err: tokio::task::JoinError) -> rimap_core::RimapError {
    rimap_core::RimapError::InternalSourced {
        message: "spawn_blocking panicked".to_string(),
        source: Box::new(err),
    }
}

/// Run a blocking audit-write closure on the threadpool, swallowing both
/// `AuditError` and `JoinError` failures with structured tracing logs.
/// Returns `Some(value)` on success, `None` on either failure path.
///
/// `op` is a stable identifier for the write site (e.g. `"session_start"`)
/// — included as a structured field on every failure log so operators can
/// triage from the audit-loss observability dashboard without grepping
/// English error strings. The `JoinError` panic-mapping is handled
/// uniformly through [`spawn_blocking_panic_error`] so panic payloads
/// surface as `RimapError::InternalSourced` everywhere.
///
/// Use this at sites where an audit-write failure is not propagated to
/// the caller (`session_start`, `session_end`, `tool_end`). Sites that
/// must propagate the failure as an MCP error use bespoke matches that
/// emit `ErrorData` — see `audit_envelope::emit_tool_start`.
pub(crate) async fn run_audit_blocking<T, F>(op: &'static str, f: F) -> Option<T>
where
    F: FnOnce() -> Result<T, rimap_audit::AuditError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(audit_err)) => {
            tracing::error!(op, error = %audit_err, "audit write failed");
            None
        }
        Err(join_err) => {
            let rimap_err = spawn_blocking_panic_error(join_err);
            tracing::error!(op, error = %rimap_err, "audit spawn_blocking join error");
            None
        }
    }
}
