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
