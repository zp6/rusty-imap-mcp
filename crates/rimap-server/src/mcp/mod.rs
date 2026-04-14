//! MCP runtime: server handler, response/error types, content parsing, attachment download.

pub mod content;
pub mod download;
pub mod error;
pub mod response;
pub mod server;

/// Render a `tokio::task::JoinError` from `spawn_blocking` as
/// `RimapError::Internal`. Shared by every `mcp/*` async wrapper so
/// panics in the blocking threadpool always surface with the same code
/// and message prefix — infrastructure failure, not user input.
pub(crate) fn spawn_blocking_panic_error(err: &tokio::task::JoinError) -> rimap_core::RimapError {
    rimap_core::RimapError::Internal(format!("spawn_blocking panicked: {err}"))
}
