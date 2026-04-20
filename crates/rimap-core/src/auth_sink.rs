//! Trait seam for emitting [`AuthEvent`] records without coupling
//! the IMAP transport to a specific audit-log implementation.
//!
//! `rimap-imap`'s `Connection` holds an `Arc<dyn AuthEventSink>` and
//! calls [`AuthEventSink::emit_auth`] from within
//! `tokio::task::spawn_blocking` — implementations may perform
//! synchronous filesystem I/O (the `rimap-audit::AuditWriter` impl
//! takes the writer's mutex and writes one JSONL line) and MUST NOT
//! be invoked from an async context without that wrapping.
//!
//! Implementations live downstream:
//! - `rimap-audit::AuditWriter` records to the rotated, locked
//!   on-disk log.
//! - Test fixtures can supply an in-memory `Vec<AuthEvent>` collector
//!   via a small adapter.

use std::error::Error as StdError;

use thiserror::Error;

use crate::auth_event::AuthEvent;
use crate::error::ErrorCode;

/// Reason an [`AuthEventSink`] failed to record an event.
///
/// Carries a stable [`ErrorCode`] (so the IMAP layer can classify
/// without inspecting the source) plus the underlying error for
/// observability. Sinks should NOT include filesystem paths or
/// other operator-configured strings in `message`; those go in the
/// `source` chain via `tracing` at the implementation site.
#[derive(Debug, Error)]
#[error("auth-event sink failed: {message}")]
pub struct AuthSinkError {
    /// Stable classification of the failure.
    pub code: ErrorCode,
    /// Short, sanitized human label (no filesystem paths, no
    /// operator-specific layout).
    pub message: String,
    /// Underlying error for observability.
    #[source]
    pub source: Box<dyn StdError + Send + Sync + 'static>,
}

/// Sink that durably records [`AuthEvent`] values.
///
/// Implementations are typically wrapped in an `Arc<dyn AuthEventSink>`
/// and shared across many `Connection` instances. The trait is `Send +
/// Sync` because the IMAP transport is `Clone`able and its clones may
/// run on different runtime tasks.
///
/// The single method is sync; async callers must invoke it inside
/// `tokio::task::spawn_blocking` if the implementation performs
/// blocking I/O (the production `AuditWriter` impl does).
pub trait AuthEventSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Returns the implementation's error on failure.
    ///
    /// # Errors
    /// Returns [`AuthSinkError`] if the underlying sink rejects the
    /// event (e.g., disk full, lock poisoned, file rotated mid-write).
    fn emit_auth(&self, event: AuthEvent) -> Result<(), AuthSinkError>;
}
