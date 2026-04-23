//! Shared and per-session state held by the daemon.

use std::sync::Arc;
use std::time::Instant;

use rimap_audit::{AuditWriter, CancelledToolEndSender};
use rimap_core::{SessionId, account::AccountId};
use tokio::sync::{RwLock, Semaphore};

use crate::boot::registry::AccountRegistry;

/// Daemon-wide shared state. One `Arc<DaemonState>` is built at boot and
/// cloned into every `PerSessionHandler`.
pub struct DaemonState {
    /// Account registry (all accounts, all connections, all per-account
    /// governors and breakers). `Connection`s are already `Arc`-backed
    /// internally; sharing the registry via `Arc` gives every session
    /// cheap access.
    pub registry: Arc<AccountRegistry>,
    /// Audit writer; the single fs-locked backing file is shared.
    pub audit: AuditWriter,
    /// Attachment download directory (read-only after boot).
    pub download_dir: Arc<std::path::Path>,
    /// Cancellation channel sender for the audit drainer.
    pub cancellation_tx: CancelledToolEndSender,
    /// Daemon start time (used to compute session durations).
    pub started_at: Instant,
    /// Bound on concurrent shim sessions. An `OwnedSemaphorePermit` is
    /// acquired on each accept and held for the session's lifetime;
    /// dropping the permit (when the session future returns) releases
    /// the slot. Connections that arrive while the semaphore is
    /// exhausted are rejected with a paired
    /// `session_start` + `session_end(Rejected)` audit pair.
    pub session_permits: Arc<Semaphore>,
}

/// Per-client-connection state.
pub struct SessionState {
    /// Generated on accept; carried through every audit record.
    pub id: SessionId,
    /// Session-scoped active account (overrides the config default).
    /// `RwLock` because `use_account` is the only writer and reads
    /// happen on every tool call.
    pub active_account: RwLock<Option<AccountId>>,
    /// When this session started — for `duration_ms` on `session_end`.
    pub started_at: Instant,
    /// Count of completed tool calls in this session, feeds
    /// `session_end.total_tool_calls` and aggregates into
    /// `process_end.total_tool_calls` at daemon shutdown.
    pub tool_call_count: std::sync::atomic::AtomicU64,
}

impl SessionState {
    /// Construct a fresh session.
    #[must_use]
    pub fn new(id: SessionId) -> Self {
        Self {
            id,
            active_account: RwLock::new(None),
            started_at: Instant::now(),
            tool_call_count: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::SessionState;
    use rimap_core::SessionId;

    #[tokio::test]
    async fn new_session_has_no_active_account() {
        let s = SessionState::new(SessionId::new());
        assert!(s.active_account.read().await.is_none());
    }

    #[tokio::test]
    async fn active_account_write_then_read_reflects_update() {
        let s = SessionState::new(SessionId::new());
        let id = rimap_core::account::AccountId::new("work").unwrap();
        *s.active_account.write().await = Some(id.clone());
        assert_eq!(*s.active_account.read().await, Some(id));
    }

    #[test]
    fn two_sessions_generate_distinct_ids() {
        let a = SessionState::new(SessionId::new());
        let b = SessionState::new(SessionId::new());
        assert_ne!(a.id, b.id);
    }
}
