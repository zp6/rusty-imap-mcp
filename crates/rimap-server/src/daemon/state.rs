//! Shared and per-session state held by the daemon.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use rimap_audit::redact::RedactionSalt;
use rimap_audit::{AuditWriter, CancelledToolEndSender};
use rimap_core::{SessionId, account::AccountId};
use tokio::sync::{RwLock, Semaphore};

use crate::boot::registry::AccountRegistry;

/// Daemon-wide shared state. One `Arc<DaemonState>` is built at boot and
/// cloned into every `PerSessionHandler`.
///
/// Fields are `pub(crate)` so in-crate code reads them directly; external
/// consumers (the `main.rs` binary + integration tests) must construct via
/// [`DaemonState::new`] and go through the in-crate APIs for reads. See
/// issue #145 (Tighten `DaemonState` field visibility).
pub struct DaemonState {
    /// Account registry (all accounts, all connections, all per-account
    /// governors and breakers). `Connection`s are already `Arc`-backed
    /// internally; sharing the registry via `Arc` gives every session
    /// cheap access.
    pub(crate) registry: Arc<AccountRegistry>,
    /// Audit writer; the single fs-locked backing file is shared.
    pub(crate) audit: AuditWriter,
    /// Attachment download directory (read-only after boot). Stored on
    /// `DaemonState` and propagated into `AccountRegistry::build`, which
    /// copies it onto each `AccountState`; tool handlers read it from the
    /// per-account copy. The daemon-level field is currently vestigial —
    /// retained for symmetry with other daemon-shared paths and as a
    /// holding spot for any future tool that needs the unscoped path.
    #[expect(
        dead_code,
        reason = "vestigial daemon-level copy; per-account download_dir on AccountState is the live path"
    )]
    pub(crate) download_dir: Arc<std::path::Path>,
    /// Cancellation channel sender for the audit drainer.
    pub(crate) cancellation_tx: CancelledToolEndSender,
    /// Daemon start time. Captured for symmetry with `process_start`'s
    /// timestamp; nothing reads it today (per-session durations come from
    /// `SessionState.started_at`, not from this field).
    #[expect(
        dead_code,
        reason = "vestigial; eligible for removal in a future cleanup PR"
    )]
    pub(crate) started_at: Instant,
    /// Bound on concurrent shim sessions. An `OwnedSemaphorePermit` is
    /// acquired on each accept and held for the session's lifetime;
    /// dropping the permit (when the session future returns) releases
    /// the slot. Connections that arrive while the semaphore is
    /// exhausted are rejected with a paired
    /// `session_start` + `session_end(Rejected)` audit pair.
    pub(crate) session_permits: Arc<Semaphore>,
    /// Daemon-wide aggregate of completed tool calls across all sessions.
    /// Incremented in `emit_session_end` with each session's final count.
    /// Read in `daemon_main` to populate `process_end.total_tool_calls`.
    pub(crate) total_tool_calls: AtomicU64,
    /// Per-process salt used by [`rimap_audit::redact::Redactor`] to hash
    /// tool arguments. One salt for the daemon lifetime; hashes are not
    /// comparable across restarts (by design — fresh randomness per boot).
    /// Cloned cheaply into every `ImapMcpServer`. See #141.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
}

impl DaemonState {
    /// Build daemon-wide shared state. Called once in `daemon_main`;
    /// integration tests also use this so a new field on `DaemonState`
    /// does not require updating every test's struct literal.
    ///
    /// Generates one [`RedactionSalt`] from the OS RNG and wraps it in
    /// `Arc` so `spawn_blocking` closures can cheaply capture it.
    #[must_use]
    pub fn new(
        registry: Arc<AccountRegistry>,
        audit: AuditWriter,
        download_dir: Arc<std::path::Path>,
        cancellation_tx: CancelledToolEndSender,
        session_permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            registry,
            audit,
            download_dir,
            cancellation_tx,
            started_at: Instant::now(),
            session_permits,
            total_tool_calls: AtomicU64::new(0),
            redaction_salt: Arc::new(RedactionSalt::new_random()),
        }
    }

    /// Read the daemon-wide total tool-call counter. `main.rs` consumes
    /// this at `process_end` emission; external callers have no other
    /// reason to touch the `AtomicU64` directly.
    #[must_use]
    pub fn total_tool_calls(&self) -> u64 {
        self.total_tool_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }
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

    #[test]
    fn total_tool_calls_aggregator_sums_independent_sessions() {
        // Pins the ordering choice used by the real aggregator: `Relaxed`
        // is correct here because the happens-before chain is provided by
        // Tokio's task-join (each session task's writes are visible after
        // `run(...).await` returns), not by atomic ordering. A stronger
        // ordering would add overhead without changing behaviour. This
        // test does not exercise `emit_session_end` or `daemon_main`
        // directly — it guards the atomic-level pattern against accidental
        // refactors to SeqCst/Acquire when Relaxed is intentional.
        use std::sync::atomic::{AtomicU64, Ordering};

        let daemon_total = AtomicU64::new(0);
        for per_session in [3_u64, 5, 7, 1] {
            daemon_total.fetch_add(per_session, Ordering::Relaxed);
        }
        assert_eq!(daemon_total.load(Ordering::Relaxed), 3 + 5 + 7 + 1);
    }

    #[tokio::test]
    async fn daemon_state_new_builds_one_salt_per_daemon_lifetime() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use rimap_audit::{AuditOptions, AuditWriter, Seq};
        use tempfile::tempdir;

        use super::DaemonState;
        use crate::boot::registry::AccountRegistry;

        fn build_state(dir: &std::path::Path) -> Arc<DaemonState> {
            let audit = AuditWriter::open(&AuditOptions {
                path: dir.join("a.jsonl"),
                rotate_bytes: 0,
                rotate_keep: 0,
                retention_seconds: None,
                fail_open: false,
                initial_seq: Seq::FIRST,
            })
            .unwrap();
            let (cancellation_tx, _rx) = rimap_audit::cancellation_channel();
            Arc::new(DaemonState::new(
                Arc::new(AccountRegistry::new(BTreeMap::new())),
                audit,
                Arc::from(dir.to_path_buf().into_boxed_path()),
                cancellation_tx,
                Arc::new(tokio::sync::Semaphore::new(1)),
            ))
        }

        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let state_a = build_state(dir_a.path());
        let state_b = build_state(dir_b.path());

        // Different daemon constructions => different salt Arcs (each `new()`
        // mints its own RedactionSalt). A weaker test that compared two clones
        // of the same `state.redaction_salt` would be trivially true regardless
        // of implementation; this catches a regression that re-allocates on
        // every read.
        assert!(
            !Arc::ptr_eq(&state_a.redaction_salt, &state_b.redaction_salt),
            "DaemonState::new must mint a fresh RedactionSalt per daemon",
        );

        // Within one daemon, cloning the field yields the same Arc.
        let clone_a = Arc::clone(&state_a.redaction_salt);
        assert!(
            Arc::ptr_eq(&state_a.redaction_salt, &clone_a),
            "Arc clones of the salt field must point to the same allocation",
        );
    }
}
