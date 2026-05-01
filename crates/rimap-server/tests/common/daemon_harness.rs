//! In-process test harness for the daemon. Spawns the daemon's accept
//! loop as a background tokio task against a tempdir-backed audit file
//! and socket directory; returns a handle for clients to connect through.

#![cfg(unix)]
// Windows parity follows in Task 29.
// Some items in this shared harness module are only used by specific test
// binaries, not all of them. Allow dead_code at module level to avoid false
// positives when a test binary uses only a subset of the harness API.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use rimap_audit::{AuditOptions, AuditWriter};
use rimap_server::daemon::run::run;
use rimap_server::daemon::state::DaemonState;
use rimap_server::daemon::transport::unix::UnixSocketListener;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Spawned daemon, ready for client connections.
pub struct TestDaemon {
    /// Path of the Unix socket the daemon is listening on.
    pub socket_path: PathBuf,
    /// Path of the JSONL audit log written by this daemon.
    pub audit_path: PathBuf,
    /// Tempdir backing the daemon's config, audit file, and socket.
    /// Held here for lifetime; tests may create additional files inside it.
    pub tempdir: TempDir,
    /// Trigger to request graceful shutdown.
    pub shutdown: Arc<Notify>,
    /// Background task running the daemon accept loop.
    pub handle: JoinHandle<anyhow::Result<()>>,
}

impl TestDaemon {
    /// Signal graceful shutdown, wait for the daemon task to complete, and
    /// return the audit log contents. The `TempDir` is dropped after reading,
    /// so callers that need to inspect the audit log must use the returned
    /// `String` rather than reading from `self.audit_path` after this call.
    pub async fn shutdown(self) -> String {
        // notify_one stores a permit even if the daemon task hasn't yet reached
        // the select! — safe whether the daemon boot is still in progress.
        self.shutdown.notify_one();
        let _ = self.handle.await;
        // Read the audit log while tempdir still owns the file; `self` drops
        // (including self.tempdir) when this function returns.
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }
}

/// Build a minimal `DaemonState` suitable for integration tests that do not
/// need a real `AccountRegistry`. Registry is empty; audit writer is real
/// (backed by `audit_path`). Session-permit capacity defaults to 64
/// (matches the production default); tests that need a different bound
/// should call [`test_daemon_state_with_limit`].
///
/// # Panics
///
/// Panics if the audit file cannot be opened — intentional in a test helper.
pub fn test_daemon_state(audit_path: &std::path::Path) -> Arc<DaemonState> {
    test_daemon_state_with_limit(audit_path, 64)
}

/// Same as [`test_daemon_state`] but with a configurable
/// `max_concurrent_sessions` bound.
///
/// # Panics
///
/// Panics if the audit file cannot be opened — intentional in a test helper.
#[expect(clippy::expect_used, reason = "test helper — panics on setup failure")]
pub fn test_daemon_state_with_limit(
    audit_path: &std::path::Path,
    max_concurrent_sessions: usize,
) -> Arc<DaemonState> {
    use rimap_server::boot::account_state::AccountRegistry;

    let audit = AuditWriter::open(&AuditOptions {
        path: audit_path.to_owned(),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .expect("open audit");

    let registry = Arc::new(AccountRegistry::new(std::collections::BTreeMap::new()));
    let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();
    let session_permits = Arc::new(tokio::sync::Semaphore::new(max_concurrent_sessions));

    Arc::new(DaemonState::new(
        registry,
        audit,
        cancellation_tx,
        session_permits,
    ))
}

impl TestDaemon {
    /// Spawn a daemon with a caller-supplied `DaemonState`. Bypasses
    /// `boot::registry::build` and its live-IMAP dependency. Suitable for
    /// tests that exercise session/transport/audit/shutdown semantics
    /// without needing a real IMAP server.
    ///
    /// # Panics
    ///
    /// Panics if the socket cannot be bound — intentional in a test harness.
    #[expect(clippy::expect_used, reason = "test harness — panics on setup failure")]
    pub async fn spawn_bare(
        tempdir: TempDir,
        audit_path: PathBuf,
        socket_path: PathBuf,
        state: Arc<DaemonState>,
    ) -> Self {
        let listener = UnixSocketListener::bind(&socket_path)
            .await
            .expect("bind test socket");
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move { run(state, listener, shutdown_clone).await });
        Self {
            socket_path,
            audit_path,
            tempdir,
            shutdown,
            handle,
        }
    }

    /// Poll the audit file at a tight interval until `predicate(content)`
    /// returns `true`, or `timeout` elapses. Returns the file contents on
    /// success, or panics with a diagnostic on timeout. Replaces the
    /// fixed `tokio::time::sleep` calls that previously gambled on a
    /// duration generous enough to outrun CI scheduler jitter.
    ///
    /// `predicate` is a `Fn(&str) -> bool` closure that inspects the
    /// JSONL contents — typically a substring count or a per-line
    /// `serde_json::from_str` parse. Tests use this to wait on actual
    /// observable state instead of guessing how long the daemon needs.
    ///
    /// # Panics
    ///
    /// Panics on timeout with the most-recent file contents to aid
    /// triage.
    pub async fn wait_for_audit(
        &self,
        timeout: std::time::Duration,
        predicate: impl Fn(&str) -> bool,
    ) -> String {
        wait_for_audit_at(&self.audit_path, timeout, predicate).await
    }
}

/// Free-function variant of [`TestDaemon::wait_for_audit`] for tests
/// that hold the audit path directly.
///
/// ## macOS race note (issue #188)
///
/// Tests that close their client connection immediately after `connect()`
/// must first wait for `session_start` to land in the audit log. On macOS
/// (Tahoe / Darwin 25.x), the daemon's `peer_cred()` call inside
/// `PlatformListener::accept` returns `ENOTCONN` (errno 57,
/// `io::ErrorKind::NotConnected`) for a peer that has fully disconnected
/// before the server reaches it; the daemon's accept loop logs
/// `accept failed` and `continue`s without emitting any audit record.
/// The passing `daemon_rejects_session_past_limit` and the post-fix
/// `daemon_releases_permit_on_session_end` /
/// `client_connects_and_sees_clean_session_lifecycle` all use the
/// `wait_for_audit_at(_, _, |c| count_audit_kind(c, "session_start") >= N)`
/// pattern between `connect` and `shutdown+drop` to sidestep this race.
/// See issue #188 for the diagnostic record.
///
/// # Panics
///
/// Panics on timeout with the most-recent file contents to aid triage.
pub async fn wait_for_audit_at(
    audit_path: &std::path::Path,
    timeout: std::time::Duration,
    predicate: impl Fn(&str) -> bool,
) -> String {
    /// 5 ms strikes a balance between responsiveness on a quiescent CI
    /// runner and not hammering the kernel with `stat()` calls under load.
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let content = std::fs::read_to_string(audit_path).unwrap_or_default();
        if predicate(&content) {
            return content;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "wait_for_audit timed out after {timeout:?}; last audit contents:\n{content}",
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Count audit lines that contain `kind` as a top-level JSON `"kind"`
/// field. Helper used by tests to wait on event arrival.
#[must_use]
pub fn count_audit_kind(content: &str, kind: &str) -> usize {
    let needle = format!(r#""kind":"{kind}""#);
    content.lines().filter(|l| l.contains(&needle)).count()
}

/// Count `session_end` records carrying a specific reason value.
#[must_use]
pub fn count_session_end_reason(content: &str, reason: &str) -> usize {
    let kind = r#""kind":"session_end""#;
    let reason_needle = format!(r#""reason":"{reason}""#);
    content
        .lines()
        .filter(|l| l.contains(kind) && l.contains(&reason_needle))
        .count()
}
