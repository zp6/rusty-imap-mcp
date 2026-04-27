//! Daemon entry point: accept loop, per-session spawn, graceful shutdown.

use std::collections::HashMap;
use std::sync::Arc;

use rimap_audit::record::PeerIdentity;
use rimap_core::SessionId;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit};
use tokio::task::JoinSet;

use crate::daemon::state::{DaemonState, SessionState};
use crate::daemon::transport::{AcceptedConnection, PlatformListener};
use crate::mcp::server::ImapMcpServer;

/// Side table of in-flight sessions, keyed by `SessionId`. Used by the
/// graceful-shutdown drain to synthesize `session_end(DaemonShutdown)`
/// records for sessions that `JoinSet::shutdown` aborts before they
/// could emit their own end records (see #137).
///
/// The map lives behind a Tokio `Mutex` rather than a `parking_lot`
/// mutex because the contention pattern is async-task spawn/join, not
/// CPU-bound — and the lock is held only across two `HashMap` ops
/// (insert/remove or drain), well under the `await_holding_lock` clippy
/// threshold.
pub(crate) struct LiveSessions {
    inner: Mutex<HashMap<SessionId, Arc<SessionState>>>,
}

impl LiveSessions {
    /// Construct an empty live-session table.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record that `session` is now in flight. Called from the accept
    /// loop immediately before `sessions.spawn(...)`.
    pub(crate) async fn insert(&self, sid: SessionId, session: Arc<SessionState>) {
        self.inner.lock().await.insert(sid, session);
    }

    /// Remove `sid` from the table. Called from `build_session_future`
    /// on every normal exit path — both Ok and Err cases — so an
    /// aborted future is the only one that leaves an entry behind.
    pub(crate) async fn remove(&self, sid: SessionId) {
        self.inner.lock().await.remove(&sid);
    }

    /// Test-only convenience for membership checks.
    #[cfg(test)]
    pub(crate) async fn contains(&self, sid: SessionId) -> bool {
        self.inner.lock().await.contains_key(&sid)
    }

    /// Drain every remaining entry. Called from `drain_sessions` AFTER
    /// `JoinSet::shutdown().await`, so any session still here was
    /// aborted mid-flight and needs a synthesized `session_end`.
    pub(crate) async fn drain(&self) -> Vec<(SessionId, Arc<SessionState>)> {
        let mut guard = self.inner.lock().await;
        std::mem::take(&mut *guard).into_iter().collect()
    }
}

/// Run the daemon until a shutdown signal fires.
///
/// Accepts connections from `listener`, gates on peer identity, and spawns one
/// `rmcp::serve_server` task per accepted client. Returns when `shutdown` is
/// notified and all in-flight sessions have drained (up to 5 s).
///
/// # Errors
///
/// Returns any fatal error that prevents the accept loop from starting. Per-
/// connection errors are logged and do not propagate here.
pub async fn run<L>(
    state: Arc<DaemonState>,
    mut listener: L,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()>
where
    L: PlatformListener,
{
    let socket_path = resolve_socket_path();
    let peer_gate = make_peer_gate();
    let mut sessions: JoinSet<()> = JoinSet::new();
    let live = Arc::new(LiveSessions::new());

    loop {
        tokio::select! {
            () = shutdown.notified() => {
                tracing::info!("shutdown signal received; stopping accept loop");
                break;
            }
            accepted = listener.accept() => {
                let AcceptedConnection { stream, identity } = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(error = %e, "accept failed");
                        continue;
                    }
                };
                if !peer_gate(&identity) {
                    handle_rejected_peer(&state, &identity, &socket_path).await;
                    drop(stream);
                    continue;
                }
                let Ok(permit) = Arc::clone(&state.session_permits).try_acquire_owned() else {
                    handle_rejected_over_capacity(&state, &identity, &socket_path).await;
                    drop(stream);
                    continue;
                };
                let sid = SessionId::new();
                let session = Arc::new(SessionState::new(sid));
                if log_session_start_blocking(&state, sid, identity, &socket_path)
                    .await
                    .is_none()
                {
                    drop(permit);
                    drop(stream);
                    continue;
                }
                // Insert BEFORE spawn so `drain_sessions` can find the
                // session even if the accept loop exits between insert
                // and spawn.
                live.insert(sid, Arc::clone(&session)).await;
                sessions.spawn(build_session_future(
                    Arc::clone(&state),
                    stream,
                    session,
                    permit,
                    Arc::clone(&live),
                ));
            }
            Some(_) = sessions.join_next() => {
                // Reap completed sessions to keep the JoinSet bounded.
            }
        }
    }

    listener.shutdown();
    drain_sessions(sessions, &state, Arc::clone(&live)).await;
    Ok(())
}

/// Wait up to 5 seconds for in-flight sessions to finish, then abort the rest
/// AND synthesize a `session_end(DaemonShutdown)` audit record for every
/// session that was aborted. The synthesized record carries the per-session
/// duration and tool-call count harvested from `SessionState`, byte-
/// equivalent to what the live future would have emitted.
///
/// See #137: prior to this fix, `JoinSet::shutdown().await` aborted the
/// in-flight session futures before they could emit their own end records,
/// leaving the audit log silently incomplete.
async fn drain_sessions(
    mut sessions: JoinSet<()>,
    state: &Arc<DaemonState>,
    live: Arc<LiveSessions>,
) {
    if sessions.is_empty() {
        // No tasks ever spawned; the live table should be empty too, but
        // belt-and-braces drain it in case an entry slipped in between
        // `live.insert` and `sessions.spawn` and the accept loop then
        // exited.
        for (_, session) in live.drain().await {
            emit_session_end(
                state,
                &session,
                rimap_audit::record::SessionEndReason::DaemonShutdown,
                None,
            )
            .await;
        }
        return;
    }
    tracing::info!(
        count = sessions.len(),
        "draining in-flight sessions (up to 5 s)"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !sessions.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let rem = deadline - now;
        match tokio::time::timeout(rem, sessions.join_next()).await {
            Ok(Some(_)) => {}           // task completed
            Ok(None) | Err(_) => break, // drained or deadline elapsed
        }
    }
    let still_running = sessions.len();
    let shutdown = tokio::time::timeout(std::time::Duration::from_secs(2), sessions.shutdown());
    let shutdown_clean = shutdown.await.is_ok();

    // After `JoinSet::shutdown`, any remaining entry in `live` is a session
    // that was aborted mid-flight. Synthesize its `session_end` record
    // now — same content the live future would have emitted, with reason
    // = DaemonShutdown.
    let aborted = live.drain().await;
    let synthesized = aborted.len();
    for (_, session) in aborted {
        emit_session_end(
            state,
            &session,
            rimap_audit::record::SessionEndReason::DaemonShutdown,
            None,
        )
        .await;
    }

    if shutdown_clean {
        tracing::info!(
            join_set_aborted = still_running,
            session_end_synthesized = synthesized,
            "session drain complete",
        );
    } else {
        tracing::warn!(
            join_set_aborted = still_running,
            session_end_synthesized = synthesized,
            "session shutdown deadline exceeded; exiting with stuck tasks",
        );
    }
}

/// Returns the socket path string via [`crate::daemon::socket_path::resolve`].
fn resolve_socket_path() -> String {
    #[cfg(unix)]
    {
        crate::daemon::socket_path::resolve().as_str().to_owned()
    }
    #[cfg(not(unix))]
    {
        match crate::daemon::socket_path::resolve() {
            Ok(ep) => ep.as_str().to_owned(),
            Err(e) => {
                tracing::warn!(error = %e, "could not resolve socket path for audit records");
                "<unresolved>".to_owned()
            }
        }
    }
}

/// Build the peer-identity gate for this platform.
///
/// Unix: accepts only connections whose UID matches our own effective UID,
/// using `rustix` to avoid unsafe FFI.
///
/// Windows: OS-level DACL on the named pipe already restricts access; the
/// SID comparison requires unsafe FFI that conflicts with the workspace
/// `unsafe_code = "forbid"` policy, so we accept all callers and rely on
/// the pipe ACL.
#[cfg(unix)]
fn make_peer_gate() -> impl Fn(&PeerIdentity) -> bool {
    let our_uid = rustix::process::geteuid().as_raw();
    move |identity: &PeerIdentity| match identity {
        PeerIdentity::Unix { uid, .. } => *uid == our_uid,
        PeerIdentity::Windows { .. } => false,
    }
}

#[cfg(not(unix))]
fn make_peer_gate() -> impl Fn(&PeerIdentity) -> bool {
    // On Windows the named-pipe DACL already restricts access to the
    // owning user. Full SID-match gating requires `unsafe` FFI which
    // the workspace forbids. Accept all callers and rely on the ACL.
    |_identity: &PeerIdentity| true
}

/// Emit a `session_start` record via `spawn_blocking` so the accept loop does
/// not stall on audit rotation. Logs and swallows both write errors and
/// join errors; returns the allocated `Seq` on success, `None` on failure.
/// Call sites decide whether to continue (reject path) or drop the
/// connection (accept path) based on the `Option`.
async fn log_session_start_blocking(
    state: &Arc<DaemonState>,
    sid: SessionId,
    identity: PeerIdentity,
    socket_path: &str,
) -> Option<rimap_audit::Seq> {
    let audit = state.audit.clone();
    let record = rimap_audit::record::SessionStart {
        session_id: sid,
        peer_identity: identity,
        socket_path: socket_path.to_owned(),
    };
    let join = tokio::task::spawn_blocking(move || audit.log_session_start(record)).await;
    match join {
        Ok(Ok(seq)) => Some(seq),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "failed to log session_start");
            None
        }
        Err(join_err) => {
            let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
            tracing::error!(error = %rimap_err, "session_start spawn_blocking join error");
            None
        }
    }
}

/// Emit a `session_end` record via `spawn_blocking`. Failures are logged but
/// not propagated; at this point the session is already over.
async fn log_session_end_blocking(state: &Arc<DaemonState>, end: rimap_audit::record::SessionEnd) {
    let audit = state.audit.clone();
    let join = tokio::task::spawn_blocking(move || audit.log_session_end(end)).await;
    match join {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "failed to log session_end"),
        Err(join_err) => {
            let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
            tracing::error!(error = %rimap_err, "session_end spawn_blocking join error");
        }
    }
}

/// Emit paired `session_start` + `session_end(PeerUidRejected)` for a
/// connection whose peer identity does not match ours, then close it.
async fn handle_rejected_peer(
    state: &Arc<DaemonState>,
    identity: &PeerIdentity,
    socket_path: &str,
) {
    let sid = SessionId::new();
    let _ = log_session_start_blocking(state, sid, identity.clone(), socket_path).await;
    let end = rimap_audit::record::SessionEnd {
        session_id: sid,
        reason: rimap_audit::record::SessionEndReason::PeerUidRejected,
        duration_ms: 0,
        total_tool_calls: 0,
        last_error: None,
    };
    log_session_end_blocking(state, end).await;
    tracing::warn!(?identity, "rejected peer with mismatching identity");
}

/// Emit paired `session_start` + `session_end(Rejected)` for a connection
/// refused because the `max_concurrent_sessions` bound was reached, then
/// close it. The shim observes this as an EOF at or shortly after connect.
async fn handle_rejected_over_capacity(
    state: &Arc<DaemonState>,
    identity: &PeerIdentity,
    socket_path: &str,
) {
    let sid = SessionId::new();
    let _ = log_session_start_blocking(state, sid, identity.clone(), socket_path).await;
    let end = rimap_audit::record::SessionEnd {
        session_id: sid,
        reason: rimap_audit::record::SessionEndReason::Rejected,
        duration_ms: 0,
        total_tool_calls: 0,
        last_error: Some("max_concurrent_sessions reached".to_owned()),
    };
    log_session_end_blocking(state, end).await;
    tracing::warn!(
        ?identity,
        "rejected session: max_concurrent_sessions reached",
    );
}

/// Build the async session future for a single accepted connection.
///
/// Assumes `session_start` has already been emitted by the caller. Runs
/// `rmcp::serve_server` and emits `session_end` on completion.
///
/// The `permit` is held for the lifetime of this future and dropped when
/// the session terminates, releasing a slot in
/// `state.session_permits`.
#[must_use = "dropping the session future loses session_end emission"]
async fn build_session_future<S>(
    state: Arc<DaemonState>,
    stream: S,
    session: Arc<SessionState>,
    permit: OwnedSemaphorePermit,
    live: Arc<LiveSessions>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Hold the permit for the session's lifetime; drops when this future
    // returns, releasing a slot back to the semaphore.
    let _permit = permit;
    let sid = session.id;
    let mcp = ImapMcpServer::new(Arc::clone(&state), Arc::clone(&session));
    let serve_result = Box::pin(rmcp::serve_server(mcp, stream)).await;
    let running = match serve_result {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!(error = %e, "rmcp::serve_server initialisation failed");
            emit_session_end(
                &state,
                &session,
                rimap_audit::record::SessionEndReason::Error,
                Some(format!("serve_server init: {e}")),
            )
            .await;
            // Remove only AFTER emission so a panic in emit_session_end
            // leaves the entry visible for the drain path's safety net.
            live.remove(sid).await;
            return;
        }
    };
    let quit = running.waiting().await;
    let (reason, last_err) = session_end_from_quit(quit);
    emit_session_end(&state, &session, reason, last_err).await;
    live.remove(sid).await;
}

/// Map `waiting()`'s `QuitReason` outcome to an audit `(SessionEndReason,
/// Option<String>)` pair.
fn session_end_from_quit(
    quit: Result<rmcp::service::QuitReason, tokio::task::JoinError>,
) -> (rimap_audit::record::SessionEndReason, Option<String>) {
    use rimap_audit::record::SessionEndReason;
    use rmcp::service::QuitReason;
    match quit {
        Ok(QuitReason::Closed) => (SessionEndReason::Eof, None),
        Ok(QuitReason::Cancelled) => (SessionEndReason::DaemonShutdown, None),
        Ok(QuitReason::JoinError(e)) | Err(e) => (
            SessionEndReason::Error,
            Some(format!("task join error: {e}")),
        ),
        // QuitReason is #[non_exhaustive]; catch any future variants and treat
        // them as unexpected errors so we surface them rather than silently
        // swallowing them.
        Ok(other) => (
            SessionEndReason::Error,
            Some(format!("unexpected QuitReason: {other:?}")),
        ),
    }
}

/// Write a `session_end` record with elapsed duration and tool-call count.
async fn emit_session_end(
    state: &Arc<DaemonState>,
    session: &Arc<SessionState>,
    reason: rimap_audit::record::SessionEndReason,
    last_error: Option<String>,
) {
    let duration_ms = crate::duration_ms_since(session.started_at);
    let total = session
        .tool_call_count
        .load(std::sync::atomic::Ordering::Relaxed);
    state
        .total_tool_calls
        .fetch_add(total, std::sync::atomic::Ordering::Relaxed);
    let end = rimap_audit::record::SessionEnd {
        session_id: session.id,
        reason,
        duration_ms,
        total_tool_calls: total,
        last_error,
    };
    log_session_end_blocking(state, end).await;
}

#[cfg(test)]
mod live_sessions_tests {
    use super::LiveSessions;
    use crate::daemon::state::SessionState;
    use rimap_core::SessionId;
    use std::sync::Arc;

    #[tokio::test]
    async fn insert_then_remove_drops_entry() {
        let live = LiveSessions::new();
        let sid = SessionId::new();
        let session = Arc::new(SessionState::new(sid));
        live.insert(sid, Arc::clone(&session)).await;
        assert!(live.contains(sid).await);
        live.remove(sid).await;
        assert!(!live.contains(sid).await);
    }

    #[tokio::test]
    async fn drain_returns_all_remaining_entries_in_one_pass() {
        let live = LiveSessions::new();
        let sid_a = SessionId::new();
        let sid_b = SessionId::new();
        live.insert(sid_a, Arc::new(SessionState::new(sid_a))).await;
        live.insert(sid_b, Arc::new(SessionState::new(sid_b))).await;
        let drained = live.drain().await;
        assert_eq!(drained.len(), 2);
        // After draining the table is empty so subsequent drain returns nothing.
        let again = live.drain().await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn drain_preserves_session_state_arc_for_duration_and_count_reads() {
        // The drain path uses `started_at` and `tool_call_count` from the
        // returned SessionState — pin that the Arcs come back live, not
        // lost copies. Bumping the counter inside the drained Arc must be
        // visible to the holder of the original Arc.
        let live = LiveSessions::new();
        let sid = SessionId::new();
        let session = Arc::new(SessionState::new(sid));
        live.insert(sid, Arc::clone(&session)).await;
        let drained = live.drain().await;
        assert_eq!(drained.len(), 1);
        let (drained_sid, drained_session) = &drained[0];
        assert_eq!(*drained_sid, sid);
        drained_session
            .tool_call_count
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            session
                .tool_call_count
                .load(std::sync::atomic::Ordering::Relaxed),
            7,
            "drained Arc must point to the same SessionState as the inserted Arc",
        );
    }
}
