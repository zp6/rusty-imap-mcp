//! Daemon entry point: accept loop, per-session spawn, graceful shutdown.

use std::sync::Arc;

use rimap_audit::record::PeerIdentity;
use rimap_core::SessionId;
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::daemon::state::{DaemonState, SessionState};
use crate::daemon::transport::{AcceptedConnection, PlatformListener};
use crate::mcp::server::ImapMcpServer;

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
                let sid = SessionId::new();
                let session = Arc::new(SessionState::new(sid));
                if log_session_start_blocking(&state, sid, identity, &socket_path)
                    .await
                    .is_none()
                {
                    drop(stream);
                    continue;
                }
                sessions.spawn(build_session_future(Arc::clone(&state), stream, session));
            }
            Some(_) = sessions.join_next() => {
                // Reap completed sessions to keep the JoinSet bounded.
            }
        }
    }

    listener.shutdown();
    drain_sessions(sessions).await;
    Ok(())
}

/// Wait up to 5 seconds for in-flight sessions to finish, then abort the rest.
async fn drain_sessions(mut sessions: JoinSet<()>) {
    if sessions.is_empty() {
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
    sessions.shutdown().await;
    tracing::info!("session drain complete");
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

/// Build the async session future for a single accepted connection.
///
/// Assumes `session_start` has already been emitted by the caller. Runs
/// `rmcp::serve_server` and emits `session_end` on completion.
#[must_use = "dropping the session future loses session_end emission"]
async fn build_session_future<S>(state: Arc<DaemonState>, stream: S, session: Arc<SessionState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
            return;
        }
    };
    let quit = running.waiting().await;
    let (reason, last_err) = session_end_from_quit(quit);
    emit_session_end(&state, &session, reason, last_err).await;
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
    let end = rimap_audit::record::SessionEnd {
        session_id: session.id,
        reason,
        duration_ms,
        total_tool_calls: total,
        last_error,
    };
    log_session_end_blocking(state, end).await;
}
