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
                    handle_rejected_peer(&state, &identity, &socket_path);
                    drop(stream);
                    continue;
                }
                if let Some(future) = build_session_future(&state, stream, identity, &socket_path) {
                    sessions.spawn(future);
                }
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

/// Emit a `session_start` record for `sid`. Failure is logged at the supplied
/// level and otherwise ignored, so callers can choose whether to continue
/// (reject path) or bail (accept path).
fn log_session_start(
    state: &DaemonState,
    sid: SessionId,
    identity: PeerIdentity,
    socket_path: &str,
) -> Result<rimap_audit::Seq, rimap_audit::AuditError> {
    state
        .audit
        .log_session_start(rimap_audit::record::SessionStart {
            session_id: sid,
            peer_identity: identity,
            socket_path: socket_path.to_owned(),
        })
}

/// Emit paired `session_start` + `session_end(PeerUidRejected)` for a
/// connection whose peer identity does not match ours, then close it.
fn handle_rejected_peer(state: &Arc<DaemonState>, identity: &PeerIdentity, socket_path: &str) {
    let sid = SessionId::new();
    if let Err(e) = log_session_start(state, sid, identity.clone(), socket_path) {
        tracing::warn!(error = %e, "failed to log session_start for rejected peer");
    }
    let end = rimap_audit::record::SessionEnd {
        session_id: sid,
        reason: rimap_audit::record::SessionEndReason::PeerUidRejected,
        duration_ms: 0,
        total_tool_calls: 0,
        last_error: None,
    };
    if let Err(e) = state.audit.log_session_end(end) {
        tracing::warn!(error = %e, "failed to log session_end for rejected peer");
    }
    tracing::warn!(?identity, "rejected peer with mismatching identity");
}

/// Build the async session future for a single accepted connection.
///
/// Emits `session_start`, then returns the future that runs `rmcp::serve_server`
/// and emits `session_end`. Returns `None` and logs an error if `session_start`
/// fails (preventing the connection from being tracked).
fn build_session_future<S>(
    state: &Arc<DaemonState>,
    stream: S,
    identity: PeerIdentity,
    socket_path: &str,
) -> Option<impl std::future::Future<Output = ()> + Send + 'static>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sid = SessionId::new();
    let session = Arc::new(SessionState::new(sid));
    if let Err(e) = log_session_start(state, sid, identity, socket_path) {
        tracing::error!(error = %e, "failed to log session_start; dropping connection");
        return None;
    }
    let state_for_task = Arc::clone(state);
    let session_for_end = Arc::clone(&session);
    Some(async move {
        let mcp = ImapMcpServer::new(Arc::clone(&state_for_task), Arc::clone(&session));
        let serve_result = Box::pin(rmcp::serve_server(mcp, stream)).await;
        let running = match serve_result {
            Ok(svc) => svc,
            Err(e) => {
                tracing::error!(error = %e, "rmcp::serve_server initialisation failed");
                emit_session_end(
                    &state_for_task,
                    &session_for_end,
                    rimap_audit::record::SessionEndReason::Error,
                    Some(format!("serve_server init: {e}")),
                );
                return;
            }
        };
        let quit = running.waiting().await;
        let (reason, last_err) = session_end_from_quit(quit);
        emit_session_end(&state_for_task, &session_for_end, reason, last_err);
    })
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
fn emit_session_end(
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
    if let Err(e) = state.audit.log_session_end(end) {
        tracing::warn!(error = %e, "failed to log session_end");
    }
}
