//! Daemon entry point: accept loop, per-session spawn, graceful shutdown.

use std::sync::Arc;

use rimap_audit::record::PeerIdentity;
use rimap_core::SessionId;
use tokio::sync::Notify;

use crate::daemon::state::{DaemonState, SessionState};
use crate::daemon::transport::{AcceptedConnection, PlatformListener};
use crate::mcp::server::ImapMcpServer;

/// Run the daemon until a shutdown signal fires.
///
/// Accepts connections from `listener`, gates on peer identity, and spawns one
/// `rmcp::serve_server` task per accepted client. Returns when `shutdown` is
/// notified.
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
    let socket_path = resolve_socket_path(&listener);
    let peer_gate = make_peer_gate();
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
                    handle_rejected_peer(&state, &identity);
                    drop(stream);
                    continue;
                }
                spawn_session(&state, stream, identity, socket_path.clone());
            }
        }
    }
    listener.shutdown();
    Ok(())
}

/// Returns the socket path string from a listener that exposes one, or a
/// generic placeholder. Unix listeners carry the path; Windows placeholders
/// are added in a follow-up.
fn resolve_socket_path<L: PlatformListener>(_listener: &L) -> String {
    // The trait does not expose a path accessor today. When UnixSocketListener
    // gains a `path()` method in a future task, downcast or thread it here.
    // For now use a fixed placeholder that integrations tests can detect.
    "(daemon socket)".to_string()
}

/// Build the peer-identity gate for this platform.
///
/// Unix: accepts only connections whose UID matches our own effective UID,
/// using `rustix` to avoid unsafe FFI.
///
/// Windows: OS-level DACL on the named pipe already restricts access; the
/// SID comparison requires unsafe FFI that conflicts with the workspace
/// `unsafe_code = "forbid"` policy, so we accept all callers and rely on
/// the pipe ACL (scope A, v1 placeholder).
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

/// Emit paired `session_start` + `session_end(PeerUidRejected)` for a
/// connection whose peer identity does not match ours, then close it.
fn handle_rejected_peer(state: &Arc<DaemonState>, identity: &PeerIdentity) {
    let sid = SessionId::new();
    let start = rimap_audit::record::SessionStart {
        session_id: sid,
        peer_identity: identity.clone(),
        socket_path: "(rejected before attach)".to_string(),
    };
    if let Err(e) = state.audit.log_session_start(start) {
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

/// Create a `SessionState`, emit `session_start`, and spawn an
/// `rmcp::serve_server` task. The spawned task emits `session_end` on
/// completion.
fn spawn_session<S>(
    state: &Arc<DaemonState>,
    stream: S,
    identity: PeerIdentity,
    socket_path: String,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sid = SessionId::new();
    let session = Arc::new(SessionState::new(sid));
    let start = rimap_audit::record::SessionStart {
        session_id: sid,
        peer_identity: identity,
        socket_path,
    };
    if let Err(e) = state.audit.log_session_start(start) {
        tracing::error!(error = %e, "failed to log session_start; dropping connection");
        return;
    }
    let state_for_task = Arc::clone(state);
    let session_for_end = Arc::clone(&session);
    tokio::spawn(async move {
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
    });
}

/// Map `waiting()`'s `QuitReason` outcome to an audit `(SessionEndReason,
/// Option<String>)` pair.
fn session_end_from_quit(
    quit: Result<rmcp::service::QuitReason, tokio::task::JoinError>,
) -> (rimap_audit::record::SessionEndReason, Option<String>) {
    match quit {
        Ok(rmcp::service::QuitReason::JoinError(e)) | Err(e) => (
            rimap_audit::record::SessionEndReason::Error,
            Some(format!("task join error: {e}")),
        ),
        Ok(_) => (rimap_audit::record::SessionEndReason::Eof, None),
    }
}

/// Write a `session_end` record with elapsed duration and tool-call count.
fn emit_session_end(
    state: &Arc<DaemonState>,
    session: &Arc<SessionState>,
    reason: rimap_audit::record::SessionEndReason,
    last_error: Option<String>,
) {
    let duration_ms = u64::try_from(session.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
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
