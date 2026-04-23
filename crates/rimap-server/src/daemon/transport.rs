//! Platform abstraction for the daemon's accept loop.
//!
//! Unix: `UnixListener` + `UnixStream` + `peer_cred()`.
//! Windows: `NamedPipeServer` (one-instance-per-client idiom). On Windows
//! the pipe DACL restricts access to the creating user, so peer identity
//! is reported as unknown on this platform until token-based SID lookup
//! lands; scope A is enforced by the OS regardless.
//!
//! Both platforms converge on a shared `PeerIdentity` audit-record
//! shape (`rimap_audit::record::PeerIdentity`).

use tokio::io::{AsyncRead, AsyncWrite};

use rimap_audit::record::PeerIdentity;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

/// One accepted client connection: a bidirectional byte stream plus
/// the peer's identity.
pub struct AcceptedConnection<S> {
    /// Bidirectional byte stream to the client. `rmcp::serve_server`
    /// will consume this via `IntoTransport`.
    pub stream: S,
    /// Peer identity as captured at accept time. Recorded on the
    /// `session_start` audit entry.
    pub identity: PeerIdentity,
}

/// A platform-specific listener. Impls bind in `new()` and accept in a loop.
///
/// # Ownership model
///
/// A `PlatformListener` is owned by a single accept task and is driven via
/// `&mut self`. It is not intended to be shared across tasks via `Arc` — the
/// underlying `UnixListener` / named-pipe handle is not cloneable in any
/// meaningful sense, and the mutex overhead would be wasted: the accept loop
/// is inherently sequential (one `accept` call at a time, handing each
/// connection off to a spawned task).
pub trait PlatformListener: Send + 'static {
    /// The bidirectional byte stream yielded by accept.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Accept one client connection. Blocks until a client connects or
    /// an I/O error occurs.
    ///
    /// # Closure / shutdown behaviour
    ///
    /// The listener is consumed by [`shutdown`](PlatformListener::shutdown),
    /// which drops the underlying handle and (on Unix) unlinks the socket
    /// file. Because the listener is held by `&mut self` — not shared —
    /// there is no concurrent reader-closer race: the accept loop task is
    /// the same task that calls `shutdown`. Dropping the listener while
    /// another task awaits `accept` would require `Arc<Mutex<…>>`, which
    /// this design intentionally avoids.
    ///
    /// # Errors
    /// Returns any I/O error from the underlying `accept` call.
    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = std::io::Result<AcceptedConnection<Self::Stream>>> + Send;

    /// Drop the listener, releasing platform resources (e.g. unlinking
    /// the Unix socket or closing all pending pipe instances).
    ///
    /// Shutdown is best-effort: implementations log errors at `warn!` but
    /// do not return them, because the listener's lifetime is already
    /// ending. `Drop` provides the same best-effort cleanup if `shutdown`
    /// is never called explicitly.
    fn shutdown(self);
}
