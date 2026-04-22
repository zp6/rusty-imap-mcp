//! Platform abstraction for the daemon's accept loop.
//!
//! Unix: `UnixListener` + `UnixStream` + `peer_cred()`.
//! Windows: `NamedPipeServer` (one-instance-per-client idiom) +
//! `GetNamedPipeClientProcessId` + token-based SID lookup.
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
pub trait PlatformListener: Send + 'static {
    /// The bidirectional byte stream yielded by accept.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Accept one client connection. Blocks until a client connects,
    /// the listener is closed, or an I/O error occurs.
    ///
    /// # Errors
    /// Returns any I/O error from the underlying `accept` call.
    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = std::io::Result<AcceptedConnection<Self::Stream>>> + Send;

    /// Drop the listener, releasing platform resources (e.g. unlinking
    /// the Unix socket or closing all pending pipe instances).
    fn shutdown(self);
}
