//! `rimap_imap::Error` and conversion into `rimap_core::RimapError`.

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use thiserror::Error;

/// Errors produced by `rimap-imap`. Each variant maps to a stable
/// `ErrorCode` via `From<Error> for RimapError`.
#[derive(Debug, Error)]
pub enum Error {
    /// TLS leaf-cert fingerprint did not match the configured pin.
    #[error("ERR_TLS: fingerprint mismatch (observed={observed}, expected={expected})")]
    Tls {
        /// The fingerprint the server presented.
        observed: TlsFingerprint,
        /// The fingerprint configured in `imap.tls_fingerprint_sha256`.
        expected: TlsFingerprint,
    },
    /// TLS handshake failed for a reason other than fingerprint mismatch
    /// (signature algorithm, protocol version, webpki path error in unpinned mode).
    #[error("ERR_TLS: handshake failed")]
    TlsHandshake(#[source] rustls::Error),
    /// TCP connect failed.
    #[error("ERR_NETWORK: connect failed")]
    Connect(#[source] std::io::Error),
    /// `tokio::time::timeout` fired around an IMAP command.
    #[error("ERR_TIMEOUT: {op} exceeded deadline")]
    Timeout {
        /// Short tag identifying the operation that timed out.
        op: &'static str,
    },
    /// Authentication-layer failure (LOGIN rejected, LOGIN disabled, BYE greeting).
    #[error("ERR_AUTH: {reason}")]
    Auth {
        /// Specific failure mode.
        reason: AuthFailure,
    },
    /// Body fetch exceeded the configured size cap; connection was dropped.
    #[error("ERR_ATTACHMENT_TOO_LARGE: body size exceeded limit of {limit} bytes")]
    SizeLimit {
        /// The configured `max_fetch_body_bytes`.
        limit: u64,
    },
    /// Underlying `async-imap` protocol error.
    #[error("ERR_IMAP_PROTOCOL: {0}")]
    Protocol(#[source] async_imap::error::Error),
    /// TCP half-open: detected dead connection during a command.
    #[error("ERR_CONNECTION_LOST: connection torn down mid-command")]
    ConnectionLost,
}

/// Specific authentication failure mode for `Error::Auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    /// LOGIN command rejected by the server.
    LoginRejected,
    /// Server advertised `LOGINDISABLED` in CAPABILITY.
    CapabilityMissing {
        /// The capability that was required but missing.
        needed: &'static str,
    },
    /// Server sent `BYE` as its greeting.
    ServerRejected,
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginRejected => f.write_str("LOGIN rejected"),
            Self::CapabilityMissing { needed } => write!(f, "missing capability `{needed}`"),
            Self::ServerRejected => f.write_str("server BYE greeting"),
        }
    }
}

impl From<Error> for RimapError {
    fn from(err: Error) -> Self {
        let code = match &err {
            Error::Tls { .. } | Error::TlsHandshake(_) => ErrorCode::Tls,
            Error::Connect(_) | Error::ConnectionLost => ErrorCode::ConnectionLost,
            Error::Timeout { .. } => ErrorCode::Timeout,
            Error::Auth { .. } => ErrorCode::Auth,
            Error::SizeLimit { .. } => ErrorCode::AttachmentTooLarge,
            Error::Protocol(_) => ErrorCode::ImapProtocol,
        };
        let message = err.to_string();
        RimapError::Imap {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
