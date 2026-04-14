//! `rimap_imap::ImapError` and conversion into `rimap_core::RimapError`.

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use thiserror::Error;

/// Errors produced by `rimap-imap`. Each variant maps to a stable
/// `ErrorCode` via `From<ImapError> for RimapError`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ImapError {
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
    #[error("connect failed")]
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
    /// Caller supplied invalid input (e.g. control bytes in a search string).
    #[error("ERR_INVALID_INPUT: {field}: {reason}")]
    InvalidInput {
        /// Short name identifying the field or parameter that is invalid.
        field: &'static str,
        /// Human-readable explanation of the validation failure.
        reason: &'static str,
    },
    /// Caller passed more UIDs than the per-command batch limit.
    #[error("ERR_BATCH_TOO_LARGE: {count} UIDs exceeds limit of {limit}")]
    BatchTooLarge {
        /// Number of UIDs the caller provided.
        count: usize,
        /// Maximum UIDs allowed per command.
        limit: usize,
    },
    /// Audit-subsystem failure during a tool call. The IMAP transport may
    /// be healthy; this variant exists so audit-write failures stay
    /// distinguishable from network failures in metrics and observability.
    #[error("ERR_AUDIT: {message}")]
    Audit {
        /// Short identifier of the audit operation that failed
        /// (e.g. `"emit_auth"`).
        op: &'static str,
        /// Human-readable failure summary captured at construction.
        message: String,
        /// Underlying error from the audit subsystem.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// Specific authentication failure mode for `ImapError::Auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The credential store had no entry for this `<user>@<host>` and the
    /// `RUSTY_IMAP_MCP_PASSWORD` env var fallback was empty or absent.
    /// The inner string is the operator-actionable reason from
    /// `rimap_config::credential::resolve_credential`.
    CredentialUnavailable(String),
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginRejected => f.write_str("LOGIN rejected"),
            Self::CapabilityMissing { needed } => write!(f, "missing capability `{needed}`"),
            Self::ServerRejected => f.write_str("server BYE greeting"),
            Self::CredentialUnavailable(reason) => write!(f, "credential unavailable: {reason}"),
        }
    }
}

impl ImapError {
    /// Map this error to the canonical [`ErrorCode`] used in audit
    /// records and the top-level [`RimapError`] envelope. Audit code
    /// strings flow through [`ErrorCode::as_str`] so they match the
    /// taxonomy instead of drifting as ad-hoc literals.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Tls { .. } | Self::TlsHandshake(_) => ErrorCode::Tls,
            Self::Connect(_) | Self::ConnectionLost => ErrorCode::ConnectionLost,
            Self::Timeout { .. } => ErrorCode::Timeout,
            Self::Auth { .. } => ErrorCode::Auth,
            Self::SizeLimit { .. } => ErrorCode::AttachmentTooLarge,
            Self::Protocol(_) => ErrorCode::ImapProtocol,
            Self::InvalidInput { .. } | Self::BatchTooLarge { .. } => ErrorCode::InvalidInput,
            Self::Audit { .. } => ErrorCode::Internal,
        }
    }
}

impl From<ImapError> for RimapError {
    fn from(err: ImapError) -> Self {
        let code = err.code();
        let message = err.to_string();
        RimapError::Imap {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
