//! SMTP error type and conversion to `RimapError`.

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-smtp`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SmtpError {
    /// Cannot reach the SMTP server.
    #[error("SMTP connection failed: {0}")]
    Connection(String),
    /// SMTP authentication failed.
    #[error("SMTP authentication failed")]
    Auth(#[source] lettre::transport::smtp::Error),
    /// TLS handshake failed.
    #[error("SMTP TLS handshake failed")]
    Tls(#[source] lettre::transport::smtp::Error),
    /// Server rejected the message (4xx/5xx).
    #[error("SMTP send rejected: {reason}")]
    Rejected {
        /// Server response reason.
        reason: String,
    },
    /// SMTP command timed out.
    #[error("SMTP operation timed out")]
    Timeout,
    /// Catch-all for other lettre errors.
    #[error("SMTP error: {0}")]
    Transport(#[source] lettre::transport::smtp::Error),
}

impl From<SmtpError> for RimapError {
    fn from(err: SmtpError) -> Self {
        let (code, message) = match &err {
            SmtpError::Connection(_) => (
                ErrorCode::ConnectionLost,
                "SMTP connection failed".to_string(),
            ),
            SmtpError::Auth(_) => (ErrorCode::Auth, "SMTP authentication failed".to_string()),
            SmtpError::Tls(_) => (ErrorCode::Tls, "SMTP TLS handshake failed".to_string()),
            SmtpError::Rejected { .. } => (
                ErrorCode::SmtpProtocol,
                "SMTP server rejected the message".to_string(),
            ),
            SmtpError::Timeout => (ErrorCode::Timeout, "SMTP operation timed out".to_string()),
            SmtpError::Transport(_) => (ErrorCode::Internal, "SMTP transport error".to_string()),
        };
        RimapError::Smtp {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
