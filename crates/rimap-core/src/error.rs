//! Top-level error enum and stable error codes for rusty-imap-mcp.
//!
//! Every error carries a machine-readable [`ErrorCode`] and a human-readable
//! message. Codes are stable across releases; changing a code is a semver-major
//! break. The code list comes from design spec §9.

use thiserror::Error;

/// Stable machine-readable error codes, per design spec §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Input validation failed.
    InvalidInput,
    /// Tool denied by the active posture.
    PostureDenied,
    /// Rate limiter token bucket empty.
    RateLimited,
    /// Circuit breaker open.
    CircuitOpen,
    /// UID / folder / part missing.
    NotFound,
    /// IMAP server misbehaved.
    ImapProtocol,
    /// SMTP server rejected message or command.
    SmtpProtocol,
    /// TLS handshake or cert verification failed.
    Tls,
    /// Authentication rejected.
    Auth,
    /// Mid-call disconnect.
    ConnectionLost,
    /// Command exceeded time limit.
    Timeout,
    /// Attachment exceeded cap.
    AttachmentTooLarge,
    /// Operation blocked because the folder is in `protected_folders`.
    ProtectedFolder,
    /// Expunge or `delete_folder` blocked because folder is not in `expunge_folders`.
    ExpungeDenied,
    /// Startup-time configuration error.
    Config,
    /// Bug, invariant violation, or audit failure.
    Internal,
    /// Multiple accounts configured but none selected.
    NoAccount,
    /// Named account not found in registry.
    UnknownAccount,
}

impl ErrorCode {
    /// Stable on-wire string form (e.g. `"ERR_INVALID_INPUT"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "ERR_INVALID_INPUT",
            Self::PostureDenied => "ERR_POSTURE_DENIED",
            Self::RateLimited => "ERR_RATE_LIMITED",
            Self::CircuitOpen => "ERR_CIRCUIT_OPEN",
            Self::NotFound => "ERR_NOT_FOUND",
            Self::ImapProtocol => "ERR_IMAP_PROTOCOL",
            Self::SmtpProtocol => "ERR_SMTP_PROTOCOL",
            Self::Tls => "ERR_TLS",
            Self::Auth => "ERR_AUTH",
            Self::ConnectionLost => "ERR_CONNECTION_LOST",
            Self::Timeout => "ERR_TIMEOUT",
            Self::AttachmentTooLarge => "ERR_ATTACHMENT_TOO_LARGE",
            Self::ProtectedFolder => "ERR_PROTECTED_FOLDER",
            Self::ExpungeDenied => "ERR_EXPUNGE_DENIED",
            Self::Config => "ERR_CONFIG",
            Self::Internal => "ERR_INTERNAL",
            Self::NoAccount => "ERR_NO_ACCOUNT",
            Self::UnknownAccount => "ERR_UNKNOWN_ACCOUNT",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level tool error returned from dispatch. Library crates produce more
/// specific errors (`AuthzError`, `ConfigError`, `rimap_imap::Error`,
/// `AuditError`, …) which map into this via `From` impls.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RimapError {
    /// Authorization, posture, rate limit, or breaker failure.
    #[error("{code}: {message}")]
    Authz {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
    },
    /// IMAP-layer failure (TLS, auth, network, protocol, timeout, size cap).
    #[error("{code}: {message}")]
    Imap {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
        /// Underlying source error from `rimap_imap::Error`, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// SMTP-layer failure (connection, auth, TLS, rejection, timeout).
    #[error("{code}: {message}")]
    Smtp {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message (redacted — no server banners).
        message: String,
        /// Underlying source error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// Audit log failure. Carries both the stable code (open-time errors
    /// map to `ErrorCode::Config`, runtime errors to `ErrorCode::Internal`)
    /// and the original `AuditError` via the source chain. `message` is
    /// the source's `to_string()` captured at construction time so the
    /// Display form does not double-print the source when reporters walk
    /// the chain.
    #[error("{code}: {message}")]
    Audit {
        /// Stable error code — `Config` for open-time, `Internal` for runtime.
        code: ErrorCode,
        /// Human-readable message captured from the source at construction.
        message: String,
        /// The original audit error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Startup-time configuration error.
    #[error("ERR_CONFIG: {0}")]
    Config(String),
    /// Bug / invariant violation.
    #[error("ERR_INTERNAL: {0}")]
    Internal(String),
    /// Multiple accounts configured but none selected.
    #[error(
        "multiple accounts configured; call `use_account` or pass \
         `account` parameter. Available: {}",
        available.join(", ")
    )]
    NoAccount {
        /// Names of the available accounts.
        available: Vec<String>,
    },
    /// Named account not found in registry.
    #[error("account '{name}' not found. Available: {}", available.join(", "))]
    UnknownAccount {
        /// The name that was looked up.
        name: String,
        /// Names of the available accounts.
        available: Vec<String>,
    },
}

impl RimapError {
    /// Construct an `Authz { code: InvalidInput, ... }` for caller-side
    /// argument validation failures. Use this instead of hand-rolling the
    /// struct form — the `Authz` variant is the canonical envelope for
    /// codes that surface to MCP as `INVALID_PARAMS`.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::Authz {
            code: ErrorCode::InvalidInput,
            message: message.into(),
        }
    }

    /// The stable error code carried by this error.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authz { code, .. }
            | Self::Imap { code, .. }
            | Self::Smtp { code, .. }
            | Self::Audit { code, .. } => *code,
            Self::Config(_) => ErrorCode::Config,
            Self::Internal(_) => ErrorCode::Internal,
            Self::NoAccount { .. } => ErrorCode::NoAccount,
            Self::UnknownAccount { .. } => ErrorCode::UnknownAccount,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{ErrorCode, RimapError};

    #[test]
    fn every_error_code_has_stable_string() {
        let cases = [
            (ErrorCode::InvalidInput, "ERR_INVALID_INPUT"),
            (ErrorCode::PostureDenied, "ERR_POSTURE_DENIED"),
            (ErrorCode::RateLimited, "ERR_RATE_LIMITED"),
            (ErrorCode::CircuitOpen, "ERR_CIRCUIT_OPEN"),
            (ErrorCode::NotFound, "ERR_NOT_FOUND"),
            (ErrorCode::ImapProtocol, "ERR_IMAP_PROTOCOL"),
            (ErrorCode::SmtpProtocol, "ERR_SMTP_PROTOCOL"),
            (ErrorCode::Tls, "ERR_TLS"),
            (ErrorCode::Auth, "ERR_AUTH"),
            (ErrorCode::ConnectionLost, "ERR_CONNECTION_LOST"),
            (ErrorCode::Timeout, "ERR_TIMEOUT"),
            (ErrorCode::AttachmentTooLarge, "ERR_ATTACHMENT_TOO_LARGE"),
            (ErrorCode::ProtectedFolder, "ERR_PROTECTED_FOLDER"),
            (ErrorCode::ExpungeDenied, "ERR_EXPUNGE_DENIED"),
            (ErrorCode::Config, "ERR_CONFIG"),
            (ErrorCode::Internal, "ERR_INTERNAL"),
            (ErrorCode::NoAccount, "ERR_NO_ACCOUNT"),
            (ErrorCode::UnknownAccount, "ERR_UNKNOWN_ACCOUNT"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert_eq!(format!("{code}"), expected);
        }
    }

    #[test]
    fn rimap_error_code_accessor_matches_variant() {
        let authz = RimapError::Authz {
            code: ErrorCode::RateLimited,
            message: "slow down".to_string(),
        };
        assert_eq!(authz.code(), ErrorCode::RateLimited);
        assert_eq!(RimapError::Config("x".into()).code(), ErrorCode::Config);
        assert_eq!(RimapError::Internal("x".into()).code(), ErrorCode::Internal);
    }

    #[test]
    fn rimap_error_display_includes_code_prefix() {
        let err = RimapError::Authz {
            code: ErrorCode::PostureDenied,
            message: "tool disabled".to_string(),
        };
        assert_eq!(err.to_string(), "ERR_POSTURE_DENIED: tool disabled");
    }

    #[test]
    fn rimap_error_audit_display_does_not_duplicate_source() {
        use std::io;

        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::other("disk full"));
        let err = RimapError::Audit {
            code: ErrorCode::Internal,
            message: inner.to_string(),
            source: inner,
        };
        let displayed = err.to_string();
        // The display string should contain "disk full" exactly once.
        assert_eq!(displayed.matches("disk full").count(), 1);
        assert!(displayed.starts_with("ERR_INTERNAL: "));
    }
}
