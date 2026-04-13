//! Authorization-layer error type. Converts into `RimapError::Authz` with the
//! appropriate error code.

use rimap_core::error::ErrorCode;
use rimap_core::tool::ToolName;
use thiserror::Error;

/// Errors produced by `rimap-authz` stages: posture, breaker, rate limiter.
#[derive(Debug, Error, Clone)]
pub enum AuthzError {
    /// Tool denied by the current posture matrix.
    #[error("tool `{0}` denied by current posture")]
    PostureDenied(ToolName),
    /// Rate limiter rejected the call; `retry_after_ms` is a hint.
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited {
        /// Hint for how long the caller should wait before retrying.
        retry_after_ms: u64,
    },
    /// Circuit breaker is open; fast-failing.
    #[error("circuit breaker open; retry after {retry_after_ms} ms")]
    CircuitOpen {
        /// Hint for how long the caller should wait before retrying.
        retry_after_ms: u64,
    },
    /// Config-time error during matrix build (e.g. unknown override tool).
    /// Wrapped as a string because we don't want `rimap-authz` to depend on
    /// the full `ConfigError` variant surface just for display.
    #[error("authz matrix build failed: {0}")]
    MatrixBuild(String),
    /// Folder is in the `protected_folders` list.
    #[error(
        "folder `{folder}` is protected and cannot be {operation}d; \
         remove it from protected_folders to allow this"
    )]
    ProtectedFolder {
        /// The folder name.
        folder: String,
        /// "delete" or "rename".
        operation: &'static str,
    },
    /// Folder is not in the `expunge_folders` allowlist.
    #[error(
        "expunge denied for folder `{folder}`; add it to expunge_folders \
         in your config to allow permanent deletion"
    )]
    ExpungeDenied {
        /// The folder name.
        folder: String,
    },
}

impl AuthzError {
    /// Map to the stable top-level error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PostureDenied(_) => ErrorCode::PostureDenied,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::MatrixBuild(_) => ErrorCode::Config,
            Self::ProtectedFolder { .. } => ErrorCode::ProtectedFolder,
            Self::ExpungeDenied { .. } => ErrorCode::ExpungeDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::AuthzError;
    use rimap_core::error::ErrorCode;
    use rimap_core::tool::ToolName;

    #[test]
    fn error_codes_match_spec() {
        assert_eq!(
            AuthzError::PostureDenied(ToolName::CreateDraft).code(),
            ErrorCode::PostureDenied
        );
        assert_eq!(
            AuthzError::RateLimited {
                retry_after_ms: 250
            }
            .code(),
            ErrorCode::RateLimited
        );
        assert_eq!(
            AuthzError::CircuitOpen {
                retry_after_ms: 15_000
            }
            .code(),
            ErrorCode::CircuitOpen
        );
        assert_eq!(
            AuthzError::MatrixBuild("x".into()).code(),
            ErrorCode::Config
        );
        assert_eq!(
            AuthzError::ProtectedFolder {
                folder: "INBOX".into(),
                operation: "delete",
            }
            .code(),
            ErrorCode::ProtectedFolder
        );
        assert_eq!(
            AuthzError::ExpungeDenied {
                folder: "Sent".into(),
            }
            .code(),
            ErrorCode::ExpungeDenied
        );
    }
}
