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
    }
}
