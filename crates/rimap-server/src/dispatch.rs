//! Shared tool dispatch pipeline.
//!
//! The guard chain runs before every tool handler:
//! posture check -> circuit breaker -> rate limiter.
//!
//! This module bridges `rimap_authz::DispatchGuard` (which returns
//! `AuthzError`) into `RimapError` for the server layer.

use rimap_authz::DispatchGuard;
use rimap_authz::breaker::Clock;
use rimap_core::RimapError;
use rimap_core::tool::ToolName;

/// Run the pre-call guard chain.
///
/// Returns `Ok(())` if all guards pass, or the first `RimapError`.
pub fn pre_call_guards<C: Clock>(
    guard: &DispatchGuard<C>,
    tool: ToolName,
) -> Result<(), RimapError> {
    guard.pre_dispatch(tool).map_err(|e| RimapError::Authz {
        code: e.code(),
        message: e.to_string(),
    })
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rimap_authz::DispatchGuard;
    use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, ManualClock};
    use rimap_authz::matrix::EffectiveMatrix;
    use rimap_authz::rate_limit::Governor;
    use rimap_core::error::ErrorCode;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use super::pre_call_guards;

    fn test_guard() -> DispatchGuard<ManualClock> {
        let matrix = EffectiveMatrix::build(Posture::Readonly, &BTreeMap::new());
        let breaker = CircuitBreaker::new(
            ManualClock::new(),
            BreakerConfig {
                error_threshold: 2,
                window: Duration::from_secs(10),
                starting_cooldown: Duration::from_secs(5),
                max_cooldown: Duration::from_secs(60),
                auth_starting_cooldown: Duration::from_secs(30),
                auth_max_cooldown: Duration::from_secs(600),
            },
        );
        let governor = Governor::new(100, 5, 3).expect("valid governor config");
        DispatchGuard::new(matrix, breaker, governor)
    }

    #[test]
    fn allowed_tool_passes() {
        let guard = test_guard();
        assert!(pre_call_guards(&guard, ToolName::ListFolders).is_ok());
    }

    #[test]
    fn denied_tool_returns_posture_denied() {
        let guard = test_guard();
        let err = pre_call_guards(&guard, ToolName::CreateDraft)
            .expect_err("should deny create_draft in readonly");
        assert_eq!(err.code(), ErrorCode::PostureDenied);
    }
}
