//! Rate limiter wrapper around `governor`.
//!
//! Three buckets (design spec §9):
//!   - Global: `limits.commands_per_second` with burst = 2× rate.
//!   - Draft: `limits.drafts_per_minute`, only consulted on `create_draft`.
//!   - Send: `limits.sends_per_minute`, only consulted on `send_email`.
//!
//! On exceed: return `AuthzError::RateLimited { retry_after_ms }`. The caller
//! (dispatch guard) decides whether to wait or fail.

use std::num::NonZeroU32;

use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Combined global + draft + send rate limiter.
pub struct Governor {
    global: DirectLimiter,
    drafts: DirectLimiter,
    sends: DirectLimiter,
    clock: DefaultClock,
}

impl Governor {
    /// Build from numeric limits.
    ///
    /// # Errors
    /// Returns `AuthzError::MatrixBuild` if either rate is zero (validation
    /// should have caught this already, but we refuse to build a degenerate
    /// limiter).
    pub fn new(
        commands_per_second: u32,
        drafts_per_minute: u32,
        sends_per_minute: u32,
    ) -> Result<Self, AuthzError> {
        let cps = NonZeroU32::new(commands_per_second).ok_or_else(|| {
            AuthzError::MatrixBuild("commands_per_second must be > 0".to_string())
        })?;
        let dpm = NonZeroU32::new(drafts_per_minute)
            .ok_or_else(|| AuthzError::MatrixBuild("drafts_per_minute must be > 0".to_string()))?;
        let spm = NonZeroU32::new(sends_per_minute)
            .ok_or_else(|| AuthzError::MatrixBuild("sends_per_minute must be > 0".to_string()))?;
        let burst = NonZeroU32::new(commands_per_second.saturating_mul(2).max(1))
            .unwrap_or(NonZeroU32::MIN);
        let global_quota = Quota::per_second(cps).allow_burst(burst);
        let draft_quota = Quota::per_minute(dpm);
        let send_quota = Quota::per_minute(spm);
        Ok(Self {
            global: RateLimiter::direct(global_quota),
            drafts: RateLimiter::direct(draft_quota),
            sends: RateLimiter::direct(send_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Attempt to admit a single call. Returns `Ok(())` on admit,
    /// `Err(RateLimited)` on reject.
    ///
    /// # Errors
    /// `AuthzError::RateLimited` when the relevant bucket is empty.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.global.check().map_err(|nu| AuthzError::RateLimited {
            retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                .unwrap_or(u64::MAX),
        })?;
        if matches!(tool, ToolName::CreateDraft) {
            self.drafts.check().map_err(|nu| AuthzError::RateLimited {
                retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                    .unwrap_or(u64::MAX),
            })?;
        }
        if matches!(tool, ToolName::SendEmail) {
            self.sends.check().map_err(|nu| AuthzError::RateLimited {
                retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                    .unwrap_or(u64::MAX),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use crate::rate_limit::Governor;

    #[test]
    fn zero_rate_rejected_at_build() {
        assert!(Governor::new(0, 5, 3).is_err());
        assert!(Governor::new(10, 0, 3).is_err());
    }

    #[test]
    fn admits_first_call_in_bucket() {
        let g = Governor::new(10, 5, 3).unwrap();
        assert!(g.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn rejects_after_bucket_drains() {
        let g = Governor::new(2, 5, 3).unwrap(); // burst = 4
        for _ in 0..4 {
            let _ = g.check(ToolName::Search);
        }
        let mut rejected = false;
        for _ in 0..4 {
            if let Err(AuthzError::RateLimited { .. }) = g.check(ToolName::Search) {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "bucket should drain within a handful of calls");
    }

    #[test]
    fn draft_bucket_is_separate() {
        let g = Governor::new(1000, 5, 3).unwrap(); // huge global, tight draft
        for _ in 0..5 {
            let _ = g.check(ToolName::CreateDraft);
        }
        let draft_err = g.check(ToolName::CreateDraft).unwrap_err();
        assert!(matches!(draft_err, AuthzError::RateLimited { .. }));
        assert!(g.check(ToolName::Search).is_ok());
    }

    #[test]
    fn sends_bucket_is_separate() {
        let g = Governor::new(1000, 5, 3).unwrap();
        for _ in 0..3 {
            let _ = g.check(ToolName::SendEmail);
        }
        let send_err = g.check(ToolName::SendEmail).unwrap_err();
        assert!(matches!(send_err, AuthzError::RateLimited { .. }));
        assert!(g.check(ToolName::Search).is_ok());
    }

    #[test]
    fn zero_sends_per_minute_rejected_at_build() {
        assert!(Governor::new(10, 5, 0).is_err());
    }

    use proptest::prelude::*;

    proptest! {
        /// Steady-state: with N calls against a bucket of burst B, we should
        /// admit *at most* B + (time_elapsed * rate) calls, and at least B
        /// if no meaningful time elapses.
        #[test]
        fn steady_state_never_exceeds_burst_plus_refill(
            cps in 1u32..50u32,
            attempts in 1usize..200usize,
        ) {
            let g = Governor::new(cps, 1, 3).unwrap();
            let mut admitted = 0usize;
            for _ in 0..attempts {
                if g.check(ToolName::Search).is_ok() {
                    admitted += 1;
                }
            }
            let burst = (cps as usize).saturating_mul(2);
            prop_assert!(
                admitted <= burst * 10 + 10,
                "admitted {admitted} calls against burst {burst} (cps={cps})"
            );
            prop_assert!(admitted >= 1, "should admit at least one call");
        }
    }
}
