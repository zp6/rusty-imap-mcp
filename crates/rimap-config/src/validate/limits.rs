//! Numeric-limits validation. New positive-integer fields get a row in
//! the [`ZERO_CHECKS`] table rather than another `if` block.

use crate::error::ConfigError;
use crate::model::LimitsConfig;

/// Accessor for one field on `LimitsConfig` for the zero-check table.
type LimitAccessor = fn(&LimitsConfig) -> u64;

pub(super) fn validate_limits(limits: &LimitsConfig) -> Result<(), ConfigError> {
    /// Table of `(field_name, accessor)` for zero-value checks. New limits
    /// that must be `> 0` get added here rather than as another `if` block.
    const ZERO_CHECKS: &[(&str, LimitAccessor)] = &[
        ("limits.commands_per_second", |l| {
            u64::from(l.commands_per_second)
        }),
        ("limits.drafts_per_minute", |l| {
            u64::from(l.drafts_per_minute)
        }),
        ("limits.sends_per_minute", |l| u64::from(l.sends_per_minute)),
        ("limits.circuit_breaker_error_threshold", |l| {
            u64::from(l.circuit_breaker_error_threshold)
        }),
        ("limits.circuit_breaker_window_seconds", |l| {
            u64::from(l.circuit_breaker_window_seconds)
        }),
        ("limits.max_search_results", |l| {
            u64::from(l.max_search_results)
        }),
        ("limits.max_fetch_body_bytes", |l| l.max_fetch_body_bytes),
        ("limits.max_attachment_bytes", |l| l.max_attachment_bytes),
        ("limits.max_append_bytes", |l| l.max_append_bytes),
    ];
    for (field, accessor) in ZERO_CHECKS {
        if accessor(limits) == 0 {
            return Err(ConfigError::InvalidLimit {
                field,
                reason: "must be > 0".to_string(),
            });
        }
    }
    if limits.max_search_results > limits.max_search_results_cap {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: format!(
                "default {} exceeds cap {}",
                limits.max_search_results, limits.max_search_results_cap
            ),
        });
    }
    Ok(())
}
