//! Per-connection identifier for daemon sessions.
//!
//! `SessionId` is a ULID (Crockford-base32, 26 chars) so that records
//! sorted by `session_id` land in roughly creation order — a forensic
//! aid when reading the audit log.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// Per-client-connection identifier. Generated on accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(ulid::Ulid);

impl SessionId {
    /// Generate a fresh `SessionId` from the system clock + randomness.
    #[must_use]
    pub fn new() -> Self {
        Self(ulid::Ulid::new())
    }

    /// Underlying ULID (escape hatch for interop).
    #[must_use]
    pub fn as_ulid(self) -> ulid::Ulid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Parse a 26-char ULID into a `SessionId`.
impl FromStr for SessionId {
    type Err = ulid::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ulid::Ulid::from_str(s).map(Self)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::SessionId;
    use core::str::FromStr;

    #[test]
    fn new_returns_distinct_values_in_the_same_tick() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn display_round_trips_via_from_str() {
        let id = SessionId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 26);
        let parsed = SessionId::from_str(&s).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn serde_json_round_trip_preserves_value() {
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn timestamps_order_monotonically_across_newtype() {
        let first = SessionId::new();
        std::thread::sleep(core::time::Duration::from_millis(2));
        let second = SessionId::new();
        assert!(
            second.to_string() > first.to_string(),
            "expected later ULID's string form to be >= earlier; got {first} then {second}"
        );
    }
}
