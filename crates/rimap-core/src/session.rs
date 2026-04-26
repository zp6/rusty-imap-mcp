//! Per-connection identifier for daemon sessions.
//!
//! `SessionId` is a ULID (Crockford-base32, 26 chars) so that records
//! sorted by `session_id` land in roughly creation order — a forensic
//! aid when reading the audit log.

crate::ulid_newtype! {
    /// Per-client-connection identifier. Generated on accept.
    pub struct SessionId;
    ctor: new;
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

    #[test]
    fn serde_json_is_a_bare_string_not_a_struct() {
        // On-disk schema pin: SessionId serializes as a bare JSON string,
        // NOT as `{"0":"..."}`. Any future refactor that drops serde
        // transparent would break every recorded audit log. This test is
        // deliberately conservative.
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let inner = &json[1..json.len() - 1];
        assert_eq!(
            inner.len(),
            26,
            "serialized form must be a raw ULID: {json}"
        );
    }
}
