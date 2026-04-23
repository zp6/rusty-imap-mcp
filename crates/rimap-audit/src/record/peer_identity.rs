//! Peer identity captured on session accept. Union of Unix-style
//! `(uid, pid)` and Windows-style `(sid, pid)`. Serialized with an
//! explicit `platform` tag so the audit log is self-describing across
//! platforms.

use serde::{Deserialize, Serialize};

/// Identity of the MCP client connected to the daemon, as observed
/// via `SO_PEERCRED` (Unix) or `GetNamedPipeClientProcessId` + token
/// lookup (Windows).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum PeerIdentity {
    /// Unix socket peer: kernel-reported user and (best-effort) process IDs.
    Unix {
        /// Peer's effective user ID.
        uid: u32,
        /// Peer's process ID (informational; racy on short-lived peers).
        /// `None` when the kernel did not report one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<i32>,
    },
    /// Windows named-pipe peer: user SID + PID.
    Windows {
        /// Peer's user SID in `S-R-I-S-...` form. `None` until the
        /// follow-up SID-lookup path lands.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sid: Option<String>,
        /// Peer's process ID from `GetNamedPipeClientProcessId`. `None`
        /// when capture is not yet implemented.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
    },
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::PeerIdentity;

    #[test]
    fn unix_variant_serializes_with_platform_tag() {
        let id = PeerIdentity::Unix {
            uid: 1000,
            pid: Some(12345),
        };
        let s = serde_json::to_string(&id).expect("serialize");
        assert_eq!(s, r#"{"platform":"unix","uid":1000,"pid":12345}"#);
    }

    #[test]
    fn windows_variant_serializes_with_platform_tag() {
        let id = PeerIdentity::Windows {
            sid: Some("S-1-5-21-0-0-0-1000".to_string()),
            pid: Some(67890),
        };
        let s = serde_json::to_string(&id).expect("serialize");
        assert_eq!(
            s,
            r#"{"platform":"windows","sid":"S-1-5-21-0-0-0-1000","pid":67890}"#
        );
    }

    #[test]
    fn unix_variant_round_trips() {
        let id = PeerIdentity::Unix {
            uid: 1000,
            pid: None,
        };
        let s = serde_json::to_string(&id).expect("serialize");
        let back: PeerIdentity = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn windows_variant_round_trips() {
        let id = PeerIdentity::Windows {
            sid: Some("S-1-5-21-0-0-0-1000".to_string()),
            pid: Some(42),
        };
        let s = serde_json::to_string(&id).expect("serialize");
        let back: PeerIdentity = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn windows_variant_with_unknown_fields_round_trips() {
        let id = PeerIdentity::Windows {
            sid: None,
            pid: None,
        };
        let s = serde_json::to_string(&id).expect("serialize");
        assert_eq!(s, r#"{"platform":"windows"}"#);
        let back: PeerIdentity = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn unknown_platform_rejects() {
        let err = serde_json::from_str::<PeerIdentity>(r#"{"platform":"haiku","uid":1,"pid":2}"#)
            .expect_err("unknown variant");
        assert!(err.to_string().contains("haiku"));
    }
}
