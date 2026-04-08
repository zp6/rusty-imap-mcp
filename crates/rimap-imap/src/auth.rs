//! Builders that translate connect-flow outcomes into `rimap_audit::Auth`
//! records. Pure functions — no I/O, no audit emission. The caller
//! (`connection.rs`) hands the result to `AuditWriter::log_auth`.

use rimap_audit::record::{Auth, AuthResult};
use rimap_core::TlsFingerprint;

/// Inputs every `Auth` record needs.
pub(crate) struct AuthContext<'a> {
    /// IMAP server host.
    pub host: &'a str,
    /// IMAP server port.
    pub port: u16,
    /// IMAP login identity (never a password).
    pub username: &'a str,
    /// Configured pinned fingerprint, if any.
    pub pinned: Option<TlsFingerprint>,
    /// Fingerprint the server actually presented, if handshake reached cert verification.
    pub observed: Option<TlsFingerprint>,
}

impl AuthContext<'_> {
    fn fingerprint_match(&self) -> Option<bool> {
        match (self.pinned, self.observed) {
            (Some(p), Some(o)) => Some(p == o),
            (Some(_) | None, None) | (None, Some(_)) => None,
        }
    }

    fn observed_hex(&self) -> Option<String> {
        self.observed.map(|f| f.to_hex())
    }
}

/// Build a successful `Auth` record.
pub(crate) fn auth_success(ctx: &AuthContext<'_>) -> Auth {
    Auth {
        result: AuthResult::Success,
        host: ctx.host.to_string(),
        port: ctx.port,
        username: ctx.username.to_string(),
        tls_fingerprint_sha256: ctx.observed_hex(),
        fingerprint_match: ctx.fingerprint_match(),
        error_code: None,
    }
}

/// Build a failure `Auth` record carrying the stable error code.
pub(crate) fn auth_failure(ctx: &AuthContext<'_>, error_code: &str) -> Auth {
    Auth {
        result: AuthResult::Failure,
        host: ctx.host.to_string(),
        port: ctx.port,
        username: ctx.username.to_string(),
        tls_fingerprint_sha256: ctx.observed_hex(),
        fingerprint_match: ctx.fingerprint_match(),
        error_code: Some(error_code.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthContext, auth_failure, auth_success};
    use rimap_audit::record::AuthResult;
    use rimap_core::TlsFingerprint;

    fn fp(seed: &[u8]) -> TlsFingerprint {
        TlsFingerprint::from_cert_der(seed)
    }

    #[test]
    fn success_with_matching_fingerprint() {
        let pin = fp(b"good");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(pin),
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.result, AuthResult::Success);
        assert_eq!(rec.fingerprint_match, Some(true));
        assert_eq!(rec.tls_fingerprint_sha256, Some(pin.to_hex()));
        assert!(rec.error_code.is_none());
    }

    #[test]
    fn failure_with_mismatched_fingerprint() {
        let pin = fp(b"good");
        let observed = fp(b"bad");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(observed),
        };
        let rec = auth_failure(&ctx, "ERR_TLS");
        assert_eq!(rec.result, AuthResult::Failure);
        assert_eq!(rec.fingerprint_match, Some(false));
        assert_eq!(rec.error_code.as_deref(), Some("ERR_TLS"));
    }

    #[test]
    fn unpinned_observed_yields_none_match() {
        let observed = fp(b"x");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: None,
            observed: Some(observed),
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.fingerprint_match, None);
        assert!(rec.tls_fingerprint_sha256.is_some());
    }

    #[test]
    fn pinned_with_no_observation_yields_no_fingerprint() {
        // The handshake aborted before the verifier ran (e.g., TCP RST
        // mid-TLS), so we have a pin but never captured a fingerprint.
        // The audit record must carry no fingerprint hex and no match
        // verdict — recording stale data here would mislead operators.
        let pin = fp(b"good");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: None,
        };
        let rec = auth_failure(&ctx, "ERR_NETWORK");
        assert_eq!(rec.result, AuthResult::Failure);
        assert_eq!(rec.tls_fingerprint_sha256, None);
        assert_eq!(rec.fingerprint_match, None);
        assert_eq!(rec.error_code.as_deref(), Some("ERR_NETWORK"));
    }
}
