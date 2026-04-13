//! SHA-256 TLS certificate fingerprint newtype. Used by `rimap-config` to
//! parse the configured pin, by `rimap-imap` to compare against the observed
//! cert during the TLS handshake, and by `rimap-audit` to record both.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256 fingerprint of a TLS leaf certificate (DER bytes).
///
/// Equality is constant-time. There is intentionally no `Debug` impl that
/// dumps the bytes as hex; use `Display` (`to_hex`) at the explicit point
/// of need.
#[derive(Clone, Copy, Eq)]
pub struct TlsFingerprint([u8; 32]);

/// Failure modes for parsing a hex-encoded fingerprint string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintParseError {
    /// Wrong number of hex characters (expected 64, optionally separated by colons).
    WrongLength {
        /// Number of hex chars after stripping colons.
        got: usize,
    },
    /// Encountered a non-hex character.
    NonHex {
        /// The offending character.
        ch: char,
    },
}

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => {
                write!(f, "fingerprint must be 64 hex chars, got {got}")
            }
            Self::NonHex { ch } => write!(f, "non-hex character `{ch}` in fingerprint"),
        }
    }
}

impl std::error::Error for FingerprintParseError {}

impl TlsFingerprint {
    /// Parse a hex-encoded fingerprint, ignoring colon separators.
    /// Accepts both `"AB:CD:..."` and `"abcd..."` forms; case-insensitive.
    ///
    /// # Errors
    /// Returns `FingerprintParseError` on length or character violations.
    pub fn from_hex(s: &str) -> Result<Self, FingerprintParseError> {
        let cleaned: String = s.chars().filter(|c| *c != ':').collect();
        if cleaned.len() != 64 {
            return Err(FingerprintParseError::WrongLength { got: cleaned.len() });
        }
        for c in cleaned.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(FingerprintParseError::NonHex { ch: c });
            }
        }
        // Both conversions are guarded by the validation above: 64 hex
        // chars always decode to exactly 32 bytes. Map residual errors to
        // WrongLength as a defensive fallback.
        let bytes = hex::decode(&cleaned)
            .map_err(|_| FingerprintParseError::WrongLength { got: cleaned.len() })?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FingerprintParseError::WrongLength { got: cleaned.len() })?;
        Ok(Self(arr))
    }

    /// Compute the fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn from_cert_der(der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(der);
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Borrow the raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, no separators (matches the audit log on-disk format).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Uppercase hex with colon separators (matches `openssl x509 -fingerprint -sha256`).
    #[must_use]
    pub fn to_hex_colon(&self) -> String {
        let hex_str = hex::encode_upper(self.0);
        let mut out = String::with_capacity(95);
        for (i, c) in hex_str.chars().enumerate() {
            if i > 0 && i.is_multiple_of(2) {
                out.push(':');
            }
            out.push(c);
        }
        out
    }
}

impl PartialEq for TlsFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking the bytes in arbitrary debug logs; surface only that
        // a fingerprint is present.
        f.write_str("TlsFingerprint(<redacted>)")
    }
}

impl Serialize for TlsFingerprint {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TlsFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(de)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{FingerprintParseError, TlsFingerprint};

    const SAMPLE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn from_hex_accepts_lowercase_no_separators() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        assert_eq!(fp.to_hex(), SAMPLE_HEX);
    }

    #[test]
    fn from_hex_accepts_uppercase_with_colons() {
        let with_colons = "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:\
             01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF";
        let fp = TlsFingerprint::from_hex(with_colons).unwrap();
        assert_eq!(fp.to_hex(), SAMPLE_HEX);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let err = TlsFingerprint::from_hex("abcd").unwrap_err();
        assert_eq!(err, FingerprintParseError::WrongLength { got: 4 });
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        let bad = "g".repeat(64);
        let err = TlsFingerprint::from_hex(&bad).unwrap_err();
        assert_eq!(err, FingerprintParseError::NonHex { ch: 'g' });
    }

    #[test]
    fn from_cert_der_matches_known_sha256() {
        // sha256("hello") in lowercase hex.
        let fp = TlsFingerprint::from_cert_der(b"hello");
        assert_eq!(
            fp.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn equality_is_constant_time_in_observable_behavior() {
        let a = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let b = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let c = TlsFingerprint::from_hex(&"f".repeat(64)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn to_hex_colon_matches_openssl_format() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let colon = fp.to_hex_colon();
        assert_eq!(colon.len(), 64 + 31, "32 bytes + 31 colons");
        assert!(colon.starts_with("01:23:45"));
        // Letters MUST be uppercase to match `openssl x509 -fingerprint -sha256`.
        for c in colon.chars() {
            assert!(
                c == ':' || c.is_ascii_digit() || c.is_ascii_uppercase(),
                "to_hex_colon must emit uppercase hex (got `{c}`)"
            );
        }
        // Spot check the AB and CD bytes are uppercase in the output.
        assert!(colon.contains(":AB:"));
        assert!(colon.contains(":CD:"));
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let debug = format!("{fp:?}");
        assert!(!debug.contains("0123"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn serde_round_trips_as_lowercase_hex_string() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, format!("\"{SAMPLE_HEX}\""));
        let back: TlsFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fp);
    }
}
