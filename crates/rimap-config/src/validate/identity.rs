//! Identity-shaped checks: username sanity and TLS fingerprint parsing.

use rimap_core::tls::TlsFingerprint;

use crate::error::ConfigError;

pub(super) fn validate_imap_username(username: &str) -> Result<(), ConfigError> {
    validate_username_field(username, "imap.username")
}

pub(super) fn validate_smtp_username(username: &str) -> Result<(), ConfigError> {
    validate_username_field(username, "smtp.username")
}

fn validate_username_field(username: &str, field: &'static str) -> Result<(), ConfigError> {
    if username.is_empty() {
        return Err(ConfigError::InvalidLimit {
            field,
            reason: "username must not be empty".to_string(),
        });
    }
    if username
        .chars()
        .any(|c| c == '\r' || c == '\n' || c == '\0')
    {
        return Err(ConfigError::InvalidLimit {
            field,
            reason: "username must not contain CR, LF, or NUL".to_string(),
        });
    }
    Ok(())
}

pub(super) fn parse_fingerprint(
    maybe_fp: Option<&str>,
) -> Result<Option<TlsFingerprint>, ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(None);
    };
    let fp = TlsFingerprint::from_hex(raw).map_err(|e| ConfigError::TlsFingerprint {
        reason: e.to_string(),
    })?;
    Ok(Some(fp))
}
