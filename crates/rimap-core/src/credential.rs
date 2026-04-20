//! Credential provenance types and resolver trait. Referenced by
//! `rimap-config` (returned from `resolve_credential`), by
//! [`crate::auth_event::AuthEvent`] (recorded per auth attempt), and
//! by `rimap-imap::Connection` (which calls
//! [`CredentialResolver::resolve`] on every connect).

use std::error::Error as StdError;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::account::AccountId;

/// Where a successfully resolved credential came from. Recorded in `Auth`
/// records so post-incident analysis can detect silent fallbacks (e.g. an
/// operator's keyring entry went missing and the process started using the
/// global env-var fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Resolved from the new namespaced keyring key.
    Keyring,
    /// Resolved from the legacy unnamespaced keyring key — indicates the
    /// operator still needs to run `migrate-keyring`.
    LegacyKeyring,
    /// Resolved from `RUSTY_IMAP_MCP_PASSWORD`.
    EnvVar,
}

/// Why a [`CredentialResolver`] failed to produce a credential.
///
/// Carries a short reason string (suitable for inclusion in user-
/// facing error messages — must not contain filesystem paths or
/// other operator-specific layout) plus the underlying error for
/// observability via the source chain.
///
/// `rimap-imap`'s `Connection::connect_and_login` maps this into
/// `ImapError::Auth { reason: AuthFailure::CredentialUnavailable }`
/// without inspecting the source.
///
/// Fields are not `pub`; construct via [`Self::new`] /
/// [`Self::with_source`] and read via [`Self::reason`] (the
/// underlying error is available through `std::error::Error::source`).
#[derive(Debug, Error)]
#[error("credential unavailable: {reason}")]
pub struct CredentialResolverError {
    reason: String,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl CredentialResolverError {
    /// Build a resolver error from a reason string with no underlying
    /// source. Use when the failure is a policy decision (e.g., "no
    /// keyring entry and env-var fallback disabled") rather than an
    /// I/O error.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            source: None,
        }
    }

    /// Build a resolver error wrapping an underlying error.
    pub fn with_source(
        reason: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            reason: reason.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Short, sanitized human reason, suitable for inclusion in
    /// user-facing error messages. The underlying error is available
    /// through `std::error::Error::source`.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Consume this error and return the reason string. Lets
    /// transport callers move the reason into their own error
    /// surface without cloning.
    #[must_use]
    pub fn into_reason(self) -> String {
        self.reason
    }
}

/// Resolves a credential for one (account, username, host) triple.
///
/// `rimap-imap::Connection` holds an `Arc<dyn CredentialResolver>`
/// and calls [`Self::resolve`] inside `connect_and_login`. The trait
/// is intentionally narrower than `rimap-config::CredentialStore`:
/// the resolver bakes the keyring-vs-env-var fallback policy in at
/// construction time, so the IMAP transport never sees `FallbackMode`.
///
/// Implementations live downstream:
/// - `rimap-config`'s `KeyringCredentialResolver` wraps a
///   `Arc<dyn CredentialStore>` plus a `FallbackMode` and routes
///   through `resolve_credential`.
/// - Test fixtures supply a small in-memory adapter.
pub trait CredentialResolver: Send + Sync + std::fmt::Debug {
    /// Resolve the credential for `(account, username, host)`.
    /// Returns the resolved [`SecretString`] together with the
    /// [`CredentialSource`] so the caller can record provenance in
    /// the audit log.
    ///
    /// # Errors
    /// Returns [`CredentialResolverError`] when no source produced
    /// a credential or the configured store errored.
    fn resolve(
        &self,
        account: &AccountId,
        username: &str,
        host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError>;
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::CredentialSource;

    #[test]
    fn credential_source_serializes_as_snake_case() {
        let j = serde_json::to_string(&CredentialSource::LegacyKeyring).unwrap();
        assert_eq!(j, "\"legacy_keyring\"");
        let back: CredentialSource = serde_json::from_str(&j).unwrap();
        assert_eq!(back, CredentialSource::LegacyKeyring);
    }
}
