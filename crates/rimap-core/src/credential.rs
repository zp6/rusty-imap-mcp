//! Credential provenance types. Referenced by `rimap-config` (returned from
//! `resolve_credential`) and by `rimap-audit::record::Auth` (recorded per
//! auth attempt). Kept here so neither crate has to depend on the other.

use serde::{Deserialize, Serialize};

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
