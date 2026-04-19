//! Credential resolution.
//!
//! Order of precedence (design spec §4, updated for #77):
//!   1. OS keychain (service = `rusty-imap-mcp`,
//!      account = `<account-id>/<username>@<host>`), with a back-compat read
//!      on the legacy `<username>@<host>` form that logs a migration hint.
//!   2. Environment variable `RUSTY_IMAP_MCP_PASSWORD`.
//!   3. Clear, actionable error naming both.

use rimap_core::account::AccountId;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Service name used for all keychain entries.
pub const KEYCHAIN_SERVICE: &str = "rusty-imap-mcp";

/// Environment variable name checked as fallback.
pub const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Abstract credential store. Production uses [`KeyringStore`]; tests
/// substitute an in-memory map.
pub trait CredentialStore: Send + Sync {
    /// Return the stored password for `account`, or `Ok(None)` if absent.
    /// Any *other* error (permission denied, service unreachable) returns
    /// `Err`.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError>;

    /// Persist `password` for `account`, overwriting any existing entry.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError>;
}

/// Build the keyring account key for `(account_id, username, host)`.
///
/// New format: `<account-id>/<username>@<host>`. Added in #77 to prevent
/// collisions when two accounts share a `<username>@<host>` tuple. Use
/// [`legacy_account_key`] only for the read-fallback path during migration.
#[must_use]
pub fn account_key(account_id: &AccountId, username: &str, host: &str) -> String {
    format!("{}/{username}@{host}", account_id.as_str())
}

/// Legacy keyring key format (`<username>@<host>`) — retained for the
/// back-compat read path in [`resolve_credential`]. New code MUST call
/// [`account_key`].
#[must_use]
pub fn legacy_account_key(username: &str, host: &str) -> String {
    format!("{username}@{host}")
}

/// Return a short (16 hex chars) SHA-256 hash of `"{username}@{host}"` suitable
/// for correlating error/audit log lines without disclosing the username.
///
/// 16 hex chars = 64 bits of prefix — collision probability is negligible at
/// the scale of "accounts a single deployment's error chain correlates".
/// The hash is not a keyring key — `account_key` remains distinct and uses the
/// full unhashed identifiers.
#[must_use]
pub fn hash_account_tag(username: &str, host: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(b"@");
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use core::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Split a `username@host` account key back into `(host, account_tag)` for
/// building error records. If the input has no `@` (malformed), treat the
/// whole string as host and use an empty username for hashing.
fn split_account_for_error(account: &str) -> (String, String) {
    let (username, host) = account.split_once('@').unwrap_or(("", account));
    (host.to_string(), hash_account_tag(username, host))
}

/// Resolve a credential: try the store first (new key, then legacy key), then
/// optionally the env var (depending on `fallback_mode`), then fail.
///
/// Accepts `&dyn CredentialStore` so callers that hold an
/// `Arc<dyn CredentialStore>` can pass `&*arc` without a generic bound.
/// Concrete references (e.g. `&KeyringStore`) coerce to `&dyn CredentialStore`
/// automatically, so existing callers are unaffected.
///
/// Returns `(SecretString, CredentialSource)` — the source lets callers record
/// where the credential came from for audit/observability purposes.
///
/// # Errors
/// - `ConfigError::Keychain` if the store itself errored.
/// - `ConfigError::NoCredential` if no source produced a value.
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
    fallback_mode: crate::model::FallbackMode,
) -> Result<(SecretString, rimap_core::CredentialSource), ConfigError> {
    use rimap_core::CredentialSource;

    let new_key = account_key(account_id, username, host);
    if let Some(p) = store.get_password(&new_key)?
        && !p.expose_secret().is_empty()
    {
        return Ok((p, CredentialSource::Keyring));
    }

    // Back-compat: before #77 the keyring key was <username>@<host>, with no
    // account-id prefix. If the new key lookup missed, try the legacy key and
    // warn the operator to run `rusty-imap-mcp migrate-keyring`.
    let legacy_key = legacy_account_key(username, host);
    if let Some(p) = store.get_password(&legacy_key)?
        && !p.expose_secret().is_empty()
    {
        tracing::warn!(
            account_id = %account_id.as_str(),
            host = %host,
            "credential resolved via legacy keyring key format; \
             run `rusty-imap-mcp migrate-keyring --account {}` to migrate",
            account_id.as_str(),
        );
        return Ok((p, CredentialSource::LegacyKeyring));
    }

    if fallback_mode == crate::model::FallbackMode::KeyringThenEnv
        && let Ok(env) = std::env::var(PASSWORD_ENV_VAR)
        && !env.is_empty()
    {
        return Ok((SecretString::from(env), CredentialSource::EnvVar));
    }

    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: build_no_credential_reason(account_id, fallback_mode, &new_key, &legacy_key),
    })
}

fn build_no_credential_reason(
    account_id: &AccountId,
    fallback_mode: crate::model::FallbackMode,
    new_key: &str,
    legacy_key: &str,
) -> String {
    match fallback_mode {
        crate::model::FallbackMode::KeyringOnly => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`; fallback mode is \
             keyring-only (env var not consulted). Run `rusty-imap-mcp \
             login --account {}`",
            account_id.as_str(),
        ),
        crate::model::FallbackMode::KeyringThenEnv => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`, and `{PASSWORD_ENV_VAR}` \
             is unset or empty. Run `rusty-imap-mcp login --account {}` \
             or set the environment variable",
            account_id.as_str(),
        ),
    }
}

/// Keychain-backed [`CredentialStore`] using the `keyring` crate. Not
/// constructed in unit tests (keychain access is unreliable in CI).
#[derive(Debug, Default)]
pub struct KeyringStore;

impl CredentialStore for KeyringStore {
    fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })?;
        match entry.get_password() {
            Ok(p) => Ok(Some(SecretString::from(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                let (host, account_tag) = split_account_for_error(account);
                Err(ConfigError::Keychain {
                    host,
                    account_tag,
                    source: Box::new(e),
                })
            }
        }
    }

    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })?;
        entry.set_password(password).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use secrecy::{ExposeSecret, SecretString};

    use rimap_core::account::AccountId;

    use crate::credential::{CredentialStore, PASSWORD_ENV_VAR, account_key, resolve_credential};
    use crate::error::ConfigError;
    use crate::model::FallbackMode;

    #[test]
    fn hash_account_tag_is_16_hex_and_deterministic() {
        let a = super::hash_account_tag("alice", "mail.example.com");
        let b = super::hash_account_tag("alice", "mail.example.com");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_account_tag_differs_on_different_inputs() {
        let a = super::hash_account_tag("alice", "mail.example.com");
        let b = super::hash_account_tag("bob", "mail.example.com");
        let c = super::hash_account_tag("alice", "other.example.com");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[derive(Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
        fail_on_get: bool,
    }

    impl MockStore {
        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut map = HashMap::new();
            for (k, v) in pairs {
                map.insert((*k).to_string(), (*v).to_string());
            }
            Self {
                entries: Mutex::new(map),
                fail_on_get: false,
            }
        }

        fn failing() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                fail_on_get: true,
            }
        }
    }

    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
            if self.fail_on_get {
                let (host, account_tag) = super::split_account_for_error(account);
                return Err(ConfigError::Keychain {
                    host,
                    account_tag,
                    source: "simulated failure".into(),
                });
            }
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(SecretString::from))
        }

        fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_string());
            Ok(())
        }
    }

    #[test]
    fn account_key_uses_namespaced_format() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let key = account_key(&id, "alice", "mail.example.test");
        assert_eq!(key, "work/alice@mail.example.test");
    }

    #[test]
    fn legacy_account_key_returns_bare_form() {
        let key = super::legacy_account_key("alice", "mail.example.test");
        assert_eq!(key, "alice@mail.example.test");
    }

    #[test]
    fn resolve_credential_reads_new_key_format_first() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[
            ("work/alice@host", "from_new_key"),
            ("alice@host", "from_legacy_key"),
        ]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (got, _src) =
                resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringThenEnv)
                    .unwrap();
            assert_eq!(got.expose_secret(), "from_new_key");
        });
    }

    #[test]
    fn resolve_credential_falls_back_to_legacy_key() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "from_legacy_key")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (got, _src) =
                resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringThenEnv)
                    .unwrap();
            assert_eq!(got.expose_secret(), "from_legacy_key");
        });
    }

    #[test]
    fn keychain_hit_wins_over_env() {
        let default_id = AccountId::default_account();
        let store = MockStore::with(&[("default/alice@host", "from_keychain")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (got, _src) = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_keychain");
        });
    }

    #[test]
    fn env_used_when_keychain_empty() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (got, _src) = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_env");
        });
    }

    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
            )
            .unwrap_err();
            match err {
                ConfigError::NoCredential {
                    host,
                    account_tag,
                    reason,
                } => {
                    assert_eq!(host, "host");
                    assert_eq!(account_tag.len(), 16);
                    assert!(reason.contains("rusty-imap-mcp login"));
                    assert!(reason.contains("RUSTY_IMAP_MCP_PASSWORD"));
                }
                other => panic!("wrong variant: {other:?}"),
            }
        });
    }

    #[test]
    fn keychain_error_propagates() {
        let store = MockStore::failing();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("unused"), || {
            let err = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn empty_keychain_value_falls_through_to_env() {
        let default_id = AccountId::default_account();
        let store = MockStore::with(&[("default/alice@host", "")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            assert_eq!(
                resolve_credential(
                    &store,
                    &default_id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                )
                .unwrap()
                .0
                .expose_secret(),
                "from_env"
            );
        });
    }

    #[test]
    fn resolved_credential_debug_does_not_leak() {
        let p = SecretString::from("hunter2".to_string());
        let formatted = format!("{p:?}");
        assert!(!formatted.contains("hunter2"));
    }

    #[test]
    fn strict_mode_skips_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let err = resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringOnly)
                .unwrap_err();
            assert!(matches!(err, ConfigError::NoCredential { .. }));
        });
    }

    #[test]
    fn permissive_mode_still_uses_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (password, source) =
                resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringThenEnv)
                    .unwrap();
            assert_eq!(password.expose_secret(), "from_env");
            assert_eq!(source, rimap_core::CredentialSource::EnvVar);
        });
    }

    #[test]
    fn keyring_hit_reports_keyring_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("work/alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) =
                resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringOnly)
                    .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::Keyring);
        });
    }

    #[test]
    fn legacy_keyring_hit_reports_legacy_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) =
                resolve_credential(&store, &id, "alice", "host", FallbackMode::KeyringOnly)
                    .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::LegacyKeyring);
        });
    }
}
