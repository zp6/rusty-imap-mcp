//! Credential resolution.
//!
//! Order of precedence (design spec §4):
//!   1. OS keychain (service = `rusty-imap-mcp`, account = `<username>@<host>`).
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
/// Returns the **legacy** `<username>@<host>` form for compatibility with
/// stored credentials. Task 3 introduces the new `<account-id>/<username>@<host>`
/// form and a back-compat read path.
#[must_use]
pub fn account_key(_account_id: &AccountId, username: &str, host: &str) -> String {
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

/// Resolve a credential: try the store first, then env var, then fail.
///
/// Accepts `&dyn CredentialStore` so callers that hold an
/// `Arc<dyn CredentialStore>` can pass `&*arc` without a generic bound.
/// Concrete references (e.g. `&KeyringStore`) coerce to `&dyn CredentialStore`
/// automatically, so existing callers are unaffected.
///
/// # Errors
/// - `ConfigError::Keychain` if the store itself errored.
/// - `ConfigError::NoCredential` if neither source had a value.
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
) -> Result<SecretString, ConfigError> {
    let account = account_key(account_id, username, host);
    if let Some(p) = store.get_password(&account)?
        && !p.expose_secret().is_empty()
    {
        return Ok(p);
    }
    if let Ok(env) = std::env::var(PASSWORD_ENV_VAR)
        && !env.is_empty()
    {
        return Ok(SecretString::from(env));
    }
    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` and \
             `{PASSWORD_ENV_VAR}` is unset or empty; run `rusty-imap-mcp login` \
             or set the environment variable"
        ),
    })
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
    fn account_key_signature_accepts_account_id() {
        let id = AccountId::default_account();
        // Old format still returned in this task; task 3 changes to
        // "<id>/<user>@<host>".
        let key = account_key(&id, "alice", "mail.example.test");
        assert_eq!(key, "alice@mail.example.test");
    }

    #[test]
    fn keychain_hit_wins_over_env() {
        let store = MockStore::with(&[("alice@host", "from_keychain")]);
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, &default_id, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_keychain");
        });
    }

    #[test]
    fn env_used_when_keychain_empty() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, &default_id, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_env");
        });
    }

    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(&store, &default_id, "alice", "host").unwrap_err();
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
            let err = resolve_credential(&store, &default_id, "alice", "host").unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn empty_keychain_value_falls_through_to_env() {
        let store = MockStore::with(&[("alice@host", "")]);
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            assert_eq!(
                resolve_credential(&store, &default_id, "alice", "host")
                    .unwrap()
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
}
