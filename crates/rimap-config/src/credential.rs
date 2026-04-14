//! Credential resolution.
//!
//! Order of precedence (design spec §4):
//!   1. OS keychain (service = `rusty-imap-mcp`, account = `<username>@<host>`).
//!   2. Environment variable `RUSTY_IMAP_MCP_PASSWORD`.
//!   3. Clear, actionable error naming both.

use secrecy::{ExposeSecret, SecretString};

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

/// Build the `<username>@<host>` account key used for keychain lookups.
#[must_use]
pub fn account_key(username: &str, host: &str) -> String {
    format!("{username}@{host}")
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
    username: &str,
    host: &str,
) -> Result<SecretString, ConfigError> {
    let account = account_key(username, host);
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
        account,
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
        let entry =
            keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            })?;
        match entry.get_password() {
            Ok(p) => Ok(Some(SecretString::from(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            }),
        }
    }

    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
        let entry =
            keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            })?;
        entry
            .set_password(password)
            .map_err(|e| ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
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

    use crate::credential::{CredentialStore, PASSWORD_ENV_VAR, account_key, resolve_credential};
    use crate::error::ConfigError;

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
                return Err(ConfigError::Keychain {
                    account: account.to_string(),
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
    fn account_key_is_username_at_host() {
        assert_eq!(
            account_key("alice", "mail.example.test"),
            "alice@mail.example.test"
        );
    }

    #[test]
    fn keychain_hit_wins_over_env() {
        let store = MockStore::with(&[("alice@host", "from_keychain")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_keychain");
        });
    }

    #[test]
    fn env_used_when_keychain_empty() {
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_env");
        });
    }

    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(&store, "alice", "host").unwrap_err();
            match err {
                ConfigError::NoCredential { account, reason } => {
                    assert_eq!(account, "alice@host");
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
        temp_env::with_var(PASSWORD_ENV_VAR, Some("unused"), || {
            let err = resolve_credential(&store, "alice", "host").unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn empty_keychain_value_falls_through_to_env() {
        let store = MockStore::with(&[("alice@host", "")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            assert_eq!(
                resolve_credential(&store, "alice", "host")
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
