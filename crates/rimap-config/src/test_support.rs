//! Test fixtures for `rimap-config`. Gated behind the `test-support`
//! feature so they ship in dev-dependencies of downstream crates without
//! widening the production surface.
//!
//! Internal `#[cfg(test)]` callers (this crate's own unit tests) reach
//! the same module via the `cfg(any(feature = "test-support", test))`
//! gate on `lib.rs`, so they don't need to enable the feature.

#![expect(
    clippy::expect_used,
    reason = "test fixtures: a poisoned mutex inside a unit test means another test panicked, and the right behavior is to propagate"
)]

use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::SecretString;

use crate::credential::CredentialStore;
use crate::error::ConfigError;

/// In-memory [`CredentialStore`] for unit tests. Supports a configurable
/// "fail every `get_password`" mode so callers can exercise the
/// keychain-failure error path without a real keychain.
///
/// Construct with [`MockStore::default`] for an empty store, or
/// [`MockStore::with`] to seed entries, or [`MockStore::failing`] to
/// have every `get_password` return [`ConfigError::Keychain`].
#[derive(Default)]
pub struct MockStore {
    entries: Mutex<HashMap<String, String>>,
    fail_on_get: bool,
}

impl MockStore {
    /// Build a store pre-populated with the given `(account_key, password)` pairs.
    #[must_use]
    pub fn with(pairs: &[(&str, &str)]) -> Self {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_string(), (*v).to_string());
        }
        Self {
            entries: Mutex::new(map),
            fail_on_get: false,
        }
    }

    /// Build a store whose every [`CredentialStore::get_password`] call returns
    /// [`ConfigError::Keychain`]. Use to exercise keychain-failure paths.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            fail_on_get: true,
        }
    }
}

impl CredentialStore for MockStore {
    fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
        if self.fail_on_get {
            let (host, account_tag) = crate::credential::split_account_for_error(account);
            return Err(ConfigError::Keychain {
                host,
                account_tag,
                source: "simulated failure".into(),
            });
        }
        Ok(self
            .entries
            .lock()
            .expect("MockStore mutex poisoned")
            .get(account)
            .cloned()
            .map(SecretString::from))
    }

    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
        self.entries
            .lock()
            .expect("MockStore mutex poisoned")
            .insert(account.to_string(), password.to_string());
        Ok(())
    }
}
