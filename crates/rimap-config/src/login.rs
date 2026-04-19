//! `login` subcommand implementation.
//!
//! Interactively prompts for a password and stores it in the keychain under
//! `(KEYCHAIN_SERVICE, <username>@<host>)`. Never reads from stdin — stdio is
//! reserved for MCP transport. Uses `rpassword::prompt_password` which opens
//! `/dev/tty` on Unix and the console on Windows.

use crate::credential::{CredentialStore, account_key, hash_account_tag};
use crate::error::ConfigError;

/// Run the `login` flow against the provided store. The caller is responsible
/// for constructing the store (a [`crate::credential::KeyringStore`] in
/// production) and for printing any user-facing success confirmation after
/// this returns — this function writes to the store and returns.
///
/// # Errors
/// Returns `ConfigError::Keychain` on store write failure, or a plain
/// `ConfigError::NoCredential` with an explanatory reason if the password
/// prompt failed (e.g. non-interactive terminal).
pub fn run_login<S: CredentialStore>(
    store: &S,
    username: &str,
    host: &str,
    prompt: impl FnOnce(&str) -> std::io::Result<String>,
) -> Result<(), ConfigError> {
    let account = account_key(username, host);
    let prompt_text = format!("Password for {account}: ");
    let password = prompt(&prompt_text).map_err(|e| ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!("interactive prompt failed: {e}"),
    })?;
    if password.is_empty() {
        return Err(ConfigError::NoCredential {
            host: host.to_string(),
            account_tag: hash_account_tag(username, host),
            reason: "empty password not accepted".to_string(),
        });
    }
    store.set_password(&account, &password)?;
    Ok(())
}

/// Default prompt function used by the binary. Wraps `rpassword`.
///
/// # Errors
/// Returns the underlying `std::io::Error` from `rpassword`.
pub fn tty_prompt(text: &str) -> std::io::Result<String> {
    rpassword::prompt_password(text)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use secrecy::{ExposeSecret, SecretString};

    use crate::credential::{CredentialStore, account_key};
    use crate::error::ConfigError;
    use crate::login::run_login;

    #[derive(Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
    }

    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
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
    fn login_writes_prompted_password_to_store() {
        let store = MockStore::default();
        run_login(&store, "alice", "host", |_| Ok("hunter2".to_string())).unwrap();
        let got = store
            .get_password(&account_key("alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), "hunter2");
    }

    #[test]
    fn empty_password_is_rejected() {
        let store = MockStore::default();
        let err = run_login(&store, "alice", "host", |_| Ok(String::new())).unwrap_err();
        assert!(matches!(err, ConfigError::NoCredential { .. }));
    }

    #[test]
    fn prompt_error_is_surfaced() {
        let store = MockStore::default();
        let err = run_login(&store, "alice", "host", |_| {
            Err(std::io::Error::other("no tty"))
        })
        .unwrap_err();
        match err {
            ConfigError::NoCredential { reason, .. } => assert!(reason.contains("no tty")),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
