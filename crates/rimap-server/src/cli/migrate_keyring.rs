//! `rusty-imap-mcp migrate-keyring` subcommand.
//!
//! Migrates a single credential from the legacy key `<username>@<host>` to
//! the new `<account-id>/<username>@<host>` key format (see #77).

use rimap_config::credential::{
    CredentialStore, account_key, hash_account_tag, legacy_account_key,
};
use rimap_config::error::ConfigError;
use rimap_core::account::AccountId;
use secrecy::ExposeSecret;

/// Migrate one credential. Returns `Ok(true)` if migration happened,
/// `Ok(false)` if the legacy key was absent (nothing to migrate).
///
/// # Errors
/// `ConfigError::NoCredential` or `ConfigError::Keychain` on I/O errors.
///
/// # Operator-visible side effect
///
/// The legacy entry is emptied via `set_password("")`, not deleted. Operators
/// auditing the keyring (e.g. `secret-tool search`, macOS Keychain Access)
/// will still see the legacy account entry with an empty secret until they
/// clear it manually. `CredentialStore` has no delete method; adding one is
/// tracked for a future refactor.
pub(crate) fn migrate_one<S: CredentialStore>(
    store: &S,
    account_id: &AccountId,
    username: &str,
    host: &str,
) -> Result<bool, ConfigError> {
    let legacy = legacy_account_key(username, host);
    let Some(password) = store.get_password(&legacy)? else {
        return Ok(false);
    };
    let new_key = account_key(account_id, username, host);
    store.set_password(&new_key, password.expose_secret())?;
    // Overwrite the legacy entry with an empty value so subsequent
    // `resolve_credential` calls no longer find it. CredentialStore has no
    // delete method; an empty string is treated as "no credential" by the
    // `!p.expose_secret().is_empty()` guard in resolve_credential.
    store.set_password(&legacy, "")?;
    tracing::info!(
        account_id = %account_id.as_str(),
        host = %host,
        account_tag = %hash_account_tag(username, host),
        "migrated keyring entry from legacy key",
    );
    Ok(true)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_config::credential::{CredentialStore, account_key, legacy_account_key};
    use rimap_config::test_support::MockStore;
    use rimap_core::account::AccountId;
    use secrecy::ExposeSecret;

    use super::migrate_one;

    #[test]
    fn migrate_copies_legacy_to_new_and_empties_legacy() {
        let store = MockStore::default();
        let id = AccountId::new("work").unwrap();
        store
            .set_password(&legacy_account_key("alice", "host"), "hunter2")
            .unwrap();

        let migrated = migrate_one(&store, &id, "alice", "host").unwrap();
        assert!(migrated);

        let new = store
            .get_password(&account_key(&id, "alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(new.expose_secret(), "hunter2");

        let legacy = store
            .get_password(&legacy_account_key("alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(legacy.expose_secret(), "", "legacy entry should be empty");
    }

    #[test]
    fn migrate_returns_false_when_no_legacy_entry() {
        let store = MockStore::default();
        let id = AccountId::new("work").unwrap();
        let migrated = migrate_one(&store, &id, "alice", "host").unwrap();
        assert!(!migrated);
    }

    #[test]
    fn migrate_overwrites_preexisting_new_key_entry() {
        // Pins current behavior: if both legacy and new-key entries exist,
        // the legacy value wins and clobbers the new-key entry. Acceptable
        // for the migration-once-per-upgrade workflow, but operators who
        // manually `login --account <id>` BEFORE migrating will lose the
        // new password. Task 4 review flagged this as a deliberate YAGNI;
        // a future MigrationOutcome::AlreadyMigrated variant can refine it.
        let store = MockStore::default();
        let id = AccountId::new("work").unwrap();
        store
            .set_password(&account_key(&id, "alice", "host"), "preexisting")
            .unwrap();
        store
            .set_password(&legacy_account_key("alice", "host"), "from_legacy")
            .unwrap();

        let migrated = migrate_one(&store, &id, "alice", "host").unwrap();
        assert!(migrated);

        let new = store
            .get_password(&account_key(&id, "alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(new.expose_secret(), "from_legacy");
    }
}
