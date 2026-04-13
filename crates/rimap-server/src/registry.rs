//! Account registry: holds per-account runtime state and resolves
//! which account a request targets.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rimap_authz::breaker::SystemClock;
use rimap_authz::{DispatchGuard, FolderGuard};
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_imap::Connection;
use rimap_smtp::SmtpClient;

/// Per-account runtime bundle.
///
/// Manual `Debug` impl prints only the account id, since several
/// inner types do not implement `Debug`.
pub struct AccountState {
    /// Validated account identifier.
    pub id: AccountId,
    /// Email address used as the From header (typically the IMAP username).
    pub from_address: String,
    /// IMAP connection for this account.
    pub imap: Connection,
    /// Optional SMTP client (present when sending is configured).
    pub smtp: Option<SmtpClient>,
    /// Rate-limit and circuit-breaker guard.
    pub guard: DispatchGuard<SystemClock>,
    /// Folder-level access guard.
    pub folder_guard: FolderGuard,
}

impl std::fmt::Debug for AccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountState")
            .field("id", &self.id)
            .field("smtp", &self.smtp.is_some())
            .finish_non_exhaustive()
    }
}

/// Holds all configured accounts and the session-scoped active
/// account selection.
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    active: Mutex<Option<AccountId>>,
}

impl AccountRegistry {
    /// Build a registry from the given accounts.
    #[must_use]
    pub fn new(accounts: BTreeMap<AccountId, AccountState>) -> Self {
        Self {
            accounts,
            active: Mutex::new(None),
        }
    }

    /// Resolve which account a request targets.
    ///
    /// Resolution order:
    /// 1. Explicit name passed by the caller.
    /// 2. Session-scoped active account (set via `use_account`).
    /// 3. Auto-select when exactly one account is configured.
    /// 4. Error listing available accounts.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if the explicit name
    /// does not match any configured account, or
    /// [`RimapError::NoAccount`] if no account can be determined.
    pub fn resolve(&self, explicit: Option<&str>) -> Result<&AccountState, RimapError> {
        let names = || {
            self.accounts
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        };

        if let Some(name) = explicit {
            return self
                .find_by_name(name)
                .ok_or_else(|| RimapError::UnknownAccount {
                    name: name.to_string(),
                    available: names(),
                });
        }

        // Check session-scoped active account.
        let lock = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = lock.as_ref().and_then(|id| self.accounts.get(id)) {
            return Ok(state);
        }
        drop(lock);

        // Auto-select when there is exactly one account.
        if let Some((_, state)) = (self.accounts.len() == 1)
            .then(|| self.accounts.iter().next())
            .flatten()
        {
            return Ok(state);
        }

        Err(RimapError::NoAccount { available: names() })
    }

    /// Set the session-scoped active account, returning the previous
    /// account name (if any).
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if `name` does not
    /// match any configured account.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by use_account handler in T6")
    )]
    pub fn set_active(&self, name: &str) -> Result<Option<String>, RimapError> {
        let id = self
            .accounts
            .keys()
            .find(|k| k.as_str() == name)
            .ok_or_else(|| RimapError::UnknownAccount {
                name: name.to_string(),
                available: self.accounts.keys().map(ToString::to_string).collect(),
            })?
            .clone();

        let mut lock = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = lock.as_ref().map(ToString::to_string);
        *lock = Some(id);
        Ok(prev)
    }

    /// List all configured account names in sorted order.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by list_accounts handler in T6")
    )]
    pub fn account_names(&self) -> Vec<&AccountId> {
        self.accounts.keys().collect()
    }

    /// Borrow the full accounts map.
    #[must_use]
    pub fn accounts(&self) -> &BTreeMap<AccountId, AccountState> {
        &self.accounts
    }

    /// Look up an account by its string name.
    fn find_by_name(&self, name: &str) -> Option<&AccountState> {
        self.accounts
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, v)| v)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use unwrap_err for assertions")]
mod tests {
    use super::*;

    // We test resolution logic through the public API using an empty
    // registry. Constructing `AccountState` requires real IMAP
    // connections, so full-path tests live in integration/e2e suites.

    #[test]
    fn empty_registry_returns_no_account() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.resolve(None).unwrap_err();
        assert!(matches!(err, RimapError::NoAccount { available } if available.is_empty()));
    }

    #[test]
    fn explicit_unknown_returns_unknown_account() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.resolve(Some("work")).unwrap_err();
        assert!(matches!(err, RimapError::UnknownAccount { name, .. } if name == "work"));
    }

    #[test]
    fn set_active_unknown_returns_error() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.set_active("nope").unwrap_err();
        assert!(matches!(err, RimapError::UnknownAccount { name, .. } if name == "nope"));
    }

    #[test]
    fn account_names_empty() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.account_names().is_empty());
    }

    #[test]
    fn accounts_returns_map() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.accounts().is_empty());
    }
}
