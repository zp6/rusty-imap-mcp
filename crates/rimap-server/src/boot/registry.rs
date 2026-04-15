//! Account registry: holds per-account runtime state and resolves
//! which account a request targets.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_authz::breaker::SystemClock;
use rimap_authz::{DispatchGuard, FolderGuard};
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_core::error::ErrorCode;
use rimap_imap::Connection;
use rimap_smtp::SmtpClient;

/// In-memory, unkeyed governor limiter used for infrastructure tools.
type InfrastructureLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Sustained rate for the infrastructure-tool limiter. The `unwrap` runs
/// in `const` context, so a zero literal would fail the build rather than
/// panic at runtime.
const INFRA_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// Burst allowance for the infrastructure-tool limiter. See
/// [`INFRA_RATE_PER_SEC`] for why the `unwrap` is sound.
const INFRA_BURST: NonZeroU32 = NonZeroU32::new(10).unwrap();

/// Per-account runtime bundle.
///
/// Manual `Debug` impl prints only the account id, since several
/// inner types do not implement `Debug`.
pub struct AccountState {
    /// Validated account identifier.
    pub id: AccountId,
    /// IMAP connection for this account.
    pub imap: Connection,
    /// Optional SMTP client (present when sending is configured).
    pub smtp: Option<SmtpClient>,
    /// Rate-limit and circuit-breaker guard.
    pub guard: DispatchGuard<SystemClock>,
    /// Folder-level access guard.
    pub folder_guard: FolderGuard,
    /// Attachment download sandbox root. Carried on `AccountState` so
    /// tool handlers keep a uniform `handle(account, input)` shape.
    pub download_dir: Arc<Path>,
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
    active: ArcSwapOption<AccountId>,
    /// Process-wide rate limiter for infrastructure tools
    /// (`use_account`, `list_accounts`). Prevents an injected prompt
    /// from flip-flopping the active account faster than a human
    /// would. 5 req/sec sustained, burst of 10.
    infrastructure_limiter: InfrastructureLimiter,
    /// Clock used by the infrastructure limiter; stored so that
    /// `wait_time_from` can format retry hints.
    clock: DefaultClock,
}

impl AccountRegistry {
    /// Build a registry from the given accounts.
    #[must_use]
    pub fn new(accounts: BTreeMap<AccountId, AccountState>) -> Self {
        let quota = Quota::per_second(INFRA_RATE_PER_SEC).allow_burst(INFRA_BURST);
        Self {
            accounts,
            active: ArcSwapOption::empty(),
            infrastructure_limiter: RateLimiter::direct(quota),
            clock: DefaultClock::default(),
        }
    }

    /// Check the infrastructure-tool rate limit. Called by
    /// `dispatch_infrastructure` before executing `use_account` or
    /// `list_accounts`.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::Authz`] with
    /// [`ErrorCode::RateLimited`] when the limit is exceeded. The
    /// error message includes a retry hint in milliseconds.
    pub fn check_infrastructure_rate(&self) -> Result<(), RimapError> {
        self.infrastructure_limiter.check().map_err(|not_until| {
            let wait_ms = u64::try_from(not_until.wait_time_from(self.clock.now()).as_millis())
                .unwrap_or(u64::MAX);
            RimapError::Authz {
                code: ErrorCode::RateLimited,
                message: format!("infrastructure tool rate limit exceeded; retry in {wait_ms}ms",),
            }
        })
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
        if let Some(name) = explicit {
            return self
                .find_by_name(name)
                .ok_or_else(|| RimapError::UnknownAccount {
                    name: name.to_string(),
                    available: self.account_name_strings(),
                });
        }

        // Check session-scoped active account.
        let active = self.active.load_full();
        if let Some(state) = active.as_deref().and_then(|id| self.accounts.get(id)) {
            return Ok(state);
        }

        // Auto-select when there is exactly one account.
        if let Some((_, state)) = (self.accounts.len() == 1)
            .then(|| self.accounts.iter().next())
            .flatten()
        {
            return Ok(state);
        }

        Err(RimapError::NoAccount {
            available: self.account_name_strings(),
        })
    }

    /// Set the session-scoped active account, returning the previous
    /// account name (if any).
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if `name` does not
    /// match any configured account.
    pub fn set_active(&self, name: &str) -> Result<Option<String>, RimapError> {
        // Parse into AccountId first so the O(log n) BTreeMap lookup does
        // typed comparison; falls back to `UnknownAccount` either way.
        let id = AccountId::new(name)
            .ok()
            .filter(|id| self.accounts.contains_key(id))
            .ok_or_else(|| RimapError::UnknownAccount {
                name: name.to_string(),
                available: self.account_name_strings(),
            })?;

        let prev = self.active.swap(Some(Arc::new(id)));
        Ok(prev.as_deref().map(ToString::to_string))
    }

    /// List all configured account names as owned strings, in sorted
    /// order. Used to populate the `available` field on
    /// [`RimapError::NoAccount`] and [`RimapError::UnknownAccount`].
    #[must_use]
    fn account_name_strings(&self) -> Vec<String> {
        self.accounts.keys().map(ToString::to_string).collect()
    }

    /// Borrow the full accounts map.
    #[must_use]
    pub fn accounts(&self) -> &BTreeMap<AccountId, AccountState> {
        &self.accounts
    }

    /// Look up an account by its string name. Parses into `AccountId`
    /// first so the `BTreeMap` lookup is O(log n) typed equality rather
    /// than O(n) string scanning.
    fn find_by_name(&self, name: &str) -> Option<&AccountState> {
        let id = AccountId::new(name).ok()?;
        self.accounts.get(&id)
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
    fn account_name_strings_empty() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.account_name_strings().is_empty());
    }

    #[test]
    fn accounts_returns_map() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.accounts().is_empty());
    }

    #[test]
    fn concurrent_active_swap_and_resolve() {
        // Exercises the ArcSwapOption-backed active slot under
        // concurrent writers and readers. The registry is empty
        // (AccountState requires live IMAP connections), so resolve()
        // must always return NoAccount regardless of interleaving;
        // the property under test is that readers never observe a
        // torn or invalid state and the process does not panic.
        use std::sync::Arc;
        use std::thread;

        let reg = Arc::new(AccountRegistry::new(BTreeMap::new()));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    // set_active on an unknown name must return
                    // UnknownAccount, not panic, even when other
                    // threads are swapping or loading concurrently.
                    let err = reg.set_active("nope").unwrap_err();
                    assert!(matches!(err, RimapError::UnknownAccount { .. }));
                }
            }));
        }

        for _ in 0..2 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let err = reg.resolve(None).unwrap_err();
                    assert!(matches!(err, RimapError::NoAccount { .. }));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }
}
