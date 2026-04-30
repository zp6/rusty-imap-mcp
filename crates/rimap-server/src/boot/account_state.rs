//! Per-account runtime state and the registry that resolves which
//! account a request targets.
//!
//! Lifted out of [`crate::boot::registry`] so the data contract used by
//! every tool handler does not share a file with the boot-time builder
//! pipeline. The split shrinks the recompile blast radius when the
//! builder changes and surfaces the register-vs-runtime separation in
//! the module tree.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{NotUntil, Quota, RateLimiter};
use rimap_authz::DispatchGuard;
use rimap_authz::FolderGuard;
use rimap_authz::breaker::SystemClock;
use rimap_authz::rate_limit::{DefaultInstant, retry_after_ms};
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_core::error::ErrorCode;
use rimap_imap::{Connection, SpecialUseMap};
use rimap_smtp::SmtpClient;

/// In-memory, unkeyed governor limiter used for infrastructure tools.
type InfrastructureLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Translate a `governor` rejection into [`RimapError::Authz`] with a
/// rate-limited error code and a human-readable retry hint. The
/// underlying ms math is shared with the per-account governor via
/// [`retry_after_ms`]; this wrapper adds the infrastructure-tool
/// framing and skips the intermediate `AuthzError`.
fn infra_rate_limited(not_until: &NotUntil<DefaultInstant>, clock: &DefaultClock) -> RimapError {
    let wait_ms = retry_after_ms(not_until, clock);
    RimapError::Authz {
        code: ErrorCode::RateLimited,
        message: format!("infrastructure tool rate limit exceeded; retry in {wait_ms}ms"),
    }
}

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
    /// RFC 6154 special-use folder name resolutions, populated at boot
    /// from one `LIST` call. Consulted by `create_draft`, `send_email`,
    /// and expanded into `folder_guard`'s protected list.
    pub special_use: SpecialUseMap,
}

impl std::fmt::Debug for AccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountState")
            .field("id", &self.id)
            .field("smtp", &self.smtp.is_some())
            .field("special_use_drafts", &self.special_use.drafts())
            .field("special_use_sent", &self.special_use.sent())
            .field("special_use_trash", &self.special_use.trash())
            .finish_non_exhaustive()
    }
}

/// Holds all configured accounts and resolves which account a request targets.
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    /// Process-wide rate limiter for infrastructure tools
    /// (`use_account`, `list_accounts`). Prevents an injected prompt
    /// from flip-flopping the active account faster than a human
    /// would. 5 req/sec sustained, burst of 10.
    infrastructure_limiter: InfrastructureLimiter,
    /// Clock used by the infrastructure limiter; stored so that
    /// `wait_time_from` can format retry hints.
    clock: DefaultClock,
    /// Lazily-populated `tools/list` result. Built once per
    /// `AccountRegistry` instance from the registered accounts'
    /// posture matrices and the static tool catalog; the rmcp
    /// `ListToolsResult` API requires `Vec<Tool>` by value, so callers
    /// clone the inner vec at the boundary, but the per-tool
    /// `format!` and `Tool::clone` work happens once. See #148.
    list_tools_cache: std::sync::OnceLock<Arc<Vec<rmcp::model::Tool>>>,
}

impl AccountRegistry {
    /// Build a registry from the given accounts.
    #[must_use]
    pub fn new(accounts: BTreeMap<AccountId, AccountState>) -> Self {
        let quota = Quota::per_second(INFRA_RATE_PER_SEC).allow_burst(INFRA_BURST);
        Self {
            accounts,
            infrastructure_limiter: RateLimiter::direct(quota),
            clock: DefaultClock::default(),
            list_tools_cache: std::sync::OnceLock::new(),
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
        self.infrastructure_limiter
            .check()
            .map_err(|not_until| infra_rate_limited(&not_until, &self.clock))
    }

    /// Resolve which account a request targets.
    ///
    /// Resolution order:
    /// 1. Explicit name passed by the caller.
    /// 2. Auto-select when exactly one account is configured.
    /// 3. Error listing available accounts.
    ///
    /// For session-aware resolution (where a `use_account` call has
    /// set a per-session default), use [`resolve_with_active`][Self::resolve_with_active]
    /// instead, passing the active account from `SessionState`.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if the explicit name
    /// does not match any configured account, or
    /// [`RimapError::NoAccount`] if no account can be determined.
    pub fn resolve(&self, explicit: Option<&str>) -> Result<&AccountState, RimapError> {
        self.resolve_with_active(explicit, None)
    }

    /// Resolve which account a request targets, using a caller-supplied
    /// session default (from [`crate::daemon::state::SessionState::active_account`]).
    ///
    /// Resolution order:
    /// 1. Explicit name — same as [`resolve`][Self::resolve].
    /// 2. Caller-supplied session default (from `SessionState`).
    /// 3. Auto-select when exactly one account is configured.
    /// 4. Error listing available accounts.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if the explicit name
    /// does not match any configured account, or
    /// [`RimapError::NoAccount`] if no account can be determined.
    pub fn resolve_with_active(
        &self,
        explicit: Option<&str>,
        session_default: Option<&AccountId>,
    ) -> Result<&AccountState, RimapError> {
        if let Some(name) = explicit {
            return self
                .find_by_name(name)
                .ok_or_else(|| RimapError::UnknownAccount {
                    name: name.to_string(),
                    available: self.account_name_strings(),
                });
        }

        // Check session-scoped active account from SessionState.
        if let Some(state) = session_default.and_then(|id| self.accounts.get(id)) {
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

    /// Return the cached `tools/list` result. Populated lazily on first
    /// call from the registered accounts' posture matrices and the
    /// static tool catalog; subsequent calls return the same `Arc<Vec>`.
    ///
    /// The `Arc` clone is `O(1)`. The rmcp `ListToolsResult` API takes
    /// `Vec<Tool>` by value, so the call site clones the inner Vec at
    /// the rmcp boundary — but the per-tool `format!` /
    /// `Tool::clone` work no longer runs per request. See #148.
    #[must_use]
    pub fn list_tools_cached(&self) -> Arc<Vec<rmcp::model::Tool>> {
        Arc::clone(
            self.list_tools_cache
                .get_or_init(|| Arc::new(self.compute_advertised_tools())),
        )
    }

    /// Build the advertised tool list from registered accounts. Mirrors
    /// the dispatch logic that previously lived inside
    /// `ServerHandler::list_tools`; centralized here so the cache
    /// builds it once.
    fn compute_advertised_tools(&self) -> Vec<rmcp::model::Tool> {
        use crate::mcp::tool_catalog::TOOL_DEFS;
        use crate::mcp::tool_name::is_legacy_single_account;

        let mut tools: Vec<rmcp::model::Tool> = Vec::new();

        // Infrastructure tools — always advertised, never namespaced.
        for name in [
            rimap_core::tool::ToolName::UseAccount,
            rimap_core::tool::ToolName::ListAccounts,
        ] {
            if let Some(def) = TOOL_DEFS.get(&name) {
                tools.push(def.clone());
            }
        }

        let use_bare_names = is_legacy_single_account(&self.accounts);

        for (id, state) in &self.accounts {
            for &tn in &state.guard.matrix().advertised() {
                let Some(base_def) = TOOL_DEFS.get(&tn) else {
                    continue;
                };
                let tool_name = if use_bare_names {
                    base_def.name.clone()
                } else {
                    format!("{}.{}", id.as_str(), base_def.name).into()
                };
                let description = if use_bare_names {
                    base_def.description.clone()
                } else {
                    Some(
                        format!(
                            "[account: {}, posture: {}] {}",
                            id.as_str(),
                            state.guard.matrix().posture().as_str(),
                            base_def.description.as_deref().unwrap_or(""),
                        )
                        .into(),
                    )
                };
                let mut def = base_def.clone();
                def.name = tool_name;
                def.description = description;
                tools.push(def);
            }
        }

        tools
    }
}

#[cfg(test)]
mod list_tools_cache_tests {
    use super::AccountRegistry;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn list_tools_cached_returns_same_arc_across_calls() {
        // Pin the cache contract: list_tools_cached returns the same
        // Arc<Vec<Tool>> on every call within a registry generation.
        // If a future refactor reverts to "build fresh on every call",
        // this assertion catches the regression — Arc::ptr_eq checks
        // identity, not equality.
        let reg = AccountRegistry::new(BTreeMap::new());
        let a = reg.list_tools_cached();
        let b = reg.list_tools_cached();
        assert!(
            Arc::ptr_eq(&a, &b),
            "list_tools_cached must return the same Arc on repeat calls",
        );
    }

    #[test]
    fn list_tools_cached_includes_use_account_and_list_accounts_for_empty_registry() {
        // Empty registry still advertises the two infrastructure tools
        // (use_account, list_accounts). The cached Vec should contain
        // both, and only those, when no accounts are configured.
        let reg = AccountRegistry::new(BTreeMap::new());
        let tools = reg.list_tools_cached();
        let names: std::collections::BTreeSet<_> =
            tools.iter().map(|t| t.name.to_string()).collect();
        assert!(names.contains("use_account"), "tools = {names:?}");
        assert!(names.contains("list_accounts"), "tools = {names:?}");
        assert_eq!(
            tools.len(),
            2,
            "empty registry should advertise exactly 2 tools, got {tools:?}",
        );
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
    fn account_name_strings_empty() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.account_name_strings().is_empty());
    }

    #[test]
    fn accounts_returns_map() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.accounts().is_empty());
    }
}
