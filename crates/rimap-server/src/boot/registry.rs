//! Account registry: holds per-account runtime state and resolves
//! which account a request targets.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use governor::NotUntil;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_authz::DispatchGuard;
use rimap_authz::FolderGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::{DefaultInstant, Governor, retry_after_ms};
use rimap_config::credential::CredentialStore;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_core::error::ErrorCode;
use rimap_imap::{Connection, ConnectionConfig, SpecialUseMap};
use rimap_smtp::SmtpClient;
use secrecy::ExposeSecret;

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
        if let Some(name) = explicit {
            return self
                .find_by_name(name)
                .ok_or_else(|| RimapError::UnknownAccount {
                    name: name.to_string(),
                    available: self.account_name_strings(),
                });
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
}

/// Build the account registry from a validated multi-account config.
///
/// Iterates over each configured account, constructs an IMAP `Connection`
/// and (optionally) an SMTP client, runs special-use folder discovery, and
/// assembles the per-account `AccountState`. Returns a populated
/// `AccountRegistry` ready for use by the daemon or integration-test harness.
///
/// # Errors
///
/// Returns an error if credential resolution, SMTP client construction, or
/// special-use folder discovery fails for any account.
pub async fn build(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> anyhow::Result<AccountRegistry> {
    let mut account_states = BTreeMap::new();
    let auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    for (id, acfg) in &multi.accounts {
        let guard = build_account_guard(acfg).context("building dispatch guard")?;
        let conn_cfg = build_account_connection(id, acfg);
        let resolver: Arc<dyn rimap_core::CredentialResolver> =
            Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
                credentials.clone(),
                acfg.fallback_mode,
            ));
        let imap = Connection::new(conn_cfg, auth_sink.clone(), resolver);

        let special_use = crate::boot::discovery::resolve_special_use(&imap)
            .await
            .with_context(|| {
                format!("resolving special-use folders for account {}", id.as_str())
            })?;

        // Expand the config-supplied protected-folders list with any
        // server-declared RFC 6154 names (e.g. Gmail's `[Gmail]/Sent Mail`).
        // The merge is case-insensitive so user-configured literals
        // (`"Sent"`) are not duplicated when the server also reports
        // `"Sent"` on the same mailbox.
        let mut protected = acfg.security.protected_folders.clone();
        for discovered in special_use.all_discovered() {
            if !protected
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&discovered))
            {
                protected.push(discovered);
            }
        }

        let smtp = build_smtp_client(acfg, credentials)?;

        let folder_guard = FolderGuard::new(&protected, &acfg.security.expunge_folders);

        let state = AccountState {
            id: id.clone(),
            imap,
            smtp,
            guard,
            folder_guard,
            download_dir: Arc::clone(download_dir),
            special_use,
        };
        account_states.insert(id.clone(), state);
    }
    Ok(AccountRegistry::new(account_states))
}

/// Build an SMTP client from account config, if SMTP is configured.
///
/// # Errors
///
/// Returns an error if credential resolution or SMTP client construction fails.
fn build_smtp_client(
    acfg: &ValidatedAccountConfig,
    credentials: &Arc<dyn CredentialStore>,
) -> anyhow::Result<Option<SmtpClient>> {
    let Some(ref smtp_cfg) = acfg.smtp else {
        return Ok(None);
    };
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        acfg.fallback_mode,
    )
    .with_context(|| format!("resolving SMTP credential for account {}", acfg.id.as_str()))?;
    let client = SmtpClient::new(smtp_cfg, smtp_password.expose_secret())
        .with_context(|| format!("building SMTP client for account {}", acfg.id.as_str()))?;
    drop(smtp_password);
    Ok(Some(client))
}

/// Build the composed authz guard from a per-account config.
fn build_account_guard(
    acfg: &ValidatedAccountConfig,
) -> anyhow::Result<DispatchGuard<SystemClock>> {
    let matrix = EffectiveMatrix::build(acfg.security.posture, &acfg.tool_overrides);
    let breaker_cfg = BreakerConfig {
        error_threshold: acfg.limits.circuit_breaker_error_threshold,
        window: Duration::from_secs(u64::from(acfg.limits.circuit_breaker_window_seconds)),
        ..BreakerConfig::default_spec()
    };
    let breaker = CircuitBreaker::new(SystemClock::new(), breaker_cfg);
    let governor = Governor::new(
        acfg.limits.commands_per_second,
        acfg.limits.drafts_per_minute,
        acfg.limits.sends_per_minute,
    )
    .map_err(|e| anyhow::anyhow!("governor: {e}"))?;
    Ok(DispatchGuard::new(matrix, breaker, governor))
}

/// Map a per-account config to a `ConnectionConfig`.
fn build_account_connection(
    id: &rimap_core::account::AccountId,
    acfg: &ValidatedAccountConfig,
) -> ConnectionConfig {
    let account = if id.as_str() == rimap_core::account::DEFAULT_ACCOUNT_NAME {
        None
    } else {
        Some(id.as_str().to_string())
    };
    ConnectionConfig {
        account,
        account_id: id.clone(),
        host: acfg.imap.host.clone(),
        port: acfg.imap.port,
        encryption: match acfg.imap.encryption {
            rimap_config::model::ImapEncryption::Tls => rimap_imap::ImapEncryption::Tls,
            rimap_config::model::ImapEncryption::Starttls => rimap_imap::ImapEncryption::Starttls,
        },
        username: acfg.imap.username.clone(),
        pinned_fingerprint: acfg.tls_fingerprint,
        connect_timeout: Duration::from_secs(u64::from(acfg.imap.connect_timeout_seconds)),
        command_timeout: Duration::from_secs(u64::from(acfg.imap.command_timeout_seconds)),
        max_fetch_body_bytes: acfg.limits.max_fetch_body_bytes,
        max_append_bytes: acfg.limits.max_append_bytes,
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
