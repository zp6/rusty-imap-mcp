//! Boot-time account registry build pipeline.
//!
//! The runtime data types — [`AccountState`] and [`AccountRegistry`] —
//! live in [`crate::boot::account_state`]. This module contains only
//! the builder that materialises them from a validated multi-account
//! config: IMAP/SMTP setup, special-use discovery, dispatch-guard
//! assembly. Tool handlers depend on `account_state`, not this module.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rimap_authz::DispatchGuard;
use rimap_authz::FolderGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::{Governor, RateConfig};
use rimap_config::credential::CredentialStore;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::account::AccountId;
use rimap_imap::{Connection, ConnectionConfig};
use rimap_smtp::SmtpClient;
use secrecy::ExposeSecret;

pub use crate::boot::account_state::{AccountRegistry, AccountState};

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
    use futures_util::stream::{self, StreamExt as _, TryStreamExt as _};

    /// Cap the number of in-flight per-account setups. The work per
    /// account is one IMAP `LIST` round trip; `4` is a conservative
    /// bound that gives parallelism speedup for typical 1–5-account
    /// configs without flooding the system with sockets when an
    /// operator deploys with 50 accounts. Tuning beyond this is a
    /// separate concern (see #128 IMAP connection pool depth).
    const PARALLEL_BUILD_CONCURRENCY: usize = 4;

    let auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());

    // Build per-account `(AccountId, AccountState)` futures. Each future
    // owns a clone of `auth_sink`, `credentials`, and `download_dir`,
    // and borrows nothing from `multi` so that the buffer can hold
    // them as `Send + 'static`.
    let account_iter = multi.accounts.iter().map(|(id, acfg)| {
        let id = id.clone();
        let acfg = acfg.clone();
        let auth_sink = Arc::clone(&auth_sink);
        let credentials = Arc::clone(credentials);
        let download_dir = Arc::clone(download_dir);
        async move { build_one_account(id, acfg, auth_sink, credentials, download_dir).await }
    });

    let states: Vec<(AccountId, AccountState)> = stream::iter(account_iter)
        .buffer_unordered(PARALLEL_BUILD_CONCURRENCY)
        .try_collect()
        .await?;

    let account_states: BTreeMap<AccountId, AccountState> = states.into_iter().collect();
    Ok(AccountRegistry::new(account_states))
}

/// Single-account setup: build the dispatch guard, IMAP connection, run
/// special-use discovery, and assemble the `AccountState`.
///
/// Owns the `Arc`s passed in so the resulting future is `Send + 'static`
/// for `buffer_unordered` consumption.
async fn build_one_account(
    id: AccountId,
    acfg: ValidatedAccountConfig,
    auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink>,
    credentials: Arc<dyn CredentialStore>,
    download_dir: Arc<std::path::Path>,
) -> anyhow::Result<(AccountId, AccountState)> {
    let guard = build_account_guard(&acfg).context("building dispatch guard")?;
    let conn_cfg = build_account_connection(&id, &acfg);
    let resolver: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            Arc::clone(&credentials),
            acfg.fallback_mode,
        ));
    let imap = Connection::new(conn_cfg, auth_sink, resolver);

    let special_use = crate::boot::discovery::resolve_special_use(&imap)
        .await
        .with_context(|| format!("resolving special-use folders for account {}", id.as_str()))?;

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

    let smtp = build_smtp_client(&acfg, &credentials)?;

    let folder_guard = FolderGuard::new(&protected, &acfg.security.expunge_folders);

    let state = AccountState {
        id: id.clone(),
        imap,
        smtp,
        guard,
        folder_guard,
        download_dir,
        special_use,
    };
    Ok((id, state))
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
    let governor = Governor::new(&RateConfig {
        commands_per_second: acfg.limits.commands_per_second,
        drafts_per_minute: acfg.limits.drafts_per_minute,
        sends_per_minute: acfg.limits.sends_per_minute,
    })
    .map_err(|e| anyhow::anyhow!("governor: {e}"))?;
    Ok(DispatchGuard::new(matrix, breaker, governor))
}

/// Map a per-account config to a `ConnectionConfig`.
#[must_use]
pub fn build_account_connection(
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

