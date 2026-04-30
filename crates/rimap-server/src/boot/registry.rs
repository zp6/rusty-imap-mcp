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

use rimap_authz::DispatchGuard;
use rimap_authz::FolderGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::{Governor, RateConfig};
use rimap_config::credential::CredentialStore;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::ErrorCode;
use rimap_core::account::AccountId;
use rimap_imap::{Connection, ConnectionConfig};
use rimap_smtp::SmtpClient;
use secrecy::ExposeSecret;
use thiserror::Error;

pub use crate::boot::account_state::{AccountRegistry, AccountState};

/// Errors produced by the boot-time account-registry pipeline.
///
/// Every variant carries a stable [`ErrorCode`] so the boot/runtime seam
/// preserves classification — credential / SMTP / governor / discovery
/// failures stay distinguishable up to the call site that converts them
/// into operator output. Source enums are boxed so this fits clippy's
/// `result_large_err` budget for an `Err`-returning fn signature.
/// Maps cleanly into [`rimap_core::RimapError`] via the [`From`] impl
/// below; `main.rs` then `?`-converts to its own `anyhow::Result`
/// wrapper at the outermost edge.
#[derive(Debug, Error)]
pub enum BootError {
    /// Credential resolution failed for an account.
    #[error("resolving credential for account {account}: {source}")]
    Credential {
        /// Account that failed.
        account: String,
        /// Underlying config-layer error.
        #[source]
        source: Box<rimap_config::ConfigError>,
    },
    /// SMTP client construction failed.
    #[error("building SMTP client for account {account}: {source}")]
    Smtp {
        /// Account that failed.
        account: String,
        /// Underlying SMTP-layer error.
        #[source]
        source: Box<rimap_smtp::SmtpError>,
    },
    /// Special-use folder discovery (the per-account boot LIST round trip)
    /// failed.
    #[error("resolving special-use folders for account {account}: {source}")]
    SpecialUseDiscovery {
        /// Account that failed.
        account: String,
        /// Underlying IMAP-layer error.
        #[source]
        source: Box<rimap_imap::ImapError>,
    },
    /// Governor / rate-limiter construction failed.
    #[error("building governor for account {account}: {source}")]
    Governor {
        /// Account that failed.
        account: String,
        /// Underlying authz-layer error.
        #[source]
        source: Box<rimap_authz::error::AuthzError>,
    },
}

impl BootError {
    /// Stable [`ErrorCode`] classification preserved across the
    /// boot/runtime seam.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Credential { source, .. } => source.code(),
            Self::Smtp { source, .. } => source.code(),
            Self::SpecialUseDiscovery { source, .. } => source.code(),
            Self::Governor { source, .. } => source.code(),
        }
    }
}

impl From<BootError> for rimap_core::RimapError {
    fn from(err: BootError) -> Self {
        let code = err.code();
        let message = err.to_string();
        rimap_core::RimapError::InternalSourced {
            message: format!("[{code}] {message}"),
            source: Box::new(err),
        }
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
/// Returns a [`BootError`] if credential resolution, SMTP client
/// construction, governor build, or special-use folder discovery fails
/// for any account. The variant carries a stable [`ErrorCode`] so the
/// boot/runtime seam preserves classification.
pub async fn build(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> Result<AccountRegistry, BootError> {
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
) -> Result<(AccountId, AccountState), BootError> {
    let guard = build_account_guard(&acfg)?;
    let conn_cfg = build_account_connection(&id, &acfg);
    let resolver: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            Arc::clone(&credentials),
            acfg.fallback_mode,
        ));
    let imap = Connection::new(conn_cfg, auth_sink, resolver);

    let special_use = crate::boot::discovery::resolve_special_use(&imap)
        .await
        .map_err(|source| BootError::SpecialUseDiscovery {
            account: id.as_str().to_string(),
            source: Box::new(source),
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
fn build_smtp_client(
    acfg: &ValidatedAccountConfig,
    credentials: &Arc<dyn CredentialStore>,
) -> Result<Option<SmtpClient>, BootError> {
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
    .map_err(|source| BootError::Credential {
        account: acfg.id.as_str().to_string(),
        source: Box::new(source),
    })?;
    let client = SmtpClient::new(smtp_cfg, smtp_password.expose_secret()).map_err(|source| {
        BootError::Smtp {
            account: acfg.id.as_str().to_string(),
            source: Box::new(source),
        }
    })?;
    drop(smtp_password);
    Ok(Some(client))
}

/// Build the composed authz guard from a per-account config.
fn build_account_guard(
    acfg: &ValidatedAccountConfig,
) -> Result<DispatchGuard<SystemClock>, BootError> {
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
    .map_err(|source| BootError::Governor {
        account: acfg.id.as_str().to_string(),
        source: Box::new(source),
    })?;
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
