//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod audit_cmd;
mod audit_init;
mod cli;
mod content;
mod dispatch;
mod download;
mod dry_run;
mod logging;
mod mcp_error;
mod registry;
mod response;
mod server;
mod tools;

#[cfg(test)]
mod e2e_test;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::{CredentialStore, KeyringStore};
use rimap_config::loader::{load_and_validate, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_imap::{Connection, ConnectionConfig};

use crate::cli::{AuditAction, Cli, Command};

fn main() -> ExitCode {
    logging::init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    if let Some(Command::Login { host, username }) = &cli.command {
        let store = KeyringStore;
        run_login(&store, username, host, tty_prompt)
            .with_context(|| format!("storing credential for {username}@{host}"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "credential stored for {username}@{host}")?;
        return Ok(());
    }

    if let Some(Command::Audit {
        action:
            AuditAction::Merge {
                path,
                since,
                until,
                tool,
                kind,
                process,
                account,
            },
    }) = cli.command
    {
        return audit_cmd::run(
            &path,
            since.as_deref(),
            until.as_deref(),
            tool.as_deref(),
            kind.as_deref(),
            process.as_deref(),
            account.as_deref(),
        );
    }

    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        return dry_run::run(&path, &mut stdout);
    }

    // Server mode: load config, build subsystems, run MCP transport.
    let config_path = resolve_cli_config_path(&cli)?;
    let multi = load_and_validate(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let audit = audit_init::init_audit_writer_multi(&multi, &config_path)
        .with_context(|| format!("opening audit log at {}", multi.audit.path.display()))?;

    let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    let download_dir = resolve_download_dir_multi(&multi)?;
    let registry = build_registry(&multi, &audit, &credentials)?;

    let audit_for_shutdown = audit.clone();
    let mcp_server = server::ImapMcpServer {
        registry,
        audit,
        download_dir,
    };

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    let mcp_result: anyhow::Result<()> = rt.block_on(async {
        let transport = rmcp::transport::io::stdio();
        let service = Box::pin(rmcp::serve_server(mcp_server, transport))
            .await
            .map_err(|e| anyhow::anyhow!("MCP server init: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
        Ok(())
    });

    // Best-effort process_end emission.
    let reason = match &mcp_result {
        Ok(()) => rimap_audit::ProcessEndReason::Eof,
        Err(_) => rimap_audit::ProcessEndReason::Error,
    };
    // total_tool_calls is not tracked yet — use 0 as placeholder.
    // A future PR can add an AtomicU64 counter to ImapMcpServer.
    match audit_for_shutdown.log_process_end(reason, 0) {
        Ok(seq) => tracing::info!(seq = %seq, "process_end audit record written"),
        Err(e) => tracing::error!(error = %e, "failed to write process_end audit record"),
    }

    mcp_result
}

/// Resolve the config file path from `--config` or the
/// `RUSTY_IMAP_MCP_CONFIG` environment variable, erroring if neither is set.
fn resolve_cli_config_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    cli.config
        .clone()
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}

/// Build the account registry from a validated multi-account config.
fn build_registry(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
) -> anyhow::Result<registry::AccountRegistry> {
    let mut account_states = std::collections::BTreeMap::new();
    for (id, acfg) in &multi.accounts {
        let guard = build_account_guard(acfg).context("building dispatch guard")?;
        let conn_cfg = build_account_connection(id, acfg);
        let imap = Connection::new(conn_cfg, audit.clone(), credentials.clone());

        let smtp = build_smtp_client(acfg, credentials)?;

        let folder_guard = rimap_authz::FolderGuard::new(
            &acfg.security.protected_folders,
            &acfg.security.expunge_folders,
        );

        let state = registry::AccountState {
            id: id.clone(),
            from_address: acfg.imap.username.clone(),
            imap,
            smtp,
            guard,
            folder_guard,
        };
        account_states.insert(id.clone(), state);
    }
    Ok(registry::AccountRegistry::new(account_states))
}

/// Build an SMTP client from account config, if SMTP is configured.
fn build_smtp_client(
    acfg: &ValidatedAccountConfig,
    credentials: &Arc<dyn CredentialStore>,
) -> anyhow::Result<Option<rimap_smtp::SmtpClient>> {
    let Some(ref smtp_cfg) = acfg.smtp else {
        return Ok(None);
    };
    let smtp_password =
        rimap_config::resolve_credential(&**credentials, &smtp_cfg.username, &smtp_cfg.host)
            .with_context(|| format!("resolving SMTP credential for {}", smtp_cfg.username))?;
    let client = rimap_smtp::SmtpClient::new(smtp_cfg, &smtp_password)
        .with_context(|| format!("building SMTP client for {}", smtp_cfg.host))?;
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
        host: acfg.imap.host.clone(),
        port: acfg.imap.port,
        username: acfg.imap.username.clone(),
        pinned_fingerprint: acfg.tls_fingerprint,
        connect_timeout: Duration::from_secs(u64::from(acfg.imap.connect_timeout_seconds)),
        command_timeout: Duration::from_secs(u64::from(acfg.imap.command_timeout_seconds)),
        max_fetch_body_bytes: acfg.limits.max_fetch_body_bytes,
        max_append_bytes: acfg.limits.max_append_bytes,
    }
}

/// Resolve the attachment download directory from a multi-account config.
fn resolve_download_dir_multi(
    multi: &rimap_config::validate::ValidatedMultiConfig,
) -> anyhow::Result<PathBuf> {
    let dir_str = &multi.attachments.download_dir;
    if dir_str.is_empty() {
        let tmp = std::env::temp_dir().join("rusty-imap-mcp-downloads");
        std::fs::create_dir_all(&tmp)
            .with_context(|| format!("creating download dir {}", tmp.display()))?;
        Ok(tmp)
    } else {
        let path = PathBuf::from(dir_str);
        if !path.is_dir() {
            anyhow::bail!(
                "download_dir {} does not exist or is not a directory",
                path.display()
            );
        }
        Ok(path)
    }
}
