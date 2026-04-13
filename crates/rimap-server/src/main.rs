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
use rimap_config::loader::{load_from_path, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};
use rimap_config::validate::{ValidatedConfig, validate};
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
        );
    }

    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        return dry_run::run(&path, &mut stdout);
    }

    // Server mode: load config, build subsystems, run MCP transport.
    let config_path = resolve_cli_config_path(&cli)?;
    let raw = load_from_path(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let validated = validate(raw).context("validating config")?;
    let audit = audit_init::init_audit_writer(&validated, &config_path).with_context(|| {
        format!(
            "opening audit log at {}",
            validated.config.audit.path.display()
        )
    })?;

    let guard = build_dispatch_guard(&validated).context("building dispatch guard")?;
    let conn_cfg = build_connection_config(&validated);
    let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    let imap = Connection::new(conn_cfg, audit.clone(), credentials);
    let download_dir = resolve_download_dir(&validated)?;

    let folder_guard = rimap_authz::FolderGuard::new(
        &validated.config.security.protected_folders,
        &validated.config.security.expunge_folders,
    );
    let from_address = validated.config.imap.username.clone();

    let id = rimap_core::account::AccountId::default_account();
    let state = registry::AccountState {
        id: id.clone(),
        from_address,
        imap,
        smtp: None,
        guard,
        folder_guard,
    };
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert(id, state);
    let registry = registry::AccountRegistry::new(accounts);

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

/// Build the composed authz guard from validated config.
fn build_dispatch_guard(cfg: &ValidatedConfig) -> anyhow::Result<DispatchGuard<SystemClock>> {
    let matrix = EffectiveMatrix::from_validated(cfg);
    let limits = &cfg.config.limits;
    let breaker_cfg = BreakerConfig {
        error_threshold: limits.circuit_breaker_error_threshold,
        window: Duration::from_secs(u64::from(limits.circuit_breaker_window_seconds)),
        ..BreakerConfig::default_spec()
    };
    let breaker = CircuitBreaker::new(SystemClock::new(), breaker_cfg);
    let governor = Governor::new(
        limits.commands_per_second,
        limits.drafts_per_minute,
        limits.sends_per_minute,
    )
    .map_err(|e| anyhow::anyhow!("governor: {e}"))?;
    Ok(DispatchGuard::new(matrix, breaker, governor))
}

/// Map validated config fields to a `ConnectionConfig`.
fn build_connection_config(cfg: &ValidatedConfig) -> ConnectionConfig {
    let imap = &cfg.config.imap;
    ConnectionConfig {
        host: imap.host.clone(),
        port: imap.port,
        username: imap.username.clone(),
        pinned_fingerprint: cfg.tls_fingerprint,
        connect_timeout: Duration::from_secs(u64::from(imap.connect_timeout_seconds)),
        command_timeout: Duration::from_secs(u64::from(imap.command_timeout_seconds)),
        max_fetch_body_bytes: cfg.config.limits.max_fetch_body_bytes,
        max_append_bytes: cfg.config.limits.max_append_bytes,
    }
}

/// Resolve the attachment download directory. Uses the configured
/// path if non-empty, otherwise creates a temporary directory.
fn resolve_download_dir(cfg: &ValidatedConfig) -> anyhow::Result<PathBuf> {
    let dir_str = &cfg.config.attachments.download_dir;
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
