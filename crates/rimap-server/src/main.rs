//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod audit_cmd;
mod audit_init;
mod cli;
mod dry_run;
mod logging;

use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rimap_config::credential::KeyringStore;
use rimap_config::loader::{load_from_path, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};
use rimap_config::validate::validate;

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
        let path = cli
            .config
            .clone()
            .or_else(|| resolve_config_path(None))
            .ok_or_else(|| {
                anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
            })?;
        let mut stdout = std::io::stdout().lock();
        return dry_run::run(&path, &mut stdout);
    }

    // Server mode: load config, open audit writer, emit process_start.
    // The MCP transport loop itself lands in Sprint 5; this scaffolding
    // ensures the audit chain is correctly initialized before it runs.
    let config_path = cli
        .config
        .clone()
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })?;
    let raw = load_from_path(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let validated = validate(raw).context("validating config")?;
    let _audit = audit_init::init_audit_writer(&validated, &config_path).with_context(|| {
        format!(
            "opening audit log at {}",
            validated.config.audit.path.display()
        )
    })?;

    Err(anyhow::anyhow!(
        "MCP server mode is not implemented until Sprint 5; \
         use --dry-run or the `login` subcommand"
    ))
}
