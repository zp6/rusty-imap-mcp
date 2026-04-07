//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;
mod dry_run;
mod logging;

use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rimap_config::credential::KeyringStore;
use rimap_config::loader::resolve_config_path;
use rimap_config::login::{run_login, tty_prompt};

use crate::cli::{Cli, Command};

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
    if let Some(Command::Login { host, username }) = cli.command {
        let store = KeyringStore;
        run_login(&store, &username, &host, tty_prompt)
            .with_context(|| format!("storing credential for {username}@{host}"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "credential stored for {username}@{host}")?;
        return Ok(());
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

    // MCP server loop lands in Sprint 5.
    Err(anyhow::anyhow!(
        "MCP server mode is not implemented until Sprint 5; \
         use --dry-run or the `login` subcommand"
    ))
}
