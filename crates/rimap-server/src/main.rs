//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;

use rimap_server::boot::logging;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::CommandFactory as _;
use clap::Parser;
use rimap_config::credential::KeyringStore;
use rimap_config::loader::resolve_config_path;
use rimap_config::login::{run_login, tty_prompt};

use crate::cli::{AuditAction, Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // The SCM service-run path installs its own subscriber pointed at the
    // daemon log file inside `service_main_impl`; installing the global
    // subscriber here would lose those redirected events. Every other
    // command uses the standard stderr subscriber.
    #[cfg(windows)]
    let defer_logging = matches!(
        cli.command,
        Some(Command::Service {
            action: crate::cli::ServiceAction::Run,
        }),
    );
    #[cfg(not(windows))]
    let defer_logging = false;

    if !defer_logging {
        logging::init();
    }

    // Shim is special: it manages its own exit code rather than fitting the
    // anyhow::Result pattern. Handle it here before entering `run`.
    if matches!(cli.command, Some(Command::Shim)) {
        return rimap_server::shim::run().await;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // When logging was deferred but the dispatcher errored before
            // `service_main_impl` installed its own subscriber, fall back
            // to a plain stderr write so the operator sees the cause.
            if defer_logging {
                let _ = writeln!(std::io::stderr().lock(), "{e:#}");
            } else {
                tracing::error!("{e:#}");
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if let Some(Command::Login {
        account,
        host,
        username,
    }) = &cli.command
    {
        let store = KeyringStore;
        let account_id = rimap_core::account::AccountId::new(account)
            .with_context(|| format!("invalid account name `{account}`"))?;
        run_login(&store, &account_id, username, host, tty_prompt)
            .with_context(|| format!("storing credential for {username}@{host}"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "credential stored for {username}@{host}")?;
        return Ok(());
    }

    if let Some(Command::MigrateKeyring {
        account,
        host,
        username,
    }) = &cli.command
    {
        return run_migrate_keyring(account, username, host);
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
        return cli::audit_merge::run(
            &path,
            cli::audit_merge::RunArgs {
                since: since.as_deref(),
                until: until.as_deref(),
                tool: tool.as_deref(),
                kind: kind.as_deref(),
                process: process.as_deref(),
                account: account.as_deref(),
            },
        );
    }

    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        return cli::dry_run::run(&path, &mut stdout).await;
    }

    if let Some(Command::Daemon) = cli.command {
        return daemon_main(cli.config).await;
    }

    #[cfg(windows)]
    if let Some(Command::Service { action }) = cli.command {
        return handle_service_action(action);
    }

    // No subcommand and not --dry-run: print help and bail.
    // Shim is handled earlier in main() before this function is called.
    Cli::command().print_help().context("print help")?;
    writeln!(std::io::stderr().lock())?;
    anyhow::bail!("no subcommand provided — see `rusty-imap-mcp daemon` and `rusty-imap-mcp shim`")
}

async fn daemon_main(config_override: Option<PathBuf>) -> anyhow::Result<()> {
    use rimap_server::daemon::run::run_with_shutdown;
    use rimap_server::daemon::shutdown::install_shutdown_handler;

    let config_path = resolve_or_default(config_override)?;
    let shutdown = install_shutdown_handler();
    run_with_shutdown(config_path, shutdown, None).await
}

/// Dispatch the `service <action>` subcommand. Windows-only because the
/// underlying `windows-service` types and the SCM dispatcher are not
/// available on other platforms.
#[cfg(windows)]
fn handle_service_action(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    use rimap_server::service::install::{InstallInputs, UninstallInputs, install, uninstall};

    match action {
        crate::cli::ServiceAction::Install { name, config } => {
            let binary_path = std::env::current_exe().context("resolving current binary path")?;
            let config_path = resolve_or_default(config)?;
            install(&InstallInputs {
                name,
                binary_path,
                config_path,
            })?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "service installed")?;
            Ok(())
        }
        crate::cli::ServiceAction::Uninstall { name } => {
            uninstall(&UninstallInputs { name })?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "service uninstalled")?;
            Ok(())
        }
        crate::cli::ServiceAction::Run => {
            rimap_server::service::run::dispatch(rimap_server::service::SERVICE_NAME_DEFAULT)
                .map_err(map_dispatch_error)
        }
    }
}

/// Translate `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (Win32 1063) — the
/// error SCM raises when `service run` is invoked interactively rather
/// than from the Service Control Manager — into a friendly hint pointing
/// at the foreground `daemon` verb. Other dispatcher errors pass through.
#[cfg(windows)]
fn map_dispatch_error(e: windows_service::Error) -> anyhow::Error {
    /// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: SCM rejects a connect
    /// attempt from a non-service process.
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return anyhow::anyhow!(
                "this verb is for the Service Control Manager — \
                 see `rusty-imap-mcp daemon` for foreground use"
            );
        }
    }
    anyhow::Error::from(e)
}

/// Resolve a config-file path from an explicit `--config` override, falling
/// back to the `RUSTY_IMAP_MCP_CONFIG` environment variable via
/// [`resolve_config_path`]. Errors with the same "no config path" message
/// used by the previous inline implementations.
fn resolve_or_default(override_: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    override_
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}

/// Resolve the config file path from `--config` or the
/// `RUSTY_IMAP_MCP_CONFIG` environment variable, erroring if neither is set.
fn resolve_cli_config_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    resolve_or_default(cli.config.clone())
}

/// Handle the `migrate-keyring` subcommand.
fn run_migrate_keyring(account: &str, username: &str, host: &str) -> anyhow::Result<()> {
    let store = KeyringStore;
    let account_id = rimap_core::account::AccountId::new(account)
        .with_context(|| format!("invalid account name `{account}`"))?;
    let migrated = cli::migrate_keyring::migrate_one(&store, &account_id, username, host)
        .with_context(|| format!("migrating credential for account `{account}`, host `{host}`"))?;
    let mut stdout = std::io::stdout().lock();
    if migrated {
        writeln!(stdout, "migrated credential for account `{account}`")?;
    } else {
        writeln!(
            stdout,
            "no legacy credential found for account `{account}` (host `{host}`); nothing to migrate"
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod resolve_or_default_tests {
    use super::resolve_or_default;
    use std::path::PathBuf;

    #[test]
    fn override_path_wins_over_env() {
        let explicit = PathBuf::from("/tmp/custom.toml");
        let got = resolve_or_default(Some(explicit.clone())).unwrap();
        assert_eq!(got, explicit);
    }

    #[test]
    fn no_override_no_env_error_message_is_actionable() {
        // We cannot force resolve_config_path to return None on a host where
        // ProjectDirs::from succeeds — on Linux it falls back to /etc/passwd
        // via getpwuid when HOME is unset, so there's no env-var combo that
        // disables it. When it *does* return None (headless / unusual passwd
        // configs), the error surface must name the fix the user should take.
        temp_env::with_var("RUSTY_IMAP_MCP_CONFIG", None::<&str>, || {
            if let Err(e) = resolve_or_default(None) {
                let msg = e.to_string();
                assert!(msg.contains("--config"), "error lacks --config hint: {msg}");
                assert!(
                    msg.contains("RUSTY_IMAP_MCP_CONFIG"),
                    "error lacks env-var hint: {msg}",
                );
            }
        });
    }
}
