//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;

use rimap_server::boot::{audit_init, logging, registry};

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use rimap_config::credential::{CredentialStore, KeyringStore};
use rimap_config::loader::{load_and_validate, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};

use clap::CommandFactory as _;

use crate::cli::{AuditAction, Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    logging::init();
    let cli = Cli::parse();

    // Shim is special: it manages its own exit code rather than fitting the
    // anyhow::Result pattern. Handle it here before entering `run`.
    if matches!(cli.command, Some(Command::Shim)) {
        return rimap_server::shim::run().await;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
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
        return cli::dry_run::run(&path, &mut stdout);
    }

    if let Some(Command::Daemon) = cli.command {
        return daemon_main(cli.config).await;
    }

    // No subcommand and not --dry-run: print help and bail.
    // Shim is handled earlier in main() before this function is called.
    Cli::command().print_help().context("print help")?;
    writeln!(std::io::stderr().lock())?;
    anyhow::bail!("no subcommand provided — see `rusty-imap-mcp daemon` and `rusty-imap-mcp shim`")
}

async fn daemon_main(config_override: Option<PathBuf>) -> anyhow::Result<()> {
    use rimap_server::daemon::run::run;
    use rimap_server::daemon::shutdown::install_shutdown_handler;
    use rimap_server::daemon::socket_path;
    use rimap_server::daemon::state::DaemonState;
    #[cfg(windows)]
    use rimap_server::daemon::transport::windows::NamedPipeListener;
    #[cfg(unix)]
    use rimap_server::daemon::{hardening, socket_setup, transport::unix::UnixSocketListener};

    // Harden the daemon process before anything reads credentials or
    // performs network I/O: setrlimit(RLIMIT_CORE,0) + PR_SET_DUMPABLE=0
    // (Linux) prevent credential bytes from leaking via a crash dump or
    // a same-UID `/proc/self/mem` / ptrace attach. Review finding I4.
    #[cfg(unix)]
    hardening::lock_down_process()
        .context("daemon startup hardening (rlimit_core / prctl_dumpable)")?;

    let config_path = config_override
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })?;
    let multi = load_and_validate(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let audit = audit_init::init_audit_writer_multi(&multi, &config_path)
        .with_context(|| format!("opening audit log at {}", multi.audit.path.display()))?;

    let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    let download_dir: Arc<std::path::Path> =
        Arc::from(resolve_download_dir_multi(&multi)?.into_boxed_path());

    let registry = registry::build(&multi, &audit, &credentials, &download_dir)
        .await
        .context("building account registry")?;

    let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
    let drainer_handle = rimap_audit::spawn_drainer(cancellation_rx, audit.clone());

    #[cfg(unix)]
    let listener = {
        let ep = socket_path::resolve();
        let path = ep
            .as_path_buf()
            .ok_or_else(|| anyhow::anyhow!("unix path resolver returned non-path endpoint"))?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("socket path has no parent: {}", path.display()))?;
        let our_uid = rustix::process::geteuid().as_raw();
        // Defense in depth: hold the verified parent-directory fd across the
        // `bind` call. `UnixListener::bind(path)` still re-walks the path, so
        // an ancestor-symlink swap after `prepare_socket_dir` returns could
        // redirect `bind`. Narrowing the residual window to full bindat-by-fd
        // is tracked as a follow-up; in the meantime the held fd plus the
        // leaf-symlink refusal + post-bind mode assertion + umask guard keep
        // the attack surface bounded.
        let _parent_fd = socket_setup::prepare_socket_dir(parent, our_uid)
            .with_context(|| format!("preparing {}", parent.display()))?;
        UnixSocketListener::bind(&path)
            .await
            .with_context(|| format!("binding daemon socket at {}", path.display()))?
    };
    #[cfg(windows)]
    let listener = {
        let ep = socket_path::resolve().context("resolving daemon pipe name")?;
        NamedPipeListener::bind(ep.as_str())
            .with_context(|| format!("creating named pipe {}", ep.as_str()))?
    };

    let max_sessions =
        usize::try_from(multi.daemon.max_concurrent_sessions.get()).unwrap_or(usize::MAX);
    let session_permits = Arc::new(tokio::sync::Semaphore::new(max_sessions));

    let state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits,
    });

    let shutdown = install_shutdown_handler();
    let mcp_result = run(state, listener, shutdown).await;

    let reason = match &mcp_result {
        Ok(()) => rimap_audit::ProcessEndReason::Eof,
        Err(_) => rimap_audit::ProcessEndReason::Error,
    };
    if let Err(e) = drainer_handle.await {
        tracing::error!(error = %e, "cancellation drainer join error");
    }
    if let Err(e) = audit.log_process_end(rimap_audit::ProcessEnd {
        reason,
        // Aggregation across sessions is a follow-up — leave 0 for v1.
        total_tool_calls: 0,
    }) {
        tracing::error!(error = %e, "failed to write process_end");
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

/// Resolve the attachment download directory from a multi-account config.
///
/// If `attachments.download_dir` is set, the path is created (if needed) and
/// locked down to 0700 on Unix. Otherwise a per-process tempdir is created
/// via `tempfile` (TOCTOU-safe) and then locked down to 0700 on Unix. The
/// per-process dir is intentionally leaked (no automatic cleanup) so that
/// downloaded attachments remain readable for the server's lifetime.
fn resolve_download_dir_multi(
    multi: &rimap_config::validate::ValidatedMultiConfig,
) -> anyhow::Result<PathBuf> {
    let dir_str = &multi.attachments.download_dir;
    if !dir_str.is_empty() {
        let dir = PathBuf::from(dir_str);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating attachment download_dir at {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
        }
        return Ok(dir);
    }

    let dir = tempfile::Builder::new()
        .prefix("rusty-imap-mcp-")
        .tempdir()
        .context("creating per-process tempdir for attachments")?
        .keep();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
    }
    Ok(dir)
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

#[cfg(all(test, unix))]
#[expect(clippy::expect_used, reason = "tests")]
mod resolve_download_dir_tests {
    use super::resolve_download_dir_multi;
    use rimap_config::model::{AttachmentsConfig, AuditConfig, DaemonConfig};
    use rimap_config::validate::ValidatedMultiConfig;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn minimal_multi(download_dir: String) -> ValidatedMultiConfig {
        ValidatedMultiConfig {
            accounts: BTreeMap::new(),
            audit: AuditConfig {
                path: PathBuf::from("/tmp/unused-audit.log"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: None,
            },
            attachments: AttachmentsConfig { download_dir },
            daemon: DaemonConfig::default(),
        }
    }

    #[test]
    fn default_tempdir_has_0700_perms() {
        let multi = minimal_multi(String::new());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        let meta = std::fs::metadata(&dir).expect("metadata");
        assert!(meta.is_dir(), "expected a directory at {}", dir.display());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_dir_is_locked_down_to_0700() {
        let base = tempfile::tempdir().expect("tempdir");
        let target = base.path().join("attachments");
        let multi = minimal_multi(target.to_string_lossy().into_owned());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        assert_eq!(dir, target);
        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
    }
}
