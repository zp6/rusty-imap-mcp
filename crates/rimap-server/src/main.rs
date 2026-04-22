//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;

use rimap_server::boot::{audit_init, logging, registry};

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
use secrecy::ExposeSecret;

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
    use rimap_server::daemon::{socket_setup, transport::unix::UnixSocketListener};

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

    let registry = build_registry(&multi, &audit, &credentials, &download_dir)
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
        socket_setup::prepare_socket_dir(parent, our_uid)
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

    let state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
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

/// Build the account registry from a validated multi-account config.
async fn build_registry(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> anyhow::Result<registry::AccountRegistry> {
    let mut account_states = std::collections::BTreeMap::new();
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

        let special_use = rimap_server::boot::discovery::resolve_special_use(&imap)
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

        let folder_guard =
            rimap_authz::FolderGuard::new(&protected, &acfg.security.expunge_folders);

        let state = registry::AccountState {
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
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        acfg.fallback_mode,
    )
    .with_context(|| format!("resolving SMTP credential for account {}", acfg.id.as_str()))?;
    let client = rimap_smtp::SmtpClient::new(smtp_cfg, smtp_password.expose_secret())
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
    use rimap_config::model::{AttachmentsConfig, AuditConfig};
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
