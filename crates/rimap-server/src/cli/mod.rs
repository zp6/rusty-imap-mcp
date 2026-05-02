//! CLI definitions for `rusty-imap-mcp`.
//!
//! Top-level flags:
//!   - `--config <path>` — explicit config path (else env var, else XDG default).
//!   - `--dry-run` — load config, print effective matrix, exit.
//!
//! Subcommand:
//!   - `login` — interactively store a credential in the keychain.
//!   - `audit <action>` — audit log inspection utilities (see `AuditAction`).

pub(crate) mod audit_merge;
pub(crate) mod dry_run;
pub(crate) mod migrate_keyring;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rimap_core::account::DEFAULT_ACCOUNT_NAME;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "rusty-imap-mcp",
    version,
    about = "Security-first MCP server for IMAP email access"
)]
pub struct Cli {
    /// Path to the config file. Overrides `RUSTY_IMAP_MCP_CONFIG` and the
    /// platform default.
    #[arg(long, value_name = "PATH", env = "RUSTY_IMAP_MCP_CONFIG")]
    pub config: Option<PathBuf>,

    /// Load the config, print the effective tool matrix, and exit.
    /// Mutually exclusive with subcommands.
    #[arg(long)]
    pub dry_run: bool,

    /// Subcommand (optional; default is the MCP server loop — not yet implemented).
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Interactively store IMAP credentials in the OS keychain.
    Login {
        /// Account name from config. Defaults to `default`, matching the
        /// synthetic account used for legacy single-account configs.
        #[arg(long, default_value_t = String::from(DEFAULT_ACCOUNT_NAME))]
        account: String,
        /// IMAP host (e.g. `127.0.0.1` for Proton Bridge).
        #[arg(long)]
        host: String,
        /// IMAP username (e.g. `alice@example.com`).
        #[arg(long)]
        username: String,
    },
    /// Migrate a credential from the legacy keyring key format
    /// (`<username>@<host>`) to the new namespaced format
    /// (`<account-id>/<username>@<host>`). Run once per account after
    /// upgrading across #77.
    MigrateKeyring {
        /// Account name from config.
        #[arg(long)]
        account: String,
        /// IMAP host.
        #[arg(long)]
        host: String,
        /// IMAP username.
        #[arg(long)]
        username: String,
    },
    /// Audit log inspection utilities.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Run the daemon in the foreground (long-lived server).
    Daemon,
    /// Run the stdio↔socket shim (connects to a running daemon).
    Shim,
    /// Windows Service Control Manager integration (issue #129).
    /// Install / uninstall the User Service Template, or enter the
    /// SCM-driven service entry point. Windows-only.
    #[cfg(windows)]
    Service {
        /// Service-management action.
        #[command(subcommand)]
        action: ServiceAction,
    },
}

/// Actions under `rusty-imap-mcp audit <action>`.
#[derive(Debug, Subcommand)]
pub enum AuditAction {
    /// Stream the active (or rotated) audit file as filtered JSONL on stdout.
    Merge {
        /// Path to an audit file.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
        /// Only include records at or after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Only include records at or before this RFC 3339 timestamp.
        #[arg(long)]
        until: Option<String>,
        /// Only include records whose `tool` field matches this string.
        #[arg(long)]
        tool: Option<String>,
        /// Only include records whose `kind` field matches this string.
        #[arg(long)]
        kind: Option<String>,
        /// Only include records whose `process_id` matches this ULID.
        #[arg(long)]
        process: Option<String>,
        /// Only include records whose `account` field matches this name.
        #[arg(long)]
        account: Option<String>,
    },
}

/// Actions under `rusty-imap-mcp service <action>`. Windows-only.
#[cfg(windows)]
#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Register the daemon as a User Service Template. Requires Administrator.
    Install {
        /// Service name (default: `RustyImapMcp`).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Config file path baked into the registered command line. If
        /// omitted, falls back to `RUSTY_IMAP_MCP_CONFIG` / the platform
        /// default at install time.
        #[arg(long, value_name = "PATH")]
        config: Option<std::path::PathBuf>,
    },
    /// Remove the User Service Template registration. Idempotent.
    /// Requires Administrator.
    Uninstall {
        /// Service name (default: `RustyImapMcp`).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// SCM-only entry point. Invoked by the Service Control Manager;
    /// not for interactive use. See `rusty-imap-mcp daemon` for the
    /// foreground equivalent.
    Run,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use clap::Parser;
    use rimap_core::account::DEFAULT_ACCOUNT_NAME;

    #[cfg(windows)]
    use crate::cli::ServiceAction;
    use crate::cli::{Cli, Command};

    #[test]
    fn parses_dry_run_with_config() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "--config", "/tmp/x.toml", "--dry-run"])
            .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/x.toml"))
        );
        assert!(cli.dry_run);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_login_subcommand() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "login",
            "--host",
            "127.0.0.1",
            "--username",
            "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Login {
                account,
                host,
                username,
            }) => {
                assert_eq!(account, DEFAULT_ACCOUNT_NAME);
                assert_eq!(host, "127.0.0.1");
                assert_eq!(username, "alice");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn parses_login_subcommand_with_explicit_account() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "login",
            "--account",
            "work",
            "--host",
            "127.0.0.1",
            "--username",
            "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Login {
                account,
                host,
                username,
            }) => {
                assert_eq!(account, "work");
                assert_eq!(host, "127.0.0.1");
                assert_eq!(username, "alice");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn no_args_is_valid_and_defaults() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp"]).unwrap();
        assert!(!cli.dry_run);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_audit_merge_with_all_filters() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "audit",
            "merge",
            "/tmp/audit.jsonl",
            "--since",
            "2026-04-07T00:00:00Z",
            "--until",
            "2026-04-08T00:00:00Z",
            "--tool",
            "search",
            "--kind",
            "tool_end",
            "--process",
            "01JXAAAAAAAAAAAAAAAAAAAAAA",
            "--account",
            "work",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Audit {
                action:
                    crate::cli::AuditAction::Merge {
                        path,
                        since,
                        until,
                        tool,
                        kind,
                        process,
                        account,
                    },
            }) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/audit.jsonl"));
                assert_eq!(since.as_deref(), Some("2026-04-07T00:00:00Z"));
                assert_eq!(until.as_deref(), Some("2026-04-08T00:00:00Z"));
                assert_eq!(tool.as_deref(), Some("search"));
                assert_eq!(kind.as_deref(), Some("tool_end"));
                assert_eq!(process.as_deref(), Some("01JXAAAAAAAAAAAAAAAAAAAAAA"));
                assert_eq!(account.as_deref(), Some("work"));
            }
            other => panic!("expected Audit::Merge, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_install_with_all_flags() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "service",
            "install",
            "--name",
            "RustyImapMcpTest",
            "--config",
            r"C:\rusty.toml",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Install { name, config } => {
                    assert_eq!(name.as_deref(), Some("RustyImapMcpTest"));
                    assert_eq!(config, Some(std::path::PathBuf::from(r"C:\rusty.toml")));
                }
                other => panic!("expected Install, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_uninstall_with_default_name() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "service", "uninstall"]).unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Uninstall { name } => assert!(name.is_none()),
                other => panic!("expected Uninstall, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_run() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "service", "run"]).unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Run => {}
                other => panic!("expected Run, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }
}
