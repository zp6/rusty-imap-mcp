//! Windows Service Control Manager integration (issue #129).
//!
//! Provides the per-user User Service Template install/uninstall surface
//! plus the `ServiceMain` body that translates SCM stop control into the
//! daemon's `Arc<Notify>` shutdown.

#![cfg(windows)]

pub mod install;
pub mod run;
pub(crate) mod tracing_sink;

/// Default User Service Template name used when `--name` is omitted.
pub const SERVICE_NAME_DEFAULT: &str = "RustyImapMcp";

/// User-facing display name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "Rusty IMAP MCP";

/// One-line description shown in `services.msc`.
pub const SERVICE_DESCRIPTION: &str = "Audit-logged Model Context Protocol server for IMAP email.";
