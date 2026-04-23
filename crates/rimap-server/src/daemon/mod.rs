//! Daemon mode: long-running MCP server multiplexing client sessions over
//! a Unix domain socket (Linux/macOS) or Windows named pipe.

pub mod audit_sink;
#[cfg(unix)]
pub mod hardening;
pub mod run;
pub mod shutdown;
pub mod socket_path;
#[cfg(unix)]
pub mod socket_setup;
pub mod state;
pub mod transport;
