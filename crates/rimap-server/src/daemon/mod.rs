//! Daemon mode: long-running MCP server multiplexing client sessions over
//! a Unix domain socket (Linux/macOS) or Windows named pipe.

pub mod socket_path;
pub mod transport;
