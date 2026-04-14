//! IMAP connection, TLS fingerprint pinning, and read operations for
//! rusty-imap-mcp. See `docs/superpowers/specs/2026-04-07-sprint-3-imap-design.md`
//! for the design.

#![deny(missing_docs)]

pub(crate) mod auth;
pub mod connection;
pub mod error;
pub mod ops;
pub mod time;
pub mod tls;
pub mod types;

pub use crate::connection::{Connection, ConnectionConfig};
pub use crate::error::{AuthFailure, ImapError};
