//! IMAP connection, TLS fingerprint pinning, and per-command operations
//! (fetch, search, store, move, append, expunge, folder management) for
//! rusty-imap-mcp. Public entry point: [`Connection`].

#![deny(missing_docs)]

pub(crate) mod auth;
pub mod connection;
pub mod error;
pub mod ops;
pub mod special_use;
pub mod time;
pub mod tls;
pub mod types;

pub use crate::connection::{Connection, ConnectionConfig};
pub use crate::error::{AuthFailure, ImapError};
pub use special_use::{SpecialUse, SpecialUseMap, classify_special_use};
