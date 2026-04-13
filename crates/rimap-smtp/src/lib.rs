//! SMTP client for rusty-imap-mcp.
//!
//! Thin wrapper around `lettre` providing connection management,
//! TLS via `rustls`, and error mapping. Does not construct messages —
//! message building is handled by the server layer.

#![deny(missing_docs)]

pub mod client;
pub mod error;

pub use crate::client::SmtpClient;
pub use crate::error::SmtpError;
