//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::AuditError;
