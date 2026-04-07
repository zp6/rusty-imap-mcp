//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod ids;
pub mod record;

pub use crate::error::AuditError;
pub use crate::ids::{ProcessId, Seq, Timestamp};
pub use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart};
