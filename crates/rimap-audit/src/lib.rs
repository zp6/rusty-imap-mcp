//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod ids;
pub mod provenance;
pub mod record;
pub mod redact;

pub use crate::error::AuditError;
pub use crate::ids::{ProcessId, Seq, Timestamp};
pub use crate::provenance::ProvenanceBuffer;
pub use crate::record::{
    AuditRecord, Auth, AuthResult, ConfigEvent, Payload, ProcessEnd, ProcessEndReason,
    ProcessStart, Provenance, ResultSummary, ToolEnd, ToolStart, ToolStatus,
};
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments, schemas,
};
