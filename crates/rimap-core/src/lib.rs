//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod audit;
pub mod error;
pub mod posture;
pub mod tool;

pub use crate::audit::{AuditRecord, AuthOutcome, ProcessEvent};
pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::tool::{ParseToolNameError, ToolName};
