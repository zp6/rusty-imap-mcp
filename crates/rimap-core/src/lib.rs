//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod error;
pub mod posture;

pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
