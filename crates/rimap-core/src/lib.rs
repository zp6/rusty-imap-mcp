//! Shared core types for rusty-imap-mcp: errors, postures, tool names.

#![deny(missing_docs)]

pub mod account;
pub mod error;
pub mod posture;
pub mod posture_matrix;
pub mod tls;
pub mod tool;

pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::posture_matrix::base_allows;
pub use crate::tls::{FingerprintParseError, TlsFingerprint};
pub use crate::tool::{ParseToolNameError, ToolName};
