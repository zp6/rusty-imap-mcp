//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod model;

pub use crate::error::ConfigError;
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
