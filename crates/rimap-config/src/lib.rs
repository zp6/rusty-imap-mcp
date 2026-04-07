//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod loader;
pub mod model;
pub mod validate;

pub use crate::error::ConfigError;
pub use crate::loader::{CONFIG_ENV_VAR, load_from_path, resolve_config_path};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
pub use crate::validate::{ValidatedConfig, validate};
