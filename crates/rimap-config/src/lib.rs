//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod credential;
pub mod error;
pub mod loader;
pub mod login;
pub mod model;
pub mod validate;

pub use crate::credential::{
    CredentialStore, KEYCHAIN_SERVICE, KeyringStore, PASSWORD_ENV_VAR, account_key,
    resolve_credential,
};
pub use crate::error::ConfigError;
pub use crate::loader::{CONFIG_ENV_VAR, load_and_validate, load_from_path, resolve_config_path};
pub use crate::login::{run_login, tty_prompt};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, DefaultsConfig, ImapConfig, LimitsConfig,
    LookalikeConfig, MultiAccountConfig, RawAccountConfig, SecurityConfig, SmtpConfig,
    SmtpEncryption, Verdict,
};
pub use crate::validate::{
    ValidatedAccountConfig, ValidatedMultiConfig, validate_legacy_as_multi, validate_multi,
};
pub use rimap_core::tls::{FingerprintParseError, TlsFingerprint};
