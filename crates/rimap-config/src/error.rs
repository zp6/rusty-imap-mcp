//! Configuration error type. Every variant is surfaced as `ERR_CONFIG` at the
//! top level per design spec §9.

use std::path::PathBuf;

use rimap_core::posture::UnknownPosture;
use rimap_core::tool::ParseToolNameError;
use thiserror::Error;

/// Error produced by config loading, parsing, validation, or credential resolution.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config file `{path}`: {source}")]
    Read {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file was not valid TOML.
    #[error("failed to parse config file `{path}`: {source}")]
    Parse {
        /// Attempted path.
        path: PathBuf,
        /// Underlying `toml` parse error.
        #[source]
        source: toml::de::Error,
    },
    /// The posture name in the config was not recognized.
    #[error(transparent)]
    Posture(#[from] UnknownPosture),
    /// A per-tool override referenced an unknown or v2 tool name.
    #[error("invalid tool override: {0}")]
    ToolOverride(#[from] ParseToolNameError),
    /// TLS fingerprint did not parse as 32 hex bytes.
    #[error("invalid tls_fingerprint_sha256: expected 32 hex bytes, {reason}")]
    TlsFingerprint {
        /// Specific parse failure reason.
        reason: String,
    },
    /// A required directory is missing or not writable.
    #[error("path `{path}` is not writable: {reason}")]
    PathNotWritable {
        /// The offending path.
        path: PathBuf,
        /// Explanation.
        reason: String,
    },
    /// A numeric limit was zero or out of range.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidLimit {
        /// TOML field name in dotted form, e.g. `limits.commands_per_second`.
        field: &'static str,
        /// Explanation.
        reason: String,
    },
    /// No credential could be found in keychain or environment.
    #[error("no credential found for `{account}`: {reason}")]
    NoCredential {
        /// `<username>@<host>` style account.
        account: String,
        /// What we tried and what the user should do next.
        reason: String,
    },
    /// Keychain access error (not "not found" — that becomes `NoCredential`).
    #[error("keychain error for `{account}`: {source}")]
    Keychain {
        /// `<username>@<host>` style account.
        account: String,
        /// Underlying keyring error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}
