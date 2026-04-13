//! Configuration error type. Every variant is surfaced as `ERR_CONFIG` at the
//! top level per design spec §9.

use std::path::PathBuf;

use rimap_core::posture::UnknownPosture;
use rimap_core::tool::ParseToolNameError;
use thiserror::Error;

/// Error produced by config loading, parsing, validation, or credential resolution.
#[derive(Debug, Error)]
#[non_exhaustive]
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
    /// A per-tool override referenced an unknown tool name.
    #[error("invalid tool override: {0}")]
    ToolOverride(#[from] ParseToolNameError),
    /// TLS fingerprint did not parse as 32 hex bytes.
    #[error("invalid tls_fingerprint_sha256: {reason}")]
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
    /// `audit.path` resolved to a location outside the configured
    /// `allowed_base_dir`.
    ///
    /// ## Path disclosure exemption (LOCAL-ERR-05)
    ///
    /// The `Display` for this variant embeds both canonicalized paths.
    /// The LOCAL-ERR-05 rule normally forbids filesystem paths in error
    /// messages because they leak layout into operator-visible logs.
    /// This variant is exempted because:
    ///
    ///   - It fires only at config validation time, during startup,
    ///     against a path the OPERATOR themselves wrote in their config
    ///     file. The audience is never an attacker — it is the same
    ///     operator who supplied the misconfigured path.
    ///   - The canonicalized paths are the actionable information the
    ///     operator needs to diagnose the problem (e.g. "I wrote
    ///     `~/audit.jsonl` but my allowed base is `~/Library/...`").
    ///
    /// Both paths are filesystem layout, which is sensitive if this
    /// variant ever starts firing from runtime (non-startup) code paths
    /// or from attacker-controlled config. If that changes, revisit
    /// this exemption.
    #[error("audit path `{path}` is not contained in allowed base `{base}`")]
    AuditPathOutsideBase {
        /// The canonicalized audit path.
        path: PathBuf,
        /// The canonicalized base directory.
        base: PathBuf,
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
    /// `send_email` is effectively enabled but no `[smtp]` section is configured.
    #[error(
        "send_email is enabled (posture = {posture}) but no [smtp] section \
         is configured; add [smtp] or deny send_email via \
         [security.tools] send_email = \"deny\""
    )]
    SmtpRequired {
        /// The posture that enabled `send_email`.
        posture: String,
    },
    /// A folder appears in both `protected_folders` and `expunge_folders`.
    #[error(
        "folder `{folder}` is in both protected_folders and expunge_folders; \
         a folder cannot be both protected and expungeable"
    )]
    ConflictingFolders {
        /// The conflicting folder name.
        folder: String,
    },
    /// SMTP encryption set to "none" for a non-localhost host.
    #[error(
        "smtp encryption is 'none' for host `{host}`; \
         plaintext SMTP exposes credentials on the network"
    )]
    SmtpPlaintextDenied {
        /// The configured SMTP host.
        host: String,
    },
}
