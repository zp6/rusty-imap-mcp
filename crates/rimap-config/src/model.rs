//! Strongly-typed config model. Field-for-field mapping of the TOML schema
//! from design spec §4 "File format".
//!
//! Validation is a separate pass (`validate.rs`): these structs only describe
//! *shape*. An instance that deserializes successfully may still be invalid.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rimap_core::posture::Posture;
use serde::{Deserialize, Serialize};

/// The full config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// IMAP connection settings.
    pub imap: ImapConfig,
    /// SMTP connection settings (optional — required when `send_email` is enabled).
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// Security posture and overrides.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Numeric limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Audit log settings.
    pub audit: AuditConfig,
    /// Attachment download settings.
    #[serde(default)]
    pub attachments: AttachmentsConfig,
}

/// `[imap]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImapConfig {
    /// Server host.
    pub host: String,
    /// Server port (IMAPS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Optional pinned TLS certificate SHA-256 fingerprint. Hex, colons
    /// optional (e.g. `"ab:cd:…"` or `"abcd…"`).
    #[serde(default)]
    pub tls_fingerprint_sha256: Option<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake + greeting + CAPABILITY probe deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}

fn default_command_timeout() -> u32 {
    30
}

fn default_connect_timeout() -> u32 {
    10
}

/// SMTP encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// STARTTLS upgrade on port 587.
    Starttls,
    /// Implicit TLS on port 465.
    Tls,
    /// No encryption (testing only).
    None,
}

/// `[smtp]` block. Optional — required only when `send_email` is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 465 for implicit TLS).
    pub port: u16,
    /// Encryption mode.
    pub encryption: SmtpEncryption,
    /// SMTP username.
    pub username: String,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}

/// Override verdict for a per-tool override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Tool is allowed regardless of posture.
    Allow,
    /// Tool is denied regardless of posture.
    Deny,
}

/// `[security]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Base posture.
    #[serde(default)]
    pub posture: Posture,
    /// Per-tool overrides, keyed by raw TOML tool name. Resolved to
    /// [`rimap_core::tool::ToolName`] during validation.
    #[serde(default)]
    pub tools: BTreeMap<String, Verdict>,
    /// Folders that cannot be deleted or renamed. Case-insensitive matching.
    #[serde(default = "default_protected_folders")]
    pub protected_folders: Vec<String>,
    /// Folders where `expunge` and `delete_folder` are permitted.
    #[serde(default)]
    pub expunge_folders: Vec<String>,
    /// Look-alike detection settings (placeholder for Sprint 4).
    #[serde(default)]
    pub lookalike: LookalikeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            posture: Posture::default(),
            tools: BTreeMap::new(),
            protected_folders: default_protected_folders(),
            expunge_folders: Vec::new(),
            lookalike: LookalikeConfig::default(),
        }
    }
}

fn default_protected_folders() -> Vec<String> {
    vec![
        "INBOX".to_string(),
        "Sent".to_string(),
        "Drafts".to_string(),
        "Trash".to_string(),
    ]
}

/// `[security.lookalike]` block. Shape only; Sprint 4 owns semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookalikeConfig {
    /// Whether look-alike detection is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// User-curated watchlist of protected domains.
    #[serde(default)]
    pub known_domains: Vec<String>,
    /// Warn on any non-ASCII domain, even if not in the watchlist.
    #[serde(default)]
    pub warn_on_any_non_ascii_domain: bool,
}

impl Default for LookalikeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            known_domains: Vec::new(),
            warn_on_any_non_ascii_domain: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// `[limits]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Default search result limit.
    #[serde(default = "default_max_search")]
    pub max_search_results: u32,
    /// Hard cap on `max_search_results`.
    #[serde(default = "default_max_search_cap")]
    pub max_search_results_cap: u32,
    /// Max fetched body bytes per message.
    #[serde(default = "default_max_body")]
    pub max_fetch_body_bytes: u64,
    /// Max attachment bytes.
    #[serde(default = "default_max_attach")]
    pub max_attachment_bytes: u64,
    /// Max APPEND message bytes.
    #[serde(default = "default_max_append")]
    pub max_append_bytes: u64,
    /// Rate limiter: commands per second.
    #[serde(default = "default_cps")]
    pub commands_per_second: u32,
    /// Per-minute draft creation cap.
    #[serde(default = "default_drafts_per_min")]
    pub drafts_per_minute: u32,
    /// Per-minute email send cap.
    #[serde(default = "default_sends_per_min")]
    pub sends_per_minute: u32,
    /// Circuit breaker error threshold within the window.
    #[serde(default = "default_breaker_threshold")]
    pub circuit_breaker_error_threshold: u32,
    /// Circuit breaker window in seconds.
    #[serde(default = "default_breaker_window")]
    pub circuit_breaker_window_seconds: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_search_results: default_max_search(),
            max_search_results_cap: default_max_search_cap(),
            max_fetch_body_bytes: default_max_body(),
            max_attachment_bytes: default_max_attach(),
            max_append_bytes: default_max_append(),
            commands_per_second: default_cps(),
            drafts_per_minute: default_drafts_per_min(),
            sends_per_minute: default_sends_per_min(),
            circuit_breaker_error_threshold: default_breaker_threshold(),
            circuit_breaker_window_seconds: default_breaker_window(),
        }
    }
}

fn default_max_search() -> u32 {
    200
}
fn default_max_search_cap() -> u32 {
    1000
}
fn default_max_body() -> u64 {
    5_242_880
}
fn default_max_attach() -> u64 {
    26_214_400
}
fn default_max_append() -> u64 {
    10_485_760
}
fn default_cps() -> u32 {
    10
}
fn default_drafts_per_min() -> u32 {
    5
}
fn default_sends_per_min() -> u32 {
    3
}
fn default_breaker_threshold() -> u32 {
    5
}
fn default_breaker_window() -> u32 {
    30
}

/// `[audit]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Path to the audit log file.
    pub path: PathBuf,
    /// Rotate when the file reaches this many bytes.
    #[serde(default = "default_rotate_bytes")]
    pub rotate_bytes: u64,
    /// Number of rotated files to keep on disk after a rotation. This is
    /// a count-based cap. For time-based expiry, also set
    /// `retention_seconds`. A rotated file is kept only if it is among
    /// the newest `rotate_keep` AND within the retention window.
    /// Default: 5.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Optional time-based retention in seconds. When set, rotated siblings
    /// whose mtime is older than `now - retention_seconds` are deleted during
    /// pruning, in addition to the count-based `rotate_keep` cap. A file is
    /// kept only if it is among the newest `rotate_keep` AND within the
    /// retention window. `None` (the default) disables time-based expiry.
    /// `Some(0)` is rejected at validation — use `None` instead.
    #[serde(default)]
    pub retention_seconds: Option<u64>,
    /// Provenance ring buffer window in seconds.
    #[serde(default = "default_provenance_window")]
    pub provenance_window_seconds: u32,
    /// If true, continue on audit write failure (insecure; default false).
    #[serde(default)]
    pub fail_open: bool,
    /// Optional containment base for `audit.path`. When set, the
    /// audit path must canonicalize to a path under this base, or
    /// config validation fails. When `None`, the default is
    /// `$XDG_STATE_HOME/rusty-imap-mcp/` (or platform equivalent via
    /// `directories::ProjectDirs::data_local_dir`). Set to
    /// `allowed_base_dir = "/"` to opt out of containment entirely
    /// (NOT recommended).
    #[serde(default)]
    pub allowed_base_dir: Option<PathBuf>,
}

fn default_rotate_bytes() -> u64 {
    10_485_760
}
fn default_rotate_keep() -> u32 {
    5
}
fn default_provenance_window() -> u32 {
    60
}

/// `[attachments]` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentsConfig {
    /// Download directory. Empty = per-session tempdir.
    #[serde(default)]
    pub download_dir: String,
}
