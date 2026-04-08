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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Base posture.
    #[serde(default)]
    pub posture: Posture,
    /// Per-tool overrides, keyed by raw TOML tool name. Resolved to
    /// [`rimap_core::tool::ToolName`] during validation.
    #[serde(default)]
    pub tools: BTreeMap<String, Verdict>,
    /// Look-alike detection settings (placeholder for Sprint 4).
    #[serde(default)]
    pub lookalike: LookalikeConfig,
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
    /// Rate limiter: commands per second.
    #[serde(default = "default_cps")]
    pub commands_per_second: u32,
    /// Per-minute draft creation cap.
    #[serde(default = "default_drafts_per_min")]
    pub drafts_per_minute: u32,
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
            commands_per_second: default_cps(),
            drafts_per_minute: default_drafts_per_min(),
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
fn default_cps() -> u32 {
    10
}
fn default_drafts_per_min() -> u32 {
    5
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
    /// Number of rotated files to keep.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Provenance ring buffer window in seconds.
    #[serde(default = "default_provenance_window")]
    pub provenance_window_seconds: u32,
    /// If true, continue on audit write failure (insecure; default false).
    #[serde(default)]
    pub fail_open: bool,
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
