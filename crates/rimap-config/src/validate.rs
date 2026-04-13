//! Config validation. Runs as a separate pass after `loader::load_from_path`.
//!
//! Checks (per design spec §4 "Config validation at startup"):
//!   - Posture is a known value (enforced by enum parsing — trivially true).
//!   - Every override tool name is a known v1 tool.
//!   - TLS fingerprint parses as 32 hex bytes.
//!   - Audit directory exists and is writable (parent dir of `audit.path`).
//!   - Attachment download dir, if non-empty, is writable.
//!   - All numeric limits are positive and cap/default invariants hold.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rimap_core::tls::TlsFingerprint;
use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{Config, SmtpEncryption, Verdict};

/// Validated config: a `Config` plus the resolved per-tool override map
/// keyed by `ToolName`, plus the parsed TLS fingerprint (if any).
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The underlying parsed config (untouched).
    pub config: Config,
    /// Resolved per-tool overrides.
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
    /// Parsed pinned TLS fingerprint, if `imap.tls_fingerprint_sha256` was set.
    pub tls_fingerprint: Option<TlsFingerprint>,
}

/// Validate a parsed config and resolve override tool names.
///
/// # Errors
/// Returns `ConfigError` on any validation failure.
pub fn validate(config: Config) -> Result<ValidatedConfig, ConfigError> {
    let tls_fingerprint = parse_fingerprint(config.imap.tls_fingerprint_sha256.as_deref())?;
    validate_limits(&config)?;
    validate_audit(&config)?;
    validate_paths(&config)?;
    validate_folder_safety(&config)?;
    let tool_overrides = resolve_tool_overrides(&config)?;
    validate_smtp_required(&config, &tool_overrides)?;
    validate_smtp_encryption(&config)?;
    Ok(ValidatedConfig {
        config,
        tool_overrides,
        tls_fingerprint,
    })
}

fn parse_fingerprint(maybe_fp: Option<&str>) -> Result<Option<TlsFingerprint>, ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(None);
    };
    let fp = TlsFingerprint::from_hex(raw).map_err(|e| ConfigError::TlsFingerprint {
        reason: e.to_string(),
    })?;
    Ok(Some(fp))
}

fn validate_audit(config: &Config) -> Result<(), ConfigError> {
    if config.audit.retention_seconds == Some(0) {
        return Err(ConfigError::InvalidLimit {
            field: "audit.retention_seconds",
            reason: "must be > 0 (use None / omit the field to disable \
                     time-based retention)"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_limits(config: &Config) -> Result<(), ConfigError> {
    let limits = &config.limits;
    if limits.commands_per_second == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.commands_per_second",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.drafts_per_minute == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.drafts_per_minute",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.sends_per_minute == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.sends_per_minute",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.circuit_breaker_error_threshold == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.circuit_breaker_error_threshold",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.circuit_breaker_window_seconds == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.circuit_breaker_window_seconds",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_search_results == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_search_results > limits.max_search_results_cap {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: format!(
                "default {} exceeds cap {}",
                limits.max_search_results, limits.max_search_results_cap
            ),
        });
    }
    if limits.max_fetch_body_bytes == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_fetch_body_bytes",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_attachment_bytes == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_attachment_bytes",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_append_bytes == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_append_bytes",
            reason: "must be > 0".to_string(),
        });
    }
    Ok(())
}

fn validate_paths(config: &Config) -> Result<(), ConfigError> {
    let audit_parent = config
        .audit
        .path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: config.audit.path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    require_writable_dir(audit_parent)?;
    enforce_audit_containment(config)?;
    if !config.attachments.download_dir.is_empty() {
        require_writable_dir(Path::new(&config.attachments.download_dir))?;
    }
    Ok(())
}

/// Compute the default audit base when `audit.allowed_base_dir` is unset.
/// Returns `$XDG_STATE_HOME/rusty-imap-mcp/` on platforms where
/// `directories::ProjectDirs` resolves; returns `None` otherwise (which
/// causes the containment check to fail with a clear error).
/// Compute the default audit base when `audit.allowed_base_dir` is unset.
/// Returns `$XDG_STATE_HOME/rusty-imap-mcp/` on platforms where
/// `directories::ProjectDirs` resolves; returns `None` otherwise (which
/// causes the containment check to fail with a clear error).
///
/// ## macOS Time Machine caveat (LOCAL-PRI-06)
///
/// On macOS, `ProjectDirs::data_local_dir()` resolves to
/// `~/Library/Application Support/rusty-imap-mcp/`, which is covered by
/// Time Machine backups by default. The audit log appears in every
/// backup snapshot and is readable from any restore. A stolen laptop or
/// stolen Time Machine disk gives cold-attacker access to the full audit
/// history even if the live process was never touched.
///
/// The backup-exclude xattr fix (setting
/// `com.apple.metadata:com_apple_backup_excludeItem` on the audit path)
/// is tracked in issue #45. Until that lands, operators on macOS should
/// either (a) set `audit.allowed_base_dir` explicitly to a path that
/// Time Machine does not back up (e.g., under `~/Library/Caches/`), or
/// (b) manually exclude `~/Library/Application Support/rusty-imap-mcp/`
/// via `tmutil addexclusion`.
fn default_audit_base() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "rusty-imap-mcp")?;
    Some(dirs.data_local_dir().to_path_buf())
}

/// Canonicalize the audit path and verify it is contained in the allowed
/// base. Called after `require_writable_dir` so the parent dir is known to
/// exist. The parent is canonicalized first (not the path itself, which
/// may not exist yet), then joined with the file name to produce the
/// canonical audit path.
fn enforce_audit_containment(config: &Config) -> Result<(), ConfigError> {
    let audit_path = &config.audit.path;
    let parent = audit_path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    let canon_parent = std::fs::canonicalize(parent).map_err(|e| ConfigError::PathNotWritable {
        path: parent.to_path_buf(),
        reason: format!("canonicalize parent: {e}"),
    })?;
    let file_name = audit_path
        .file_name()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no file name".to_string(),
        })?;
    let canon_path = canon_parent.join(file_name);

    let base = config
        .audit
        .allowed_base_dir
        .clone()
        .or_else(default_audit_base)
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "no allowed_base_dir configured and platform default unavailable".to_string(),
        })?;
    let canon_base = std::fs::canonicalize(&base).map_err(|e| ConfigError::PathNotWritable {
        path: base.clone(),
        reason: format!("canonicalize allowed_base_dir: {e}"),
    })?;

    if !canon_path.starts_with(&canon_base) {
        return Err(ConfigError::AuditPathOutsideBase {
            path: canon_path,
            base: canon_base,
        });
    }
    Ok(())
}

fn require_writable_dir(dir: &Path) -> Result<(), ConfigError> {
    if !dir.exists() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory does not exist".to_string(),
        });
    }
    let meta = std::fs::metadata(dir).map_err(|e| ConfigError::PathNotWritable {
        path: dir.to_path_buf(),
        reason: format!("stat failed: {e}"),
    })?;
    if !meta.is_dir() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "not a directory".to_string(),
        });
    }
    if meta.permissions().readonly() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory is read-only".to_string(),
        });
    }
    Ok(())
}

fn validate_folder_safety(config: &Config) -> Result<(), ConfigError> {
    let mut protected: Vec<String> = config
        .security
        .protected_folders
        .iter()
        .map(|f| utf7_imap::decode_utf7_imap(f.clone()).to_lowercase())
        .collect();
    protected.push("inbox".to_string());

    for folder in &config.security.expunge_folders {
        let norm = utf7_imap::decode_utf7_imap(folder.clone()).to_lowercase();
        if protected.contains(&norm) {
            return Err(ConfigError::ConflictingFolders {
                folder: folder.clone(),
            });
        }
    }
    Ok(())
}

fn validate_smtp_required(
    config: &Config,
    tool_overrides: &BTreeMap<ToolName, Verdict>,
) -> Result<(), ConfigError> {
    let posture = config.security.posture;
    let send_email_base = rimap_core::base_allows(posture, ToolName::SendEmail);
    let send_email_effective = match tool_overrides.get(&ToolName::SendEmail) {
        Some(Verdict::Allow) => true,
        Some(Verdict::Deny) => false,
        None => send_email_base,
    };
    if send_email_effective && config.smtp.is_none() {
        return Err(ConfigError::SmtpRequired {
            posture: posture.to_string(),
        });
    }
    Ok(())
}

fn validate_smtp_encryption(config: &Config) -> Result<(), ConfigError> {
    let Some(smtp) = &config.smtp else {
        return Ok(());
    };
    if smtp.encryption == SmtpEncryption::None {
        let host = &smtp.host;
        let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
        if !is_localhost {
            return Err(ConfigError::SmtpPlaintextDenied { host: host.clone() });
        }
    }
    Ok(())
}

fn resolve_tool_overrides(config: &Config) -> Result<BTreeMap<ToolName, Verdict>, ConfigError> {
    let mut out = BTreeMap::new();
    for (name, verdict) in &config.security.tools {
        let tool = ToolName::from_str(name)?;
        out.insert(tool, *verdict);
    }
    Ok(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use rimap_core::posture::Posture;
    use rimap_core::tool::{ParseToolNameError, ToolName};
    use tempfile::TempDir;

    use crate::error::ConfigError;
    use crate::model::{
        AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, SecurityConfig,
        SmtpEncryption, Verdict,
    };
    use crate::validate::validate;

    fn base_config(audit_dir: &std::path::Path) -> Config {
        Config {
            imap: ImapConfig {
                host: "127.0.0.1".into(),
                port: 1143,
                username: "alice@example.test".into(),
                tls_fingerprint_sha256: None,
                command_timeout_seconds: 30,
                connect_timeout_seconds: 10,
            },
            smtp: None,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: Some(audit_dir.to_path_buf()),
            },
            attachments: AttachmentsConfig::default(),
        }
    }

    #[test]
    fn minimal_valid_config_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate(cfg).unwrap();
        assert!(v.tool_overrides.is_empty());
    }

    #[test]
    fn override_resolves_v1_tool_name() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.tools.insert("mark_read".into(), Verdict::Deny);
        cfg.security.tools.insert("search".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(
            v.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Deny)
        );
        assert_eq!(
            v.tool_overrides.get(&ToolName::Search),
            Some(&Verdict::Allow)
        );
    }

    #[test]
    fn override_unknown_tool_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("nuke_inbox".into(), Verdict::Deny);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ToolOverride(ParseToolNameError::Unknown(_))
        ));
    }

    #[test]
    fn override_v2_tool_resolves_successfully() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("delete_message".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(
            v.tool_overrides.get(&ToolName::DeleteMessage),
            Some(&Verdict::Allow)
        );
    }

    #[test]
    fn fingerprint_32_hex_bytes_with_colons_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some(
            "ab:cd:ef:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d"
                .into(),
        );
        validate(cfg).unwrap();
    }

    #[test]
    fn fingerprint_wrong_length_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("abcd".into());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn fingerprint_non_hex_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("z".repeat(64));
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn validate_returns_parsed_tls_fingerprint() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some(
            "0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef"
                .to_string(),
        );
        let validated = validate(cfg).unwrap();
        let Some(fp) = validated.tls_fingerprint else {
            panic!("fingerprint should be set");
        };
        assert_eq!(
            fp.to_hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn validate_returns_none_when_fingerprint_absent() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let validated = validate(cfg).unwrap();
        assert!(validated.tls_fingerprint.is_none());
    }

    #[test]
    fn validate_uses_default_connect_timeout_when_unset() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let validated = validate(cfg).unwrap();
        assert_eq!(validated.config.imap.connect_timeout_seconds, 10);
    }

    #[test]
    fn zero_commands_per_second_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.commands_per_second = 0;
        let err = validate(cfg).unwrap_err();
        match err {
            ConfigError::InvalidLimit { field, .. } => {
                assert_eq!(field, "limits.commands_per_second");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_drafts_per_minute_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.drafts_per_minute = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.drafts_per_minute",
                ..
            }
        ));
    }

    #[test]
    fn max_search_exceeds_cap_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.max_search_results = 5000;
        cfg.limits.max_search_results_cap = 1000;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.max_search_results",
                ..
            }
        ));
    }

    #[test]
    fn missing_audit_parent_dir_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        // Construct a guaranteed-nonexistent nested path under the tempdir.
        cfg.audit.path = dir.path().join("nope/nested/audit.jsonl");
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::PathNotWritable { .. }));
    }

    #[test]
    fn audit_path_inside_allowed_base_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        validate(cfg).unwrap();
    }

    #[test]
    fn audit_path_outside_allowed_base_fails() {
        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let mut cfg = base_config(outside.path());
        cfg.audit.allowed_base_dir = Some(base.path().to_path_buf());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn retention_seconds_zero_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.audit.retention_seconds = Some(0);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidLimit {
                field: "audit.retention_seconds",
                ..
            }
        ));
    }

    #[test]
    fn retention_seconds_nonzero_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.audit.retention_seconds = Some(3600);
        validate(cfg).unwrap();
    }

    #[test]
    fn smtp_section_parses_from_toml() {
        let toml_str = r#"
[imap]
host = "imap.example.com"
port = 993
username = "alice@example.com"

[smtp]
host = "smtp.example.com"
port = 587
encryption = "starttls"
username = "alice@example.com"

[audit]
path = "/tmp/audit.jsonl"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let smtp = cfg.smtp.as_ref().unwrap();
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.encryption, SmtpEncryption::Starttls);
    }

    #[test]
    fn config_without_smtp_section_is_valid() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        assert!(cfg.smtp.is_none());
        validate(cfg).unwrap();
    }

    #[test]
    fn audit_path_with_traversal_segments_is_canonicalized_before_containment() {
        let base = TempDir::new().unwrap();
        let nested = base.path().join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        let mut cfg = base_config(&nested);
        // Path with "../../" attempting to escape to the base's parent:
        cfg.audit.path = nested.join("..").join("..").join("escape.jsonl");
        cfg.audit.allowed_base_dir = Some(nested);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn smtp_required_when_send_email_enabled_by_posture() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
    }

    #[test]
    fn smtp_not_required_when_send_email_explicitly_denied() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.security
            .tools
            .insert("send_email".into(), Verdict::Deny);
        validate(cfg).unwrap();
    }

    #[test]
    fn smtp_not_required_for_draft_safe_posture() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        validate(cfg).unwrap();
    }

    #[test]
    fn conflicting_folders_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["Trash".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    #[test]
    fn non_overlapping_folders_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["INBOX".into(), "Sent".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        validate(cfg).unwrap();
    }

    #[test]
    fn conflicting_folders_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["trash".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    #[test]
    fn zero_sends_per_minute_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.sends_per_minute = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.sends_per_minute",
                ..
            }
        ));
    }

    #[test]
    fn smtp_plaintext_rejected_for_remote_host() {
        use crate::model::SmtpConfig;
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.smtp = Some(SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            encryption: SmtpEncryption::None,
            username: "user".into(),
            command_timeout_seconds: 30,
        });
        let result = validate(cfg);
        assert!(
            matches!(result, Err(ConfigError::SmtpPlaintextDenied { .. })),
            "expected SmtpPlaintextDenied, got {result:?}",
        );
    }

    #[test]
    fn smtp_plaintext_allowed_for_localhost() {
        use crate::model::SmtpConfig;
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.smtp = Some(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1025,
            encryption: SmtpEncryption::None,
            username: "user".into(),
            command_timeout_seconds: 30,
        });
        let result = validate(cfg);
        assert!(
            result.is_ok(),
            "localhost plaintext should be allowed: {result:?}",
        );
    }

    #[test]
    fn smtp_config_debug_redacts_username() {
        use crate::model::{SmtpConfig, SmtpEncryption};
        let cfg = SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            encryption: SmtpEncryption::Starttls,
            username: "secret_user@example.com".into(),
            command_timeout_seconds: 30,
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("secret_user"),
            "Debug output must not contain username: {debug}",
        );
    }
}
