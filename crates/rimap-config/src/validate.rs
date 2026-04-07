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
use std::path::Path;
use std::str::FromStr;

use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{Config, Verdict};

/// Validated config: a `Config` plus the resolved per-tool override map
/// keyed by `ToolName` instead of raw string.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The underlying parsed config (untouched).
    pub config: Config,
    /// Resolved per-tool overrides.
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
}

/// Validate a parsed config and resolve override tool names.
///
/// # Errors
/// Returns `ConfigError` on any validation failure.
pub fn validate(config: Config) -> Result<ValidatedConfig, ConfigError> {
    validate_fingerprint(config.imap.tls_fingerprint_sha256.as_deref())?;
    validate_limits(&config)?;
    validate_paths(&config)?;
    let tool_overrides = resolve_tool_overrides(&config)?;
    Ok(ValidatedConfig {
        config,
        tool_overrides,
    })
}

fn validate_fingerprint(maybe_fp: Option<&str>) -> Result<(), ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(());
    };
    let cleaned: String = raw.chars().filter(|c| *c != ':').collect();
    if cleaned.len() != 64 {
        return Err(ConfigError::TlsFingerprint {
            reason: format!("got {} hex chars (want 64)", cleaned.len()),
        });
    }
    for c in cleaned.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(ConfigError::TlsFingerprint {
                reason: format!("non-hex character `{c}`"),
            });
        }
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
    if !config.attachments.download_dir.is_empty() {
        require_writable_dir(Path::new(&config.attachments.download_dir))?;
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
    use rimap_core::tool::{ParseToolNameError, ToolName};
    use tempfile::TempDir;

    use crate::error::ConfigError;
    use crate::model::{
        AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, SecurityConfig, Verdict,
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
            },
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                provenance_window_seconds: 60,
                fail_open: false,
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
    fn override_v2_tool_fails_with_v2_error() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("delete_message".into(), Verdict::Allow);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ToolOverride(ParseToolNameError::V2(_))
        ));
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
}
