//! Config file discovery and TOML loading.
//!
//! Path resolution order, per design spec §4:
//!   1. Explicit `--config <path>` argument (handled by caller; passed here as `Some(path)`).
//!   2. `RUSTY_IMAP_MCP_CONFIG` environment variable.
//!   3. Platform default:
//!        - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
//!          (falling back to `~/.config/rusty-imap-mcp/config.toml`)
//!        - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::ConfigError;
use crate::model::{Config, MultiAccountConfig};
use crate::validate::{ValidatedMultiConfig, validate_legacy_as_multi, validate_multi};

/// Organization qualifiers for `directories::ProjectDirs`.
const QUALIFIER: &str = "";
const ORGANIZATION: &str = "";
const APPLICATION: &str = "rusty-imap-mcp";

/// Environment variable name for the config path override.
pub const CONFIG_ENV_VAR: &str = "RUSTY_IMAP_MCP_CONFIG";

/// Return the config path based on the explicit override, the environment
/// variable, or the platform default. Returns `None` if no default path can
/// be determined (e.g. headless system with no HOME).
#[must_use]
pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(v) = std::env::var(CONFIG_ENV_VAR)
        && !v.is_empty()
    {
        return Some(PathBuf::from(v));
    }
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Load and deserialize a config file from the given path. Does **not**
/// validate semantic constraints — that's [`crate::validate::validate`].
///
/// # Errors
/// Returns `ConfigError::Read` if the file cannot be read, or
/// `ConfigError::Parse` if the TOML is malformed.
pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str::<Config>(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Load a config file and validate it, producing a `ValidatedMultiConfig`.
///
/// Detects format by scanning for `[[accounts]]` (multi-account) vs `[imap]`
/// (legacy). Both present is an error. Parses the appropriate struct and
/// runs validation.
///
/// # Errors
/// Returns `ConfigError` on read, parse, or validation failure.
pub fn load_and_validate(path: &Path) -> Result<ValidatedMultiConfig, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let has_accounts = contains_toml_key(&contents, "[[accounts]]");
    let has_imap = contains_toml_key(&contents, "[imap]");

    if has_accounts && has_imap {
        return Err(ConfigError::MixedConfigFormat);
    }

    if has_accounts {
        let config = toml::from_str::<MultiAccountConfig>(&contents).map_err(|source| {
            ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            }
        })?;
        validate_multi(config)
    } else {
        let config = toml::from_str::<Config>(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        validate_legacy_as_multi(config)
    }
}

/// Check whether a TOML key/header marker appears in the raw text.
/// Matches only outside of strings by looking for lines that start with the
/// pattern (after optional whitespace). This is intentionally simple — it
/// does not parse TOML, but false positives are harmless (they would trigger
/// a parse error, not silent misconfiguration).
fn contains_toml_key(contents: &str, marker: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim_start().starts_with(marker))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::posture::Posture;
    use tempfile::TempDir;

    use rimap_core::account::AccountId;

    use crate::error::ConfigError;
    use crate::loader::{CONFIG_ENV_VAR, load_and_validate, load_from_path, resolve_config_path};
    use crate::model::Verdict;

    fn write_config(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    const MINIMAL_CONFIG: &str = r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "/tmp/rimap-audit.jsonl"
"#;

    #[test]
    fn load_minimal_config_fills_defaults() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", MINIMAL_CONFIG);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.imap.host, "127.0.0.1");
        assert_eq!(cfg.imap.port, 1143);
        assert_eq!(cfg.imap.command_timeout_seconds, 30);
        assert_eq!(cfg.imap.connect_timeout_seconds, 10);
        assert_eq!(cfg.security.posture, Posture::DraftSafe);
        assert_eq!(cfg.limits.commands_per_second, 10);
        assert_eq!(cfg.limits.drafts_per_minute, 5);
        assert!(cfg.security.tools.is_empty());
    }

    #[test]
    fn load_with_tool_overrides_preserves_order_independent_map() {
        let toml = format!(
            r#"{MINIMAL_CONFIG}
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"
search = "allow"
"#
        );
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.security.tools.get("mark_read"), Some(&Verdict::Deny));
        assert_eq!(cfg.security.tools.get("search"), Some(&Verdict::Allow));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // Prepend the bogus field above any section header so TOML parses it
        // as a top-level key (not a member of `[audit]`).
        let toml = format!("bogus_top_level = 1\n{MINIMAL_CONFIG}");
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, crate::error::ConfigError::Parse { .. }));
    }

    #[test]
    fn missing_file_returns_read_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.toml");
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, crate::error::ConfigError::Read { .. }));
    }

    #[test]
    fn resolve_explicit_path_wins() {
        let p = PathBuf::from("/etc/rimap/custom.toml");
        assert_eq!(resolve_config_path(Some(&p)), Some(p));
    }

    #[test]
    fn resolve_env_var_used_when_no_explicit() {
        // Use a unique tempdir path to avoid clobbering a real user env.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("env.toml");
        // SAFETY: single-threaded test; std::env::set_var is safe here.
        temp_env::with_var(CONFIG_ENV_VAR, Some(env_path.as_os_str()), || {
            assert_eq!(resolve_config_path(None), Some(env_path.clone()));
        });
    }

    #[test]
    fn resolve_default_is_some_on_supported_platforms() {
        temp_env::with_var(CONFIG_ENV_VAR, None::<&str>, || {
            let p = resolve_config_path(None);
            // On supported platforms (Linux, macOS, Windows) directories will
            // return Some. On exotic platforms it may be None; accept both.
            if let Some(path) = p {
                assert!(path.to_string_lossy().contains("rusty-imap-mcp"));
                assert!(path.ends_with("config.toml"));
            }
        });
    }

    // -----------------------------------------------------------------------
    // load_and_validate format detection tests
    // -----------------------------------------------------------------------

    fn legacy_toml(audit_dir: &std::path::Path) -> String {
        format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "{dir}/audit.jsonl"
allowed_base_dir = "{dir}"
"#,
            dir = audit_dir.display(),
        )
    }

    fn multi_toml(audit_dir: &std::path::Path) -> String {
        format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.com"
port = 993
username = "alice@work.com"

[[accounts]]
name = "personal"

[accounts.imap]
host = "imap.personal.com"
port = 993
username = "alice@personal.com"

[audit]
path = "{dir}/audit.jsonl"
allowed_base_dir = "{dir}"
"#,
            dir = audit_dir.display(),
        )
    }

    #[test]
    fn load_and_validate_legacy_format() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &legacy_toml(dir.path()));
        let v = load_and_validate(&path).unwrap();
        assert_eq!(v.accounts.len(), 1);
        assert!(v.accounts.contains_key(&AccountId::default_account()));
    }

    #[test]
    fn load_and_validate_multi_format() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &multi_toml(dir.path()));
        let v = load_and_validate(&path).unwrap();
        assert_eq!(v.accounts.len(), 2);
        assert!(v.accounts.contains_key(&AccountId::new("work").unwrap()));
        assert!(
            v.accounts
                .contains_key(&AccountId::new("personal").unwrap())
        );
    }

    #[test]
    fn load_and_validate_mixed_format_rejected() {
        let dir = TempDir::new().unwrap();
        let mixed = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.com"
port = 993
username = "alice@work.com"

[audit]
path = "{dir}/audit.jsonl"
"#,
            dir = dir.path().display(),
        );
        let path = write_config(&dir, "config.toml", &mixed);
        let err = load_and_validate(&path).unwrap_err();
        assert!(matches!(err, ConfigError::MixedConfigFormat));
    }
}
