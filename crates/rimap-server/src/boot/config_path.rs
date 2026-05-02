//! Resolve a config-file path from `--config` overrides or the
//! `RUSTY_IMAP_MCP_CONFIG` env var / platform default.

use std::path::PathBuf;

use rimap_config::loader::resolve_config_path;

/// Resolve a config-file path from an explicit `--config` override,
/// falling back to `RUSTY_IMAP_MCP_CONFIG` / the platform default via
/// [`resolve_config_path`].
///
/// # Errors
///
/// Returns an actionable error when neither an explicit path nor the env
/// var resolve.
pub fn resolve(override_: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    override_
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use super::resolve;

    #[test]
    fn override_path_wins_over_env() {
        let explicit = PathBuf::from("/tmp/custom.toml");
        let got = resolve(Some(explicit.clone())).unwrap();
        assert_eq!(got, explicit);
    }

    #[test]
    fn no_override_no_env_error_message_is_actionable() {
        // We cannot force resolve_config_path to return None on a host where
        // ProjectDirs::from succeeds — on Linux it falls back to /etc/passwd
        // via getpwuid when HOME is unset, so there's no env-var combo that
        // disables it. When it *does* return None (headless / unusual passwd
        // configs), the error surface must name the fix the user should take.
        temp_env::with_var("RUSTY_IMAP_MCP_CONFIG", None::<&str>, || {
            if let Err(e) = resolve(None) {
                let msg = e.to_string();
                assert!(msg.contains("--config"), "error lacks --config hint: {msg}");
                assert!(
                    msg.contains("RUSTY_IMAP_MCP_CONFIG"),
                    "error lacks env-var hint: {msg}",
                );
            }
        });
    }
}
