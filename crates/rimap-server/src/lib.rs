//! Library crate for the rusty-imap-mcp binary.
//!
//! The modules are exposed with `#[doc(hidden)] pub` so that the
//! binary entry point (`main.rs`) and integration tests in
//! `tests/` can reach internal types, without advertising a stable
//! library API. External consumers should not depend on this
//! surface — it is an implementation detail.
//!
//! # Submodule visibility convention
//!
//! Inside the top-level subfolders (`boot/`, `daemon/`, `mcp/`,
//! `tools/`), child modules use `pub mod` whenever any integration
//! test (the only out-of-crate consumer) needs to reach them, and
//! `pub(crate) mod` otherwise. The whole tree is `#[doc(hidden)]`
//! through the wrappers above, so the `pub` does not advertise a
//! stable library API — it just keeps integration-test reach
//! working without stamping `#[cfg(test)] pub use` re-exports
//! everywhere. New modules should default to `pub(crate) mod` and
//! switch to `pub mod` only when an integration test imports them.

#![deny(missing_docs)]

#[doc(hidden)]
pub mod boot;
#[doc(hidden)]
pub mod daemon;
#[doc(hidden)]
pub mod mcp;
#[doc(hidden)]
pub mod shim;
#[doc(hidden)]
pub mod tools;

/// Elapsed milliseconds since `start`, saturating at `u64::MAX`. Audit
/// records carry `duration_ms` as `u64`; the saturation handles the
/// theoretically-possible overflow when an `Instant` delta exceeds ~584
/// million years without requiring each call site to re-justify its
/// `.unwrap_or(u64::MAX)`.
#[must_use]
pub(crate) fn duration_ms_since(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Resolve the attachment download directory from a multi-account config.
///
/// If `attachments.download_dir` is set, the path is created (if needed) and
/// locked down to 0700 on Unix. Otherwise a per-process tempdir is created
/// via `tempfile` (TOCTOU-safe) and then locked down to 0700 on Unix. The
/// per-process dir is intentionally leaked (no automatic cleanup) so that
/// downloaded attachments remain readable for the server's lifetime.
///
/// # Errors
///
/// Returns an error if directory creation, permission tightening, or
/// tempdir construction fails.
pub fn resolve_download_dir_multi(
    multi: &rimap_config::validate::ValidatedMultiConfig,
) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context as _;

    let dir_str = &multi.attachments.download_dir;
    if !dir_str.is_empty() {
        let dir = std::path::PathBuf::from(dir_str);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating attachment download_dir at {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
        }
        return Ok(dir);
    }

    let dir = tempfile::Builder::new()
        .prefix("rusty-imap-mcp-")
        .tempdir()
        .context("creating per-process tempdir for attachments")?
        .keep();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
    }
    Ok(dir)
}

#[cfg(all(test, unix))]
#[expect(clippy::expect_used, reason = "tests")]
mod resolve_download_dir_tests {
    use super::resolve_download_dir_multi;
    use rimap_config::model::{AttachmentsConfig, AuditConfig, DaemonConfig};
    use rimap_config::validate::ValidatedMultiConfig;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn minimal_multi(download_dir: String) -> ValidatedMultiConfig {
        ValidatedMultiConfig {
            accounts: BTreeMap::new(),
            audit: AuditConfig {
                path: PathBuf::from("/tmp/unused-audit.log"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: None,
            },
            attachments: AttachmentsConfig { download_dir },
            daemon: DaemonConfig::default(),
        }
    }

    #[test]
    fn default_tempdir_has_0700_perms() {
        let multi = minimal_multi(String::new());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        let meta = std::fs::metadata(&dir).expect("metadata");
        assert!(meta.is_dir(), "expected a directory at {}", dir.display());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_dir_is_locked_down_to_0700() {
        let base = tempfile::tempdir().expect("tempdir");
        let target = base.path().join("attachments");
        let multi = minimal_multi(target.to_string_lossy().into_owned());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        assert_eq!(dir, target);
        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
    }
}
