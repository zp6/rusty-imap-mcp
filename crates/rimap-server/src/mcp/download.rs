//! Attachment download sandboxing.
//!
//! Validates download destinations against an allowed root directory,
//! writes attachment data with collision-safe filenames, and provides
//! MIME sniffing and SHA-256 hashing utilities.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rimap_core::RimapError;

/// Resolve and validate the download destination.
///
/// If `dest_dir` is provided, canonicalize it and verify it starts
/// with `allowed_root`. If absent, use `fallback_dir`.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when the
/// user-supplied `dest_dir` cannot be canonicalized (missing path,
/// permission denied) or when the canonical form falls outside
/// `allowed_root`.
pub(crate) fn resolve_dest_dir(
    dest_dir: Option<&str>,
    allowed_root: &Path,
    fallback_dir: &Path,
) -> Result<PathBuf, RimapError> {
    let dir = match dest_dir {
        Some(d) => {
            let p = PathBuf::from(d);
            let canonical = p
                .canonicalize()
                .map_err(|e| RimapError::invalid_input(format!("cannot resolve dest_dir: {e}")))?;
            if !canonical.starts_with(allowed_root) {
                return Err(RimapError::invalid_input(
                    "dest_dir is outside allowed download directory",
                ));
            }
            canonical
        }
        None => fallback_dir.to_path_buf(),
    };
    Ok(dir)
}

/// Write `data` to `dir/filename`, de-duplicating on collision.
/// Returns the final path.
///
/// # Errors
///
/// Returns `RimapError::Internal` if writing fails or if more than
/// 1000 filename collisions occur.
pub(crate) fn write_attachment(
    dir: &Path,
    filename: &str,
    data: &[u8],
) -> Result<PathBuf, RimapError> {
    // Strip path components to prevent directory traversal.
    let safe_name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment");

    let base = Path::new(safe_name);
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let ext = base.extension().and_then(|s| s.to_str());

    let mut path = dir.join(safe_name);
    let mut counter = 1u32;
    while path.exists() {
        let new_name = match ext {
            Some(e) => format!("{stem}_{counter}.{e}"),
            None => format!("{stem}_{counter}"),
        };
        path = dir.join(new_name);
        counter += 1;
        if counter > 1000 {
            return Err(RimapError::Internal("too many filename collisions".into()));
        }
    }

    // The filename has already been stripped to its final component
    // above, so `path` is always `dir/<safe_name>`. Directory-traversal
    // containment is enforced by `resolve_dest_dir` for the initial
    // `dir`, not here — a re-canonicalize at this point compares `dir`
    // against itself and cannot fail meaningfully.
    std::fs::write(&path, data).map_err(|e| RimapError::InternalSourced {
        message: "failed to write attachment".into(),
        source: Box::new(e),
    })?;

    Ok(path)
}

/// Async wrapper around [`resolve_dest_dir`] that runs on a
/// blocking thread.
///
/// # Errors
///
/// Propagates whatever [`resolve_dest_dir`] returns (typically
/// `RimapError::Authz` with `InvalidInput` when the path cannot be
/// canonicalized or escapes `allowed_root`). Returns
/// `RimapError::Internal` if the blocking task panics.
pub async fn resolve_dest_dir_async(
    dest_dir: Option<String>,
    root: Arc<Path>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || resolve_dest_dir(dest_dir.as_deref(), &root, &root))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// Async wrapper around [`write_attachment`] that runs on a
/// blocking thread.
///
/// # Errors
///
/// Propagates whatever [`write_attachment`] returns
/// (`RimapError::Internal` on I/O failure or after >1000 filename
/// collisions). Also returns `RimapError::Internal` if the blocking
/// task panics.
pub async fn write_attachment_async(
    dir: PathBuf,
    filename: String,
    data: Vec<u8>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || write_attachment(&dir, &filename, &data))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// MIME-sniff `data` using magic bytes.
#[must_use]
pub fn sniff_mime(data: &[u8]) -> Option<String> {
    infer::get(data).map(|t| t.mime_type().to_string())
}

/// SHA-256 hex digest.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn resolve_dest_dir_uses_fallback_when_none() {
        let fallback = PathBuf::from("/tmp/fallback");
        let allowed = Path::new("/tmp");
        let result = resolve_dest_dir(None, allowed, &fallback).unwrap();
        assert_eq!(result, fallback);
    }

    #[test]
    fn resolve_dest_dir_accepts_valid_path() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let allowed = tmp.path();
        let fallback = tmp.path();
        let result = resolve_dest_dir(Some(sub.to_str().unwrap()), allowed, fallback).unwrap();
        assert!(result.starts_with(allowed));
    }

    #[test]
    fn resolve_dest_dir_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("sandbox");
        std::fs::create_dir_all(&allowed).unwrap();
        // Try to escape to the parent.
        let err =
            resolve_dest_dir(Some(tmp.path().to_str().unwrap()), &allowed, &allowed).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(err.to_string().contains("outside allowed"));
    }

    #[test]
    fn resolve_dest_dir_invalid_path_returns_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("sandbox");
        std::fs::create_dir_all(&allowed).unwrap();
        // Non-existent dest_dir cannot be canonicalized.
        let bogus = tmp.path().join("does/not/exist");
        let err = resolve_dest_dir(Some(bogus.to_str().unwrap()), &allowed, &allowed).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn write_attachment_normal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "doc.pdf", b"data").unwrap();
        assert_eq!(path, tmp.path().join("doc.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[test]
    fn write_attachment_collision() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("doc.pdf"), b"old").unwrap();
        let path = write_attachment(tmp.path(), "doc.pdf", b"new").unwrap();
        assert_eq!(path, tmp.path().join("doc_1.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn write_attachment_no_extension() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme"), b"old").unwrap();
        let path = write_attachment(tmp.path(), "readme", b"new").unwrap();
        assert_eq!(path, tmp.path().join("readme_1"));
    }

    #[test]
    fn write_attachment_rejects_relative_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "../escape.txt", b"data").unwrap();
        // Must land inside tmp, not escape.
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "escape.txt");
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[test]
    fn write_attachment_rejects_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "/etc/passwd", b"data").unwrap();
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "passwd");
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[test]
    fn write_attachment_handles_deep_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "../../.ssh/authorized_keys", b"data").unwrap();
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "authorized_keys");
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256 of empty input.
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934\
             ca495991b7852b855"
        );
    }

    #[test]
    fn sniff_mime_detects_png() {
        // Minimal PNG header.
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = sniff_mime(&png_header);
        assert_eq!(result.as_deref(), Some("image/png"));
    }

    #[test]
    fn sniff_mime_returns_none_for_unknown() {
        assert!(sniff_mime(b"hello world").is_none());
    }
}
