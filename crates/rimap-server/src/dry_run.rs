//! `--dry-run` path: load + validate config, build effective matrix, print it
//! to stdout, exit 0.
//!
//! Stdout is reserved for MCP transport, but `--dry-run` is an *out-of-band*
//! mode that terminates the process before any MCP wiring happens, so writing
//! the matrix to stdout is both acceptable and the most useful destination
//! (it can be piped to `less`, etc.).
//!
//! Output format is stable text: one header line and one row per tool, in
//! declaration order. Sample:
//!
//! ```text
//! Effective matrix (posture = draft-safe)
//!   [ok ] list_folders
//!   [ok ] search
//!   [deny] search.advanced_query
//!   ...
//! ```

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{AuditOptions, AuditWriter};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_config::loader::load_from_path;
use rimap_config::validate::validate;

/// Load `path`, validate, acquire an exclusive audit lock, build the effective
/// matrix, print to `out`, and return. The audit lock is held for the duration
/// of the call and released on return.
///
/// # Errors
/// Propagates config load/validate errors, audit lock acquisition errors, and
/// I/O errors from the writer.
pub fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
    let raw = load_from_path(path).with_context(|| format!("loading config {}", path.display()))?;
    let validated = validate(raw).context("validating config")?;

    let audit_path = validated.config.audit.path.clone();
    let rotate_bytes = validated.config.audit.rotate_bytes;
    // dry-run is a one-shot diagnostic path that exits immediately after
    // printing the matrix. Chain-of-history continuation (trailing state) is
    // not useful here; Seq::FIRST is correct.
    let _audit_writer = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
        rotate_bytes,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .with_context(|| format!("opening audit log at {}", audit_path.display()))?;

    let matrix = EffectiveMatrix::from_validated(&validated);
    writeln!(out, "Effective matrix (posture = {})", matrix.posture())?;
    for (tool, allowed) in matrix.rows() {
        let tag = if allowed { "[ok ]" } else { "[deny]" };
        writeln!(out, "  {tag} {tool}")?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::dry_run::run;

    fn write_minimal_config(dir: &TempDir) -> PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "{}"
"#,
            audit.display()
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    #[test]
    fn dry_run_prints_matrix_with_default_posture() {
        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("draft-safe"));
        assert!(text.contains("list_folders"));
        assert!(text.contains("search.advanced_query"));
        // The advanced_query cell is denied under draft-safe.
        assert!(text.contains("[deny] search.advanced_query"));
        assert!(text.contains("[ok ] list_folders"));
    }

    #[test]
    fn second_dry_run_against_same_audit_fails_with_config_error() {
        use rimap_audit::{AuditOptions, AuditWriter};

        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);

        // First dry-run acquires the lock for the duration of the call.
        let mut out1 = Vec::new();
        run(&path, &mut out1).unwrap();

        // Hold the audit file open with a direct writer so the second dry-run
        // collides with us.
        let audit_path = dir.path().join("audit.jsonl");
        let _held = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .unwrap();

        let err = run(&path, &mut Vec::new()).unwrap_err();
        let chain: String = err
            .chain()
            .map(|c| format!("{c}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            chain.contains("already locked") || chain.contains("opening audit log"),
            "unexpected error chain: {chain}",
        );
    }

    #[test]
    fn dry_run_surfaces_parse_errors_as_anyhow() {
        let dir = TempDir::new().unwrap();
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not valid toml =\n").unwrap();
        let err = run(&bad, &mut Vec::new()).unwrap_err();
        // anyhow chains context; the bottom-most error comes from rimap-config.
        let mut chain = String::new();
        for cause in err.chain() {
            use std::fmt::Write as _;
            writeln!(chain, "{cause}").unwrap();
        }
        assert!(chain.contains("loading config") || chain.contains("parse"));
    }
}
