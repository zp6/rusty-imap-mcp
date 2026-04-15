//! `audit merge` subcommand handler.
//!
//! Streams JSONL from an audit file on stdout, filtered by the CLI flags.
//! Stdout writes go through `std::io::stdout().lock()` directly to dodge the
//! workspace `print_stdout` lint (same pattern as `dry_run`).
//!
//! The audit log is the source of truth; this command re-serializes every
//! record via `serde_json::to_string` so the output is canonical and easily
//! piped into `jq`.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{Filter, stream_records};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Filter inputs for [`run`], expressed as string slices straight from
/// the CLI parser. Parsed into `rimap_audit::Filter` inside [`run`] so
/// error contexts can point back at the originating flag.
#[derive(Debug, Default, Clone, Copy)]
pub struct RunArgs<'a> {
    /// `--since` RFC 3339 timestamp.
    pub since: Option<&'a str>,
    /// `--until` RFC 3339 timestamp.
    pub until: Option<&'a str>,
    /// `--tool` name filter.
    pub tool: Option<&'a str>,
    /// `--kind` record-kind filter.
    pub kind: Option<&'a str>,
    /// `--process` id filter.
    pub process: Option<&'a str>,
    /// `--account` name filter.
    pub account: Option<&'a str>,
}

/// Run the `audit merge` subcommand.
///
/// # Errors
/// - Any `AuditError` from opening / locking / reading the file.
/// - Parse errors on `--since` / `--until` arguments.
/// - Stdout I/O errors.
pub fn run(path: &Path, args: RunArgs<'_>) -> anyhow::Result<()> {
    let filter = Filter {
        since: args
            .since
            .map(|s| OffsetDateTime::parse(s, &Rfc3339))
            .transpose()
            .with_context(|| format!("parsing --since `{}`", args.since.unwrap_or("")))?,
        until: args
            .until
            .map(|s| OffsetDateTime::parse(s, &Rfc3339))
            .transpose()
            .with_context(|| format!("parsing --until `{}`", args.until.unwrap_or("")))?,
        tool: args.tool.map(str::to_string),
        kind: args.kind.map(str::to_string),
        process: args.process.map(str::to_string),
        account: args.account.map(str::to_string),
    };

    let mut stdout = std::io::stdout().lock();
    stream_records(path, &filter, |record| {
        let line = serde_json::to_string(record).map_err(rimap_audit::AuditError::Serialize)?;
        writeln!(stdout, "{line}").map_err(|source| rimap_audit::AuditError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    })
    .context("streaming audit records")?;
    Ok(())
}
