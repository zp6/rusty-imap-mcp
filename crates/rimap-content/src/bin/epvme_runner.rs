//! Bulk regression runner for external malicious-email datasets.
//!
//! This binary walks a directory tree of `.eml` files, parses each
//! sample with [`rimap_content::parse_message`], aggregates warnings
//! and failures, and optionally writes a JSON report.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rimap_content::{Content, ContentError, WarningCode, parse_message};
use serde::Serialize;

const MAX_RECORDED_FAILURES: usize = 50;

#[derive(Debug)]
struct Args {
    dataset_root: PathBuf,
    limit: Option<usize>,
    json_out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    dataset_root: String,
    discovered_files: usize,
    processed_files: usize,
    ok_count: usize,
    panic_count: usize,
    read_failure_count: usize,
    parse_error_count: usize,
    limit: Option<usize>,
    warning_counts: BTreeMap<String, usize>,
    parse_error_counts: BTreeMap<String, usize>,
    recorded_failures: Vec<FailureRecord>,
}

#[derive(Debug, Serialize)]
struct FailureRecord {
    path: String,
    kind: String,
    detail: String,
}

#[derive(Debug)]
enum SampleOutcome {
    Ok(Box<Content>),
    ParseError(ContentError),
    Panic(String),
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(message) => {
            let _ = writeln!(io::stderr().lock(), "{message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;
    let files = collect_eml_files(&args.dataset_root)?;
    if files.is_empty() {
        return Err(format!(
            "no .eml files found under {}",
            args.dataset_root.display()
        ));
    }

    let summary = run_dataset(&args.dataset_root, &files, args.limit, parse_message);
    print_summary(&summary).map_err(|err| format!("write stdout: {err}"))?;
    if let Some(json_out) = &args.json_out {
        write_json_report(json_out, &summary)?;
    }

    if is_success(&summary) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn parse_args() -> Result<Args, String> {
    let mut dataset_root: Option<PathBuf> = None;
    let mut limit: Option<usize> = None;
    let mut json_out: Option<PathBuf> = None;

    let mut args = std::env::args_os();
    let _program = args.next();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => {
                return Err(usage());
            }
            Some("--limit") => {
                let Some(value) = args.next() else {
                    return Err("--limit requires a value".to_string());
                };
                let parsed = value
                    .to_str()
                    .ok_or_else(|| "--limit must be valid UTF-8".to_string())?
                    .parse::<usize>()
                    .map_err(|_| "--limit must be a non-negative integer".to_string())?;
                limit = Some(parsed);
            }
            Some("--json-out") => {
                let Some(value) = args.next() else {
                    return Err("--json-out requires a path".to_string());
                };
                json_out = Some(PathBuf::from(value));
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(format!("unknown flag: {flag}\n\n{}", usage()));
            }
            _ => {
                if dataset_root.is_some() {
                    let arg = arg.to_string_lossy();
                    return Err(format!("unexpected extra positional argument: {arg}"));
                }
                dataset_root = Some(PathBuf::from(arg));
            }
        }
    }

    let Some(dataset_root) = dataset_root else {
        return Err(usage());
    };

    Ok(Args {
        dataset_root,
        limit,
        json_out,
    })
}

fn usage() -> String {
    "usage: epvme_runner <dataset-root> [--limit N] [--json-out PATH]".to_string()
}

fn collect_eml_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Err(format!("dataset root does not exist: {}", root.display()));
    }
    if !root.is_dir() {
        return Err(format!(
            "dataset root is not a directory: {}",
            root.display()
        ));
    }

    let mut files = Vec::new();
    walk_eml_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_eml_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(root).map_err(|err| format!("read directory {}: {err}", root.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("read directory entry {}: {err}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("read file type {}: {err}", path.display()))?;
        if file_type.is_dir() {
            walk_eml_files(&path, files)?;
            continue;
        }
        if file_type.is_file() && is_eml_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_eml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("eml"))
}

fn run_dataset<P>(
    dataset_root: &Path,
    files: &[PathBuf],
    limit: Option<usize>,
    parser: P,
) -> RunSummary
where
    P: Fn(&[u8]) -> Result<Content, ContentError>,
{
    let mut summary = RunSummary {
        dataset_root: dataset_root.display().to_string(),
        discovered_files: files.len(),
        processed_files: 0,
        ok_count: 0,
        panic_count: 0,
        read_failure_count: 0,
        parse_error_count: 0,
        limit,
        warning_counts: BTreeMap::new(),
        parse_error_counts: BTreeMap::new(),
        recorded_failures: Vec::new(),
    };

    let take_count = limit.unwrap_or(files.len());
    for path in files.iter().take(take_count) {
        summary.processed_files += 1;
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(err) => {
                summary.read_failure_count += 1;
                record_failure(
                    &mut summary,
                    path,
                    "read_error",
                    format!("read {}: {err}", path.display()),
                );
                continue;
            }
        };

        match parse_one(&raw, &parser) {
            SampleOutcome::Ok(content) => {
                summary.ok_count += 1;
                for warning in content.security_warnings {
                    let label = warning_code_to_label(warning.code).to_string();
                    *summary.warning_counts.entry(label).or_insert(0) += 1;
                }
            }
            SampleOutcome::ParseError(err) => {
                summary.parse_error_count += 1;
                let label = error_kind_label(&err).to_string();
                *summary.parse_error_counts.entry(label.clone()).or_insert(0) += 1;
                record_failure(&mut summary, path, label, err.to_string());
            }
            SampleOutcome::Panic(message) => {
                summary.panic_count += 1;
                record_failure(&mut summary, path, "panic", message);
            }
        }
    }

    summary
}

fn parse_one<P>(raw: &[u8], parser: P) -> SampleOutcome
where
    P: Fn(&[u8]) -> Result<Content, ContentError>,
{
    match panic::catch_unwind(AssertUnwindSafe(|| parser(raw))) {
        Ok(Ok(content)) => SampleOutcome::Ok(Box::new(content)),
        Ok(Err(err)) => SampleOutcome::ParseError(err),
        Err(payload) => SampleOutcome::Panic(panic_message(payload)),
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    let payload = match payload.downcast::<String>() {
        Ok(message) => return *message,
        Err(payload) => payload,
    };

    let payload = match payload.downcast::<&'static str>() {
        Ok(message) => return (*message).to_string(),
        Err(payload) => payload,
    };

    let _payload = payload;
    "panic payload was not a string".to_string()
}

fn unknown_warning_code_label(code: WarningCode) -> &'static str {
    match code.severity() {
        rimap_content::WarningSeverity::Informational => "unknown_informational_warning",
        rimap_content::WarningSeverity::Adversarial => "unknown_adversarial_warning",
        _ => "unknown_warning",
    }
}

fn record_failure(summary: &mut RunSummary, path: &Path, kind: impl Into<String>, detail: String) {
    if summary.recorded_failures.len() >= MAX_RECORDED_FAILURES {
        return;
    }
    summary.recorded_failures.push(FailureRecord {
        path: path.display().to_string(),
        kind: kind.into(),
        detail,
    });
}

fn print_summary(summary: &RunSummary) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "EPVME dataset root: {}", summary.dataset_root)?;
    writeln!(
        stdout,
        "Discovered .eml files: {}",
        summary.discovered_files
    )?;
    writeln!(stdout, "Processed files: {}", summary.processed_files)?;
    if let Some(limit) = summary.limit {
        writeln!(stdout, "Limit: {limit}")?;
    }
    writeln!(stdout, "Parsed successfully: {}", summary.ok_count)?;
    writeln!(stdout, "Parse errors: {}", summary.parse_error_count)?;
    writeln!(stdout, "Read failures: {}", summary.read_failure_count)?;
    writeln!(stdout, "Panics: {}", summary.panic_count)?;

    if !summary.parse_error_counts.is_empty() {
        writeln!(stdout, "Parse error kinds:")?;
        for (kind, count) in &summary.parse_error_counts {
            writeln!(stdout, "  {kind}: {count}")?;
        }
    }

    if !summary.warning_counts.is_empty() {
        writeln!(stdout, "Warning counts:")?;
        for (warning, count) in &summary.warning_counts {
            writeln!(stdout, "  {warning}: {count}")?;
        }
    }

    if !summary.recorded_failures.is_empty() {
        writeln!(
            stdout,
            "Recorded failures (showing up to {MAX_RECORDED_FAILURES}):"
        )?;
        for failure in &summary.recorded_failures {
            writeln!(
                stdout,
                "  {} [{}] {}",
                failure.path, failure.kind, failure.detail
            )?;
        }
    }

    Ok(())
}

fn write_json_report(path: &Path, summary: &RunSummary) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create JSON report directory {}: {err}", parent.display()))?;
    }

    let json = serde_json::to_vec_pretty(summary)
        .map_err(|err| format!("serialize JSON report {}: {err}", path.display()))?;
    fs::write(path, json).map_err(|err| format!("write JSON report {}: {err}", path.display()))
}

fn is_success(summary: &RunSummary) -> bool {
    summary.parse_error_count == 0 && summary.read_failure_count == 0 && summary.panic_count == 0
}

fn warning_code_to_label(code: WarningCode) -> &'static str {
    match code {
        WarningCode::UnicodeZeroWidthStripped => "unicode_zero_width_stripped",
        WarningCode::UnicodeBidiOverrideStripped => "unicode_bidi_override_stripped",
        WarningCode::UnicodeC0C1Stripped => "unicode_c0_c1_stripped",
        WarningCode::ParseHeaderSmugglingBlocked => "parse_header_smuggling_blocked",
        WarningCode::ParseMimeTypeMismatch => "parse_mime_type_mismatch",
        WarningCode::ParseAttachmentPolyglot => "parse_attachment_polyglot",
        WarningCode::ParseBodyTruncated => "parse_body_truncated",
        WarningCode::ParseMimeDepthExceeded => "parse_mime_depth_exceeded",
        WarningCode::ParseMimePartCountExceeded => "parse_mime_part_count_exceeded",
        WarningCode::ParseHeaderCountExceeded => "parse_header_count_exceeded",
        WarningCode::ParseAttachmentFilenameRewritten => "parse_attachment_filename_rewritten",
        WarningCode::HtmlHiddenContentDetected => "html_hidden_content_detected",
        WarningCode::HtmlLinkTextHrefMismatch => "html_link_text_href_mismatch",
        WarningCode::HtmlScriptStripped => "html_script_stripped",
        WarningCode::HtmlStyleStripped => "html_style_stripped",
        WarningCode::HtmlRemoteImageStripped => "html_remote_image_stripped",
        WarningCode::LookalikeMixedScript => "lookalike_mixed_script",
        WarningCode::LookalikeHomographDomain => "lookalike_homograph_domain",
        WarningCode::LookalikeIdnPunycode => "lookalike_idn_punycode",
        WarningCode::LookalikeFilenameExtensionSpoof => "lookalike_filename_extension_spoof",
        _ => unknown_warning_code_label(code),
    }
}

fn error_kind_label(err: &ContentError) -> &'static str {
    match err {
        ContentError::Malformed { .. } => "Malformed",
        ContentError::LimitExceeded { .. } => "LimitExceeded",
        ContentError::Decoding { .. } => "Decoding",
        _ => "Unknown",
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test helpers construct temporary datasets"
)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn write_sample(root: &Path, relative: &str, body: &[u8]) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, body).unwrap();
        path
    }

    fn simple_email(body: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\n{body}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn collect_eml_files_walks_nested_tree() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        write_sample(root, "1/one.eml", &simple_email("hello"));
        write_sample(root, "2/two.EML", &simple_email("world"));
        write_sample(root, "2/skip.txt", b"nope");

        let files = collect_eml_files(root).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|path| is_eml_path(path)));
    }

    #[test]
    fn run_dataset_reports_parse_errors_by_kind() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let good = write_sample(root, "1/good.eml", &simple_email("hello"));
        let bad = write_sample(root, "1/bad.eml", &simple_email("trigger-malformed"));
        let files = vec![bad.clone(), good];

        let summary = run_dataset(root, &files, None, |raw| {
            if raw
                .windows("trigger-malformed".len())
                .any(|window| window == b"trigger-malformed")
            {
                return Err(ContentError::Malformed {
                    reason: "synthetic malformed fixture".to_string(),
                });
            }
            parse_message(raw)
        });

        assert_eq!(summary.processed_files, 2);
        assert_eq!(summary.ok_count, 1);
        assert_eq!(summary.parse_error_count, 1);
        assert_eq!(summary.parse_error_counts.get("Malformed"), Some(&1));
        assert_eq!(summary.recorded_failures.len(), 1);
        assert_eq!(summary.recorded_failures[0].path, bad.display().to_string());
        assert!(!is_success(&summary));
    }

    #[test]
    fn run_dataset_catches_panics_and_continues() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let panic_path = write_sample(root, "1/panic.eml", &simple_email("panic"));
        let ok_path = write_sample(root, "1/ok.eml", &simple_email("ok"));
        let files = vec![panic_path.clone(), ok_path];

        let summary = run_dataset(root, &files, None, |raw| {
            assert!(!raw.windows(5).any(|window| window == b"panic"), "boom");
            parse_message(raw)
        });

        assert_eq!(summary.processed_files, 2);
        assert_eq!(summary.ok_count, 1);
        assert_eq!(summary.panic_count, 1);
        assert_eq!(
            summary.recorded_failures[0].path,
            panic_path.display().to_string()
        );
        assert_eq!(summary.recorded_failures[0].kind, "panic");
    }

    #[test]
    fn run_dataset_honors_limit() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let first = write_sample(root, "1/a.eml", &simple_email("one"));
        let second = write_sample(root, "1/b.eml", &simple_email("two"));
        let files = vec![first, second];

        let summary = run_dataset(root, &files, Some(1), parse_message);

        assert_eq!(summary.discovered_files, 2);
        assert_eq!(summary.processed_files, 1);
        assert_eq!(summary.ok_count, 1);
    }

    #[test]
    fn run_dataset_aggregates_warning_counts() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let sample = write_sample(root, "1/zero-width.eml", &simple_email("te\u{200B}st"));
        let files = vec![sample];

        let summary = run_dataset(root, &files, None, parse_message);

        assert_eq!(summary.ok_count, 1);
        assert_eq!(
            summary.warning_counts.get("unicode_zero_width_stripped"),
            Some(&1)
        );
        assert!(is_success(&summary));
    }
}
