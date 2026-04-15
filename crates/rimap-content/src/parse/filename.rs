//! Attachment filename sanitisation and double-extension detection.
//!
//! Sibling of the MIME scrubber and attachment builder; called from
//! `attachments::build_attachment_meta` and reused by the crate's
//! filename-hardening tests.

use crate::output::{SecurityWarning, WarningCode};
use crate::parse::MAX_HEADER_BYTES;
use crate::unicode;

/// File extensions that look legitimate to humans and that attackers
/// frequently pair with executable extensions to spoof document
/// attachments. Consumed by [`detect_double_extension`].
pub(super) const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "txt", "csv", "rtf",
];

/// Reserved Windows filename stems (case-insensitive). Used by
/// [`sanitize_filename`]. Non-enum input means we identify membership
/// via a named slice rather than a `matches!` pattern.
pub(super) const RESERVED_WINDOWS_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Extensions that mark a file as directly executable on one or more
/// mainstream operating systems; used to spot double-extension spoofs
/// when paired with a [`DOCUMENT_EXTENSIONS`] penultimate component.
pub(super) const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "msi", "app", "dmg", "sh", "com", "pif",
    "jar", "lnk",
];

/// Sanitize a raw attachment filename for safe downstream display.
///
/// The pipeline matches the invariants the rest of `build_attachment_meta`
/// relies on: bidi-override detection, double-extension detection, the
/// shared unicode sanitizer, and `sanitize_filename` rewriting. Every
/// step that triggers a warning pushes a [`SecurityWarning`] tagged
/// with the attachment index so the caller does not need to know the
/// per-warning codes.
pub(super) fn sanitize_attachment_filename(
    name: &str,
    idx: usize,
    warnings: &mut Vec<SecurityWarning>,
) -> String {
    if contains_bidi_override(name) {
        warnings.push(SecurityWarning::at(
            WarningCode::LookalikeFilenameExtensionSpoof,
            format!("raw={name:?},contains_bidi_override=true"),
            format!("attachment[{idx}]:filename"),
        ));
    }
    if let Some((penult, final_ext)) = detect_double_extension(name) {
        warnings.push(SecurityWarning::at(
            WarningCode::LookalikeFilenameExtensionSpoof,
            format!(
                "reason=double_extension,visible=.{penult},\
                 declared=.{penult}.{final_ext}"
            ),
            format!("attachment[{idx}]:filename"),
        ));
    }
    let (unicode_clean, mut ws) = unicode::sanitize(
        name.as_bytes(),
        Some("utf-8"),
        MAX_HEADER_BYTES,
        &format!("attachment[{idx}]:filename"),
    );
    warnings.append(&mut ws);
    let (safe, rewritten) = sanitize_filename(&unicode_clean, idx);
    if rewritten {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseAttachmentFilenameRewritten,
            format!("original={unicode_clean:?}"),
            format!("attachment[{idx}]:filename"),
        ));
    }
    safe
}

/// Sanitize an attachment filename into a safe form. Returns
/// `(sanitized, rewritten)` where `rewritten` is `true` if any
/// normalization step changed the input.
///
/// Rules:
/// - Split on `/` or `\`, collapse `..` components to `_`, rejoin with `_`.
/// - Drop any NUL bytes.
/// - Trim leading and trailing `.` and ASCII whitespace.
/// - Prefix reserved Windows names (`CON`, `PRN`, `AUX`, `NUL`,
///   `COM0..9`, `LPT0..9`, case-insensitive) with `_`.
/// - Truncate to 255 bytes at a grapheme-cluster boundary.
/// - If the result is empty, fall back to `attachment_{idx}`.
pub(super) fn sanitize_filename(name: &str, idx: usize) -> (String, bool) {
    let original = name;
    let mut parts: Vec<&str> = Vec::new();
    for segment in name.split(['/', '\\']) {
        parts.push(if segment == ".." { "_" } else { segment });
    }
    let joined = parts.join("_");
    let no_nul: String = joined.chars().filter(|&c| c != '\0').collect();
    let trimmed = no_nul
        .trim_start_matches(|c: char| c == '.' || c.is_ascii_whitespace())
        .trim_end_matches(|c: char| c == '.' || c.is_ascii_whitespace())
        .to_string();
    let lowered = trimmed.to_ascii_lowercase();
    let reserved_stem = lowered.split('.').next().unwrap_or("");
    let reserved = RESERVED_WINDOWS_STEMS.contains(&reserved_stem);
    let prefixed = if reserved {
        format!("_{trimmed}")
    } else {
        trimmed
    };
    let capped = crate::unicode::truncate_graphemes(&prefixed, 255);
    let final_name = if capped.is_empty() {
        format!("attachment_{idx}")
    } else {
        capped
    };
    let rewritten = final_name != original;
    (final_name, rewritten)
}

/// Return true if `s` contains any Unicode bidi-override codepoint.
/// These characters never appear in legitimate filenames or domains;
/// their presence is a strong adversarial signal.
pub(super) fn contains_bidi_override(s: &str) -> bool {
    // Non-enum input (`char`); the set of bidi-override codepoints is closed.
    // Explicit disjunction avoids `matches!` (banned by project style) and
    // the wildcard arm that `match { pat => true, _ => false }` would need.
    s.chars().any(|c| {
        c == '\u{202A}'
            || c == '\u{202B}'
            || c == '\u{202C}'
            || c == '\u{202D}'
            || c == '\u{202E}'
            || c == '\u{2066}'
            || c == '\u{2067}'
            || c == '\u{2068}'
            || c == '\u{2069}'
    })
}

/// Detect a `.document.executable` double-extension pair (e.g.
/// `invoice.pdf.exe`). Returns `(penultimate, final)` lowercase when a
/// document extension is followed by an executable extension; otherwise
/// `None`.
pub(super) fn detect_double_extension(name: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    let penultimate = segments[segments.len() - 2].to_ascii_lowercase();
    let final_ext = segments[segments.len() - 1].to_ascii_lowercase();
    if DOCUMENT_EXTENSIONS.contains(&penultimate.as_str())
        && EXECUTABLE_EXTENSIONS.contains(&final_ext.as_str())
    {
        Some((penultimate, final_ext))
    } else {
        None
    }
}

/// Return the substring after the last `.` in `filename`, if any.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "retained for future visible/declared extension comparison"
    )
)]
pub(super) fn last_extension(filename: &str) -> Option<&str> {
    filename.rsplit_once('.').map(|(_, ext)| ext)
}

#[cfg(test)]
mod filename_helper_tests {
    use super::sanitize_attachment_filename;
    use crate::output::{SecurityWarning, WarningCode};

    fn sanitize(name: &str) -> (String, Vec<SecurityWarning>) {
        let mut warnings = Vec::new();
        let out = sanitize_attachment_filename(name, 0, &mut warnings);
        (out, warnings)
    }

    #[test]
    fn plain_name_produces_no_warnings() {
        let (out, warnings) = sanitize("notes.txt");
        assert_eq!(out, "notes.txt");
        assert!(warnings.is_empty());
    }

    #[test]
    fn bidi_override_raises_spoof_warning() {
        // U+202E RIGHT-TO-LEFT OVERRIDE embedded before a fake extension.
        let (_, warnings) = sanitize("invoice\u{202e}fdp.exe");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeFilenameExtensionSpoof),
            "expected a spoof warning for bidi override",
        );
    }

    #[test]
    fn double_extension_raises_spoof_warning() {
        let (_, warnings) = sanitize("report.pdf.exe");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeFilenameExtensionSpoof),
            "expected a spoof warning for double extension",
        );
    }
}
