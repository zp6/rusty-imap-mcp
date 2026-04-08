//! Pure Unicode sanitization pipeline.
//!
//! The pipeline is a sequence of independent pure functions:
//! [`decode`] → [`normalize_nfkc`] → [`filter_codepoints`] →
//! [`normalize_line_endings`] → [`truncate_graphemes`]. The [`sanitize`]
//! composer runs the full sequence and returns the output string
//! alongside any [`SecurityWarning`]s emitted during filtering.
//!
//! This module has no I/O, no allocations beyond its output string, and
//! knows nothing about MIME or email structure. It is the single
//! chokepoint through which every untrusted string in the crate passes.

use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::output::{SecurityWarning, WarningCode};

/// Zero-width codepoints stripped by [`filter_codepoints`].
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
];

/// Bidi override/isolate codepoints stripped by [`filter_codepoints`].
const BIDI_OVERRIDE: &[char] = &[
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
];

/// Decode `bytes` to a UTF-8 `String` using the label in `charset_label`.
/// Unknown labels and missing labels fall back to UTF-8 decoding with
/// replacement characters.
///
/// `encoding_rs` never fails for any byte slice — it substitutes
/// U+FFFD on decode errors — so this function returns an owned `String`
/// rather than `Result`.
#[must_use]
pub fn decode(bytes: &[u8], charset_label: Option<&str>) -> String {
    let encoding = charset_label
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    let (cow, _encoding_used, _had_errors) = encoding.decode(bytes);
    cow.into_owned()
}

/// Apply Unicode NFKC normalization to `input`.
///
/// This is idempotent: `normalize_nfkc(normalize_nfkc(s)) == normalize_nfkc(s)`.
#[must_use]
pub fn normalize_nfkc(input: &str) -> String {
    input.nfkc().collect()
}

/// Filter disallowed codepoints from `input`, returning the filtered
/// string alongside the set of warning codes produced by the scan.
///
/// The strip set covers:
/// - Zero-width formatting codepoints ([`ZERO_WIDTH`])
/// - Bidi overrides and isolates ([`BIDI_OVERRIDE`])
/// - C0 controls (U+0000..U+001F) except `\t` (U+0009) and `\n` (U+000A)
/// - C1 controls (U+0080..U+009F)
///
/// Each warning code is emitted at most once per call, regardless of
/// how many codepoints of that class were stripped. The returned
/// counts (in the `detail` string of the warning, populated by
/// [`sanitize`]) record the total.
#[must_use]
pub fn filter_codepoints(input: &str) -> FilterResult {
    let mut out = String::with_capacity(input.len());
    let mut zero_width = 0_usize;
    let mut bidi = 0_usize;
    let mut c0_c1 = 0_usize;

    for ch in input.chars() {
        if ZERO_WIDTH.contains(&ch) {
            zero_width += 1;
            continue;
        }
        if BIDI_OVERRIDE.contains(&ch) {
            bidi += 1;
            continue;
        }
        if is_c0_control_disallowed(ch) || is_c1_control(ch) {
            c0_c1 += 1;
            continue;
        }
        out.push(ch);
    }

    FilterResult {
        text: out,
        zero_width_stripped: zero_width,
        bidi_stripped: bidi,
        c0_c1_stripped: c0_c1,
    }
}

/// Outcome of [`filter_codepoints`]. The three count fields record how
/// many codepoints of each class were stripped from the input; the
/// [`sanitize`] composer converts non-zero counts into
/// [`SecurityWarning`] entries.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Filtered text with disallowed codepoints removed.
    pub text: String,
    /// Number of zero-width codepoints stripped.
    pub zero_width_stripped: usize,
    /// Number of bidi-override codepoints stripped.
    pub bidi_stripped: usize,
    /// Number of C0/C1 control codepoints stripped.
    pub c0_c1_stripped: usize,
}

fn is_c0_control_disallowed(ch: char) -> bool {
    let c = ch as u32;
    c <= 0x1F && ch != '\t' && ch != '\n'
}

fn is_c1_control(ch: char) -> bool {
    let c = ch as u32;
    (0x80..=0x9F).contains(&c)
}

/// Normalize all line endings to `\n`. Converts `\r\n` to `\n` and
/// any remaining bare `\r` to `\n`. Idempotent.
#[must_use]
pub fn normalize_line_endings(input: &str) -> String {
    // Two-pass: first collapse CRLF, then convert bare CR. A single
    // pass with a char iterator would also work but this is clearer.
    let crlf_collapsed = input.replace("\r\n", "\n");
    crlf_collapsed.replace('\r', "\n")
}

/// Truncate `input` to at most `max_bytes` bytes, cutting at a
/// grapheme-cluster boundary. Returns an owned `String` that is
/// always a prefix of `input` (byte-wise).
///
/// If `input` is already ≤ `max_bytes`, returns a clone. If
/// `max_bytes == 0`, returns an empty string.
#[must_use]
pub fn truncate_graphemes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for cluster in input.graphemes(true) {
        if out.len() + cluster.len() > max_bytes {
            break;
        }
        out.push_str(cluster);
    }
    out
}

/// Run the full sanitization pipeline on `bytes`: decode with the
/// given charset, NFKC-normalize, filter disallowed codepoints,
/// normalize line endings, and truncate to at most `max_bytes` bytes
/// at a grapheme-cluster boundary.
///
/// Returns the sanitized string and the list of warnings produced by
/// the filter pass. `location` is embedded verbatim in each warning's
/// `location` field so callers can attribute strippings to a header
/// name or body part index.
#[must_use]
pub fn sanitize(
    bytes: &[u8],
    charset_label: Option<&str>,
    max_bytes: usize,
    location: &str,
) -> (String, Vec<SecurityWarning>) {
    let decoded = decode(bytes, charset_label);
    let normalized = normalize_nfkc(&decoded);
    let filter_result = filter_codepoints(&normalized);
    let line_normalized = normalize_line_endings(&filter_result.text);
    let truncated = truncate_graphemes(&line_normalized, max_bytes);

    let warnings = build_warnings(&filter_result, location);
    (truncated, warnings)
}

fn build_warnings(result: &FilterResult, location: &str) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    if result.zero_width_stripped > 0 {
        warnings.push(SecurityWarning {
            code: WarningCode::UnicodeZeroWidthStripped,
            detail: Some(format!("count={}", result.zero_width_stripped)),
            location: Some(location.to_string()),
        });
    }
    if result.bidi_stripped > 0 {
        warnings.push(SecurityWarning {
            code: WarningCode::UnicodeBidiOverrideStripped,
            detail: Some(format!("count={}", result.bidi_stripped)),
            location: Some(location.to_string()),
        });
    }
    if result.c0_c1_stripped > 0 {
        warnings.push(SecurityWarning {
            code: WarningCode::UnicodeC0C1Stripped,
            detail: Some(format!("count={}", result.c0_c1_stripped)),
            location: Some(location.to_string()),
        });
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_utf8_passthrough() {
        let out = decode(b"hello world", Some("utf-8"));
        assert_eq!(out, "hello world");
    }

    #[test]
    fn decode_latin1_handles_high_bytes() {
        // "café" in ISO-8859-1 is [0x63, 0x61, 0x66, 0xE9].
        let out = decode(&[0x63, 0x61, 0x66, 0xE9], Some("iso-8859-1"));
        assert_eq!(out, "café");
    }

    #[test]
    fn decode_unknown_charset_falls_back_to_utf8() {
        let out = decode(b"hello", Some("pig-latin"));
        assert_eq!(out, "hello");
    }

    #[test]
    fn decode_none_charset_defaults_utf8() {
        let out = decode(b"hello", None);
        assert_eq!(out, "hello");
    }

    #[test]
    fn nfkc_compatibility_composes_decomposed() {
        // "e" + combining acute => precomposed "é"
        let decomposed = "e\u{0301}";
        let composed = normalize_nfkc(decomposed);
        assert_eq!(composed, "é");
    }

    #[test]
    fn nfkc_is_idempotent() {
        // Mixed input: precomposed é, NBSP, em-dash, and the LATIN SMALL LIGATURE FI.
        let input = "Café\u{00A0}—\u{FB01}ve";
        let once = normalize_nfkc(input);
        let twice = normalize_nfkc(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn nfkc_expands_ligature() {
        // U+FB01 LATIN SMALL LIGATURE FI -> "fi" under NFKC.
        let out = normalize_nfkc("\u{FB01}ve");
        assert_eq!(out, "five");
    }

    #[test]
    fn filter_strips_zero_width_codepoints() {
        let input = "he\u{200B}llo\u{FEFF} wor\u{2060}ld";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "hello world");
        assert_eq!(result.zero_width_stripped, 3);
        assert_eq!(result.bidi_stripped, 0);
        assert_eq!(result.c0_c1_stripped, 0);
    }

    #[test]
    fn filter_strips_bidi_overrides() {
        let input = "safe\u{202E}evil\u{202C}.exe";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "safeevil.exe");
        assert_eq!(result.bidi_stripped, 2);
        assert_eq!(result.zero_width_stripped, 0);
    }

    #[test]
    fn filter_strips_c0_controls_except_tab_newline() {
        let input = "a\tb\nc\x01d\x07e";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "a\tb\ncde");
        assert_eq!(result.c0_c1_stripped, 2);
    }

    #[test]
    fn filter_strips_c1_controls() {
        let input = "a\u{0085}b\u{009F}c";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "abc");
        assert_eq!(result.c0_c1_stripped, 2);
    }

    #[test]
    fn filter_preserves_legitimate_multilingual() {
        let inputs = [
            "こんにちは世界",   // Japanese
            "مرحبا بالعالم",    // Arabic
            "שלום עולם",        // Hebrew
            "Grüße aus Bayern", // German with umlauts
        ];
        for input in inputs {
            let result = filter_codepoints(input);
            assert_eq!(result.text, input, "input={input}");
            assert_eq!(result.zero_width_stripped, 0);
            assert_eq!(result.bidi_stripped, 0);
            assert_eq!(result.c0_c1_stripped, 0);
        }
    }

    #[test]
    fn line_endings_crlf_to_lf() {
        assert_eq!(normalize_line_endings("a\r\nb\r\nc"), "a\nb\nc");
    }

    #[test]
    fn line_endings_bare_cr_to_lf() {
        assert_eq!(normalize_line_endings("a\rb\rc"), "a\nb\nc");
    }

    #[test]
    fn line_endings_mixed() {
        assert_eq!(normalize_line_endings("a\r\nb\rc\nd"), "a\nb\nc\nd");
    }

    #[test]
    fn line_endings_idempotent() {
        let once = normalize_line_endings("a\r\nb\rc");
        let twice = normalize_line_endings(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn truncate_under_limit_is_passthrough() {
        assert_eq!(truncate_graphemes("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_limit() {
        assert_eq!(truncate_graphemes("hello", 5), "hello");
    }

    #[test]
    fn truncate_ascii_cuts_cleanly() {
        assert_eq!(truncate_graphemes("hello world", 5), "hello");
    }

    #[test]
    fn truncate_preserves_grapheme_cluster() {
        // "é" (e + combining acute) is 3 bytes as a single cluster.
        // Truncating at byte 2 must drop the whole cluster, not split it.
        let input = "ae\u{0301}b";
        let out = truncate_graphemes(input, 2);
        // "a" fits (1 byte). "e\u{0301}" would push total to 4 (> 2), so drop it.
        assert_eq!(out, "a");
    }

    #[test]
    fn truncate_zero_max_bytes_returns_empty() {
        assert_eq!(truncate_graphemes("hello", 0), "");
    }

    #[test]
    fn sanitize_passthrough_ascii() {
        let (text, warnings) = sanitize(b"hello", Some("utf-8"), 1024, "header:subject");
        assert_eq!(text, "hello");
        assert!(warnings.is_empty());
    }

    #[test]
    fn sanitize_emits_zero_width_warning() {
        let input = "he\u{200B}llo".as_bytes();
        let (text, warnings) = sanitize(input, Some("utf-8"), 1024, "header:subject");
        assert_eq!(text, "hello");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::UnicodeZeroWidthStripped);
        assert_eq!(warnings[0].location.as_deref(), Some("header:subject"));
        assert!(
            warnings[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("count=1")
        );
    }

    #[test]
    fn sanitize_emits_multiple_warnings() {
        let input = "a\u{200B}b\u{202E}c\x01d".as_bytes();
        let (text, warnings) = sanitize(input, Some("utf-8"), 1024, "body:part[0]");
        assert_eq!(text, "abcd");
        assert_eq!(warnings.len(), 3);
        let codes: Vec<WarningCode> = warnings.iter().map(|w| w.code).collect();
        assert!(codes.contains(&WarningCode::UnicodeZeroWidthStripped));
        assert!(codes.contains(&WarningCode::UnicodeBidiOverrideStripped));
        assert!(codes.contains(&WarningCode::UnicodeC0C1Stripped));
    }

    #[test]
    fn sanitize_truncates_oversized() {
        let input = "a".repeat(100);
        let (text, warnings) = sanitize(input.as_bytes(), Some("utf-8"), 10, "body:part[0]");
        assert_eq!(text.len(), 10);
        assert_eq!(text, "aaaaaaaaaa");
        assert!(warnings.is_empty()); // truncation warning is emitted by parse, not sanitize
    }

    #[test]
    fn sanitize_multilingual_clean() {
        let (text, warnings) =
            sanitize("こんにちは".as_bytes(), Some("utf-8"), 1024, "body:part[0]");
        assert_eq!(text, "こんにちは");
        assert!(warnings.is_empty());
    }
}
