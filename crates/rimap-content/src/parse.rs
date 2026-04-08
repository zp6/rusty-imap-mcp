//! Message parsing via `mail-parser`.
//!
//! This module owns all interaction with `mail-parser`; no other
//! module in `rimap-content` imports `mail-parser` types directly.
//! It applies hard limits declared as compile-time constants and
//! routes every extracted string through [`crate::unicode::sanitize`]
//! so downstream consumers see only Unicode-clean text.

use mail_parser::{Address, HeaderValue, Message, MessageParser};
use time::OffsetDateTime;

use crate::error::ContentError;
use crate::output::{Content, ContentMeta, SecurityWarning, Untrusted, WarningCode};
use crate::unicode;

/// Maximum raw message size accepted. Bodies over this are truncated
/// and `ParseBodyTruncated` is emitted.
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

/// Maximum per-text-part size after sanitization.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum per-header-value size after sanitization.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Maximum MIME nesting depth. Exceeding this is a terminal error.
pub const MAX_MIME_DEPTH: usize = 8;

/// Maximum number of MIME parts (across all depths). Exceeding this
/// is a terminal error.
pub const MAX_MIME_PARTS: usize = 100;

/// Maximum number of headers. Exceeding this is a terminal error.
pub const MAX_HEADER_COUNT: usize = 256;

/// Parse a raw RFC 5322 message into a [`Content`] structure.
///
/// # Errors
///
/// Returns [`ContentError::Malformed`] if `mail-parser` rejects the
/// byte stream, and [`ContentError::LimitExceeded`] if any hard limit
/// (MIME depth, part count, header count) is exceeded.
pub fn parse_message(raw: &[u8]) -> Result<Content, ContentError> {
    let original_size_bytes = raw.len() as u64;
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = scrub_header_smuggling(raw, &mut warnings);

    let message =
        MessageParser::default()
            .parse(&scrubbed)
            .ok_or_else(|| ContentError::Malformed {
                reason: "mail-parser rejected byte stream".to_string(),
            })?;

    enforce_header_count(&message, &mut warnings)?;

    let meta = extract_meta(&message, original_size_bytes, &mut warnings);

    Ok(Content {
        meta,
        untrusted: Untrusted::default(),
        security_warnings: warnings,
    })
}

fn enforce_header_count(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let header_count = message.headers().len();
    if header_count > MAX_HEADER_COUNT {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseHeaderCountExceeded,
            detail: Some(format!("count={header_count} limit={MAX_HEADER_COUNT}")),
            location: Some("headers".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "header_count",
            limit: MAX_HEADER_COUNT,
        });
    }
    Ok(())
}

fn extract_meta(
    message: &Message<'_>,
    original_size_bytes: u64,
    warnings: &mut Vec<SecurityWarning>,
) -> ContentMeta {
    let from = first_address_string(message.from(), "header:from", warnings);
    let to = address_strings(message.to(), "header:to", warnings);
    let cc = address_strings(message.cc(), "header:cc", warnings);
    let subject = sanitize_opt_str(message.subject(), "header:subject", warnings);
    let date = message.date().and_then(convert_datetime);
    let message_id = sanitize_opt_str(message.message_id(), "header:message_id", warnings);
    let in_reply_to =
        header_value_first_text(message.in_reply_to(), "header:in_reply_to", warnings);
    let references = header_value_all_text(message.references(), "header:references", warnings);

    ContentMeta {
        from,
        to,
        cc,
        subject,
        date,
        message_id,
        in_reply_to,
        references,
        mailing_list: None,
        attachments: Vec::new(),
        original_size_bytes,
        body_truncated: false,
    }
}

/// Sanitize an optional header string, appending any warnings.
fn sanitize_opt_str(
    value: Option<&str>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let value = value?;
    let (text, mut new_warnings) =
        unicode::sanitize(value.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Flatten an `Address` (list or group) into a sequence of display
/// strings and sanitize each one.
fn address_strings(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let Some(address) = address else {
        return Vec::new();
    };
    address
        .iter()
        .map(format_addr)
        .map(|raw| {
            let (text, mut new_warnings) =
                unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

/// Sanitize the first address in an `Address` value (if any).
fn first_address_string(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = format_addr(address?.first()?);
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Render a single `Addr` as `"Name <email@host>"` or just
/// `"email@host"` if the display name is absent or empty.
fn format_addr(addr: &mail_parser::Addr<'_>) -> String {
    let email = addr.address.as_deref().unwrap_or("");
    match addr.name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
        _ => email.to_string(),
    }
}

/// Extract the first textual value from a `HeaderValue`, sanitize it,
/// and return `None` if the header is `Empty` or non-textual.
fn header_value_first_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list.first()?.as_ref().to_string(),
        _ => return None,
    };
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Extract every textual value from a `HeaderValue` and sanitize each.
fn header_value_all_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let raws: Vec<String> = match value {
        HeaderValue::Text(s) => vec![s.as_ref().to_string()],
        HeaderValue::TextList(list) => list.iter().map(|s| s.as_ref().to_string()).collect(),
        _ => return Vec::new(),
    };
    raws.into_iter()
        .map(|raw| {
            let (text, mut new_warnings) =
                unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

/// Convert a `mail_parser::DateTime` into a UTC `OffsetDateTime`,
/// returning `None` for invalid or out-of-range values.
fn convert_datetime(dt: &mail_parser::DateTime) -> Option<OffsetDateTime> {
    if !dt.is_valid() {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(dt.to_timestamp()).ok()
}

/// Scan the header block for raw CRLF inside RFC 2047 encoded-words.
/// Drop any offending logical header(s) and emit
/// [`WarningCode::ParseHeaderSmugglingBlocked`].
///
/// Returns a byte vector containing the message with the offending
/// header lines removed.
fn scrub_header_smuggling(raw: &[u8], warnings: &mut Vec<SecurityWarning>) -> Vec<u8> {
    let Some((header_end, _sep_len)) = find_header_end(raw) else {
        return raw.to_vec(); // no headers = no smuggling
    };

    let headers = &raw[..header_end];
    let body = &raw[header_end..];

    let logical = split_header_lines(headers);
    let drop_mask = detect_smuggling_spans(&logical);
    let dropped = drop_mask.iter().filter(|flag| **flag).count();

    let mut kept: Vec<u8> = Vec::with_capacity(headers.len());
    for (idx, line) in logical.iter().enumerate() {
        if !drop_mask[idx] {
            kept.extend_from_slice(line);
        }
    }
    if dropped > 0 {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseHeaderSmugglingBlocked,
            detail: Some(format!("count={dropped}")),
            location: Some("headers".to_string()),
        });
    }
    kept.extend_from_slice(body);
    kept
}

/// Walk the logical-header slice and mark every header index that
/// participates in an RFC 2047 smuggling attempt: either an encoded-word
/// whose `=?` and `?=` terminators land in different logical headers,
/// or a dangling `=?` with no `?=` anywhere in the remaining block.
fn detect_smuggling_spans(logical: &[&[u8]]) -> Vec<bool> {
    let mut mask = vec![false; logical.len()];
    let mut idx = 0_usize;
    let mut scan_from = 0_usize;
    while idx < logical.len() {
        let header = logical[idx];
        let search_start = scan_from.min(header.len());
        let Some(rel) = find_subslice(&header[search_start..], b"=?") else {
            idx += 1;
            scan_from = 0;
            continue;
        };
        let start_pos = search_start + rel;
        match locate_encoded_word_end(logical, idx, start_pos + 2) {
            EncodedWordEnd::SameHeader(end_rel_to_header) => {
                scan_from = end_rel_to_header + 2;
            }
            EncodedWordEnd::LaterHeader(end_idx) => {
                for flag in mask.iter_mut().take(end_idx + 1).skip(idx) {
                    *flag = true;
                }
                idx = end_idx + 1;
                scan_from = 0;
            }
            EncodedWordEnd::Missing => {
                mask[idx] = true;
                idx += 1;
                scan_from = 0;
            }
        }
    }
    mask
}

/// Result of searching for the `?=` terminator of an encoded-word that
/// began at a known position inside a logical header.
enum EncodedWordEnd {
    /// Terminator found inside the same logical header as the opener.
    SameHeader(usize),
    /// Terminator found in a later logical header; carries that index.
    LaterHeader(usize),
    /// No terminator anywhere in the remaining header block.
    Missing,
}

/// Scan for `?=` starting at `start_offset` inside `logical[start_idx]`
/// and continuing through later logical headers if needed.
fn locate_encoded_word_end(
    logical: &[&[u8]],
    start_idx: usize,
    start_offset: usize,
) -> EncodedWordEnd {
    let first = logical[start_idx];
    if start_offset < first.len()
        && let Some(rel) = find_subslice(&first[start_offset..], b"?=")
    {
        return EncodedWordEnd::SameHeader(start_offset + rel);
    }
    for (offset, line) in logical.iter().enumerate().skip(start_idx + 1) {
        if find_subslice(line, b"?=").is_some() {
            return EncodedWordEnd::LaterHeader(offset);
        }
    }
    EncodedWordEnd::Missing
}

/// Return the byte offset of the first occurrence of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    for i in 0..=last {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Find the byte offset where the header block ends (exclusive of the
/// blank-line separator). Handles both CRLF and LF line endings.
/// Returns `(header_end, separator_length)`.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if raw.len() >= 4 {
        for i in 0..=raw.len() - 4 {
            if &raw[i..i + 4] == b"\r\n\r\n" {
                return Some((i + 2, 2));
            }
        }
    }
    if raw.len() >= 2 {
        for i in 0..=raw.len() - 2 {
            if &raw[i..i + 2] == b"\n\n" {
                return Some((i + 1, 1));
            }
        }
    }
    None
}

/// Split a header block into individual logical header lines.
/// Preserves continuation (folded) lines as part of their parent line
/// by joining on leading whitespace. Each returned slice INCLUDES its
/// terminating CRLF or LF.
fn split_header_lines(headers: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut line_start = 0_usize;
    let mut i = 0_usize;
    while i < headers.len() {
        let line_end = match memchr_lf(&headers[i..]) {
            Some(off) => i + off + 1,
            None => headers.len(),
        };
        if line_end < headers.len() {
            let next = headers[line_end];
            if next == b' ' || next == b'\t' {
                i = line_end;
                continue;
            }
        }
        out.push(&headers[line_start..line_end]);
        line_start = line_end;
        i = line_end;
    }
    if line_start < headers.len() {
        out.push(&headers[line_start..]);
    }
    out
}

fn memchr_lf(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b| b == b'\n')
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn find_header_end_crlf() {
        let raw = b"From: a\r\nTo: b\r\n\r\nbody";
        let (end, sep) = find_header_end(raw).unwrap();
        assert_eq!(sep, 2);
        assert_eq!(&raw[..end], b"From: a\r\nTo: b\r\n");
        assert_eq!(&raw[end + sep..], b"body");
    }

    #[test]
    fn find_header_end_lf_only() {
        let raw = b"From: a\nTo: b\n\nbody";
        let (end, sep) = find_header_end(raw).unwrap();
        assert_eq!(sep, 1);
        assert_eq!(&raw[end + sep..], b"body");
    }

    #[test]
    fn find_header_end_none_when_no_blank() {
        let raw = b"From: a\r\nTo: b\r\n";
        assert!(find_header_end(raw).is_none());
    }

    #[test]
    fn split_header_lines_folds_continuations() {
        let raw = b"Subject: line one\r\n continuation\r\nFrom: a\r\n";
        let lines = split_header_lines(raw);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"Subject: line one\r\n continuation\r\n");
        assert_eq!(lines[1], b"From: a\r\n");
    }

    #[test]
    fn encoded_word_with_clean_content_is_not_smuggling() {
        let logical: Vec<&[u8]> = vec![b"Subject: =?utf-8?B?aGVsbG8=?=\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![false]);
    }

    #[test]
    fn encoded_word_with_crlf_is_smuggling() {
        // Raw CR+LF injected inside an encoded-word, producing multiple
        // logical header lines where the `?=` terminator lands in a
        // later header than the opening `=?`.
        let logical: Vec<&[u8]> = vec![
            b"Subject: =?utf-8?B?aGVsbG8\r\n",
            b"Bcc: victim@example\r\n",
            b"?=\r\n",
        ];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![true, true, true]);
    }

    #[test]
    fn scrub_drops_smuggled_header_and_emits_warning() {
        let raw = b"From: a\r\nSubject: =?utf-8?B?x\r\nBcc: y@e\r\n?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Bcc:"));
        assert!(!out_str.contains("Subject:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn scrub_clean_message_no_warnings() {
        let raw = b"From: a@example\r\nSubject: hello\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        assert_eq!(out, raw);
        assert!(warnings.is_empty());
    }

    #[test]
    fn encoded_word_that_stays_in_one_line_is_legal() {
        let raw = b"From: a\r\nSubject: =?utf-8?B?aGVsbG8=?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("Subject: =?utf-8?B?aGVsbG8=?="));
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn dangling_encoded_word_is_dropped() {
        // =? with no matching ?= anywhere in headers.
        let raw = b"From: a\r\nSubject: =?utf-8?B?dangling\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Subject:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn dangling_encoded_word_at_last_header_is_dropped() {
        // Originating `=?` is the last logical header — the `Missing`
        // branch must still mark it even though there are no later
        // headers to search for `?=`.
        let raw = b"From: a\r\nSubject: =?utf-8?B?dangling\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(!out_str.contains("Subject:"));
        assert!(out_str.contains("body"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn legal_then_smuggled_encoded_word_in_same_header_drops_span() {
        // First `=?...?=` is a legal SameHeader match; the second `=?`
        // on the same header opens a smuggling span into later headers.
        // The detector's `scan_from` cursor must advance past the legal
        // token and still catch the second opener. The originating
        // header is dropped together with the span through `?=`.
        let raw = b"From: a\r\nSubject: =?utf-8?B?aGVsbG8=?= =?utf-8?B?x\r\nBcc: y@e\r\n?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Subject:"));
        assert!(!out_str.contains("Bcc:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn multiple_legal_encoded_words_in_one_header_are_not_flagged() {
        // Two legal SameHeader encoded-words in a single header line.
        // The `scan_from` cursor must advance past the first `?=` so the
        // second opener is detected and resolved correctly.
        let logical: Vec<&[u8]> = vec![b"Subject: =?utf-8?B?aA==?= =?utf-8?B?Yg==?=\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![false]);
    }

    #[test]
    fn parse_extracts_from_to_subject() {
        let raw = b"From: Alice <alice@example.com>\r\n\
                    To: Bob <bob@example.com>\r\n\
                    Subject: Test message\r\n\
                    Date: Tue, 8 Apr 2026 12:00:00 +0000\r\n\
                    \r\n\
                    body text";
        let content = parse_message(raw).unwrap();
        assert_eq!(
            content.meta.from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(content.meta.to, vec!["Bob <bob@example.com>".to_string()]);
        assert_eq!(content.meta.subject.as_deref(), Some("Test message"));
        assert!(content.meta.date.is_some());
        assert!(content.security_warnings.is_empty());
    }

    #[test]
    fn parse_sanitizes_subject_zero_width() {
        let raw = "From: a@example\r\nSubject: he\u{200B}llo\r\n\r\nbody".as_bytes();
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.subject.as_deref(), Some("hello"));
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::UnicodeZeroWidthStripped)
        );
    }

    #[test]
    fn parse_missing_headers_yields_none() {
        let raw = b"\r\nbody only";
        let content = parse_message(raw).unwrap();
        assert!(content.meta.from.is_none());
        assert!(content.meta.subject.is_none());
        assert_eq!(content.meta.original_size_bytes, raw.len() as u64);
    }

    #[test]
    fn parse_idn_u_label_address_passes_through_with_no_warnings() {
        // Raw UTF-8 U-label IDN (Russian "example.rf"). Sprint 4a has no
        // homograph / mixed-script detection — that's reserved for
        // Sprint 4b. This test pins the baseline: an IDN address parses
        // successfully, NFKC-normalizes idempotently, and emits zero
        // security warnings. When Sprint 4b adds lookalike detection,
        // this fixture should still pass because the domain is a
        // legitimate single-script IDN, not a homograph attack.
        let raw = "From: Тест <user@\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}>\r\n\
                   Subject: IDN baseline\r\n\
                   \r\n\
                   body"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(content.meta.from.is_some());
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}"));
        assert!(content.security_warnings.is_empty());
    }

    #[test]
    fn parse_idn_a_label_address_passes_through_byte_for_byte() {
        // Punycode A-label form of the same domain. Pure ASCII, so
        // NFKC is a no-op and the codepoint filter strips nothing.
        // Pins baseline for when Sprint 4b adds idna decoding — the
        // A-label should still pass through zero warnings here.
        let raw = b"From: Test <user@xn--e1afmkfd.xn--p1ai>\r\n\
                    Subject: IDN A-label baseline\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("xn--e1afmkfd.xn--p1ai"));
        assert!(content.security_warnings.is_empty());
    }
}
