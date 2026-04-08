//! Message parsing via `mail-parser`.
//!
//! This module owns all interaction with `mail-parser`; no other
//! module in `rimap-content` imports `mail-parser` types directly.
//! It applies hard limits declared as compile-time constants and
//! routes every extracted string through [`crate::unicode::sanitize`]
//! so downstream consumers see only Unicode-clean text.

use crate::error::ContentError;
use crate::output::{Content, ContentMeta, SecurityWarning, Untrusted, WarningCode};

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
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = scrub_header_smuggling(raw, &mut warnings);
    let _ = scrubbed; // Mail-parser walk lands in Task 6.

    // Placeholder return until Task 6 wires mail-parser.
    Ok(Content {
        meta: ContentMeta {
            original_size_bytes: raw.len() as u64,
            ..ContentMeta::default()
        },
        untrusted: Untrusted::default(),
        security_warnings: warnings,
    })
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
    fn parse_message_stub_returns_empty_content() {
        let raw = b"From: a\r\n\r\nhello";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.original_size_bytes, raw.len() as u64);
        assert!(content.untrusted.body_text.is_empty());
        assert!(content.security_warnings.is_empty());
    }
}
