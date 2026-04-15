//! Pre-parser header-smuggling scrubber.
//!
//! Strips logical header lines that participate in RFC 2047
//! encoded-word smuggling (raw CRLF inside an encoded-word) before
//! `mail-parser` sees the byte stream. Emits a single
//! [`WarningCode::ParseHeaderSmugglingBlocked`] aggregated warning.

use crate::output::{SecurityWarning, WarningCode};

/// Scan the header block for raw CRLF inside RFC 2047 encoded-words.
/// Drop any offending logical header(s) and emit
/// [`WarningCode::ParseHeaderSmugglingBlocked`].
///
/// Returns a byte vector containing the message with the offending
/// header lines removed.
pub(super) fn scrub_header_smuggling(raw: &[u8], warnings: &mut Vec<SecurityWarning>) -> Vec<u8> {
    let Some((header_end, _sep_len)) = find_header_end(raw) else {
        return raw.to_vec(); // no headers = no smuggling
    };

    let headers = &raw[..header_end];
    let body = &raw[header_end..];

    let logical = split_header_lines(headers);
    let drop_mask = detect_smuggling_spans(&logical);
    let dropped = drop_mask.iter().filter(|flag| **flag).count();

    let mut kept: Vec<u8> = Vec::with_capacity(headers.len());
    let mut dropped_names: Vec<String> = Vec::new();
    for (idx, line) in logical.iter().enumerate() {
        if drop_mask[idx] {
            // Capture the header name (bytes before first ':') for
            // audit reconstruction. Bounded at 8 names to cap log
            // growth; names are routed through the unicode sanitizer
            // so attacker-controlled bytes cannot leak into the
            // warning detail verbatim.
            if dropped_names.len() < 8
                && let Some(colon) = line.iter().position(|&b| b == b':')
                && let Ok(name) = std::str::from_utf8(&line[..colon])
            {
                let (sanitized, _) =
                    crate::unicode::sanitize(name.as_bytes(), Some("utf-8"), 64, "headers");
                if !sanitized.is_empty() {
                    dropped_names.push(sanitized);
                }
            }
        } else {
            kept.extend_from_slice(line);
        }
    }
    if dropped > 0 {
        let detail = if dropped_names.is_empty() {
            format!("count={dropped}")
        } else {
            format!("count={dropped} names=[{}]", dropped_names.join(","))
        };
        warnings.push(SecurityWarning::at(
            WarningCode::ParseHeaderSmugglingBlocked,
            detail,
            "headers",
        ));
    }
    kept.extend_from_slice(body);
    kept
}

/// Walk the logical-header slice and mark every header index that
/// participates in an RFC 2047 smuggling attempt: either an encoded-word
/// whose `=?` and `?=` terminators land in different logical headers,
/// or a dangling `=?` with no `?=` anywhere in the remaining block.
pub(super) fn detect_smuggling_spans(logical: &[&[u8]]) -> Vec<bool> {
    let mut mask = vec![false; logical.len()];
    let mut idx = 0_usize;
    let mut scan_from = 0_usize;
    while idx < logical.len() {
        let header = logical[idx];
        let search_start = scan_from.min(header.len());
        let Some(rel) = header[search_start..].windows(2).position(|w| w == b"=?") else {
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
        && let Some(rel) = first[start_offset..].windows(2).position(|w| w == b"?=")
    {
        return EncodedWordEnd::SameHeader(start_offset + rel);
    }
    for (offset, line) in logical.iter().enumerate().skip(start_idx + 1) {
        if line.windows(2).any(|w| w == b"?=") {
            return EncodedWordEnd::LaterHeader(offset);
        }
    }
    EncodedWordEnd::Missing
}

/// Find the byte offset where the header block ends (exclusive of the
/// blank-line separator). Handles both CRLF and LF line endings.
/// Returns `(header_end, separator_length)`.
pub(super) fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos + 2, 2));
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some((pos + 1, 1));
    }
    None
}

/// Split a header block into individual logical header lines.
/// Preserves continuation (folded) lines as part of their parent line
/// by joining on leading whitespace. Each returned slice INCLUDES its
/// terminating CRLF or LF.
pub(super) fn split_header_lines(headers: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut line_start = 0_usize;
    let mut i = 0_usize;
    while i < headers.len() {
        let line_end = match headers[i..].iter().position(|&b| b == b'\n') {
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
