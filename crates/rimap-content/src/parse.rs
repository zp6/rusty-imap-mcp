//! Message parsing via `mail-parser`.
//!
//! This module owns all interaction with `mail-parser`; no other
//! module in `rimap-content` imports `mail-parser` types directly.
//! It applies hard limits declared as compile-time constants and
//! routes every extracted string through [`crate::unicode::sanitize`]
//! so downstream consumers see only Unicode-clean text.

use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders as _, PartType};
use time::OffsetDateTime;

use crate::error::ContentError;
use crate::html;
use crate::lookalike;
use crate::output::{
    AttachmentMeta, Content, ContentMeta, MailingListInfo, SecurityWarning, Untrusted, WarningCode,
};
use crate::unicode;

/// Maximum raw message size accepted. Messages larger than this are
/// rejected with [`ContentError::LimitExceeded`] with `kind = "message_bytes"`
/// before any parsing work is performed.
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

/// Maximum per-text-part size after sanitization.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum total sanitized body bytes across `body_text` +
/// `alternate_parts`. Enforced in addition to the per-part
/// [`MAX_BODY_BYTES`] cap to prevent a multipart message from
/// producing a `Content` too large for the MCP stdio transport.
pub const MAX_TOTAL_BODY_BYTES: usize = 4 * 1024 * 1024;

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
/// - [`ContentError::LimitExceeded`] with `kind = "message_bytes"` when
///   `raw.len() > MAX_MESSAGE_BYTES`, and with other `kind` values when
///   MIME depth, part count, or header count exceed their hard limits.
/// - [`ContentError::Malformed`] if `mail-parser` rejects the byte stream.
pub fn parse_message(raw: &[u8]) -> Result<Content, ContentError> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err(ContentError::LimitExceeded {
            kind: "message_bytes",
            limit: MAX_MESSAGE_BYTES,
        });
    }
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

    let mut meta = extract_meta(&message, original_size_bytes, &mut warnings);
    let bodies = extract_bodies(&message, &mut warnings)?;
    meta.body_truncated = bodies.body_truncated;
    let html_anchor_hrefs = bodies.anchor_hrefs;

    let mut content = Content {
        meta,
        untrusted: Untrusted {
            body_text: bodies.primary_text,
            body_html: bodies.body_html,
            alternate_parts: bodies.alternates,
        },
        security_warnings: warnings,
    };

    let header_domains = collect_header_domains(&message);
    let lookalike_warnings = lookalike::audit(&lookalike::LookalikeInput {
        meta: &content.meta,
        body_text: &content.untrusted.body_text,
        anchor_hrefs: &html_anchor_hrefs,
        header_domains,
    });
    content.security_warnings.extend(lookalike_warnings);

    Ok(content)
}

/// Append the domain of every address in `group` to `out`, tagging each
/// with `label`. No-op when `group` is `None`.
fn push_domains_from(group: Option<&Address<'_>>, label: &str, out: &mut Vec<(String, String)>) {
    let Some(address) = group else { return };
    for addr in address.iter() {
        if let Some(domain) = addr_domain(addr) {
            out.push((domain, label.to_string()));
        }
    }
}

/// Pre-extract domains from structured `Addr.address` fields for
/// all header address sources (From, To, Cc, Reply-To). Using the
/// parser's structured data is more reliable than re-parsing the
/// rendered display string.
fn collect_header_domains(message: &Message<'_>) -> Vec<(String, String)> {
    let mut domains = Vec::new();
    push_domains_from(message.from(), "header:from", &mut domains);
    push_domains_from(message.to(), "header:to", &mut domains);
    push_domains_from(message.cc(), "header:cc", &mut domains);
    push_domains_from(message.reply_to(), "header:reply_to", &mut domains);
    domains
}

/// Extract the domain portion from a structured `mail_parser::Addr`.
fn addr_domain(addr: &mail_parser::Addr<'_>) -> Option<String> {
    let email = addr.address.as_deref()?;
    let (_local, domain) = email.rsplit_once('@')?;
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
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
    let reply_to = first_address_string(message.reply_to(), "header:reply_to", warnings);
    let subject = sanitize_opt_str(message.subject(), "header:subject", warnings);
    let date = message.date().and_then(convert_datetime);
    let message_id = sanitize_opt_str(message.message_id(), "header:message_id", warnings);
    let in_reply_to =
        header_value_first_text(message.in_reply_to(), "header:in_reply_to", warnings);
    let references = header_value_all_text(message.references(), "header:references", warnings);
    let mailing_list = extract_mailing_list(message, warnings);
    let attachments = extract_attachments(message, warnings);

    ContentMeta {
        from,
        to,
        cc,
        reply_to,
        subject,
        date,
        message_id,
        in_reply_to,
        references,
        mailing_list,
        attachments,
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
        .map(|addr| {
            audit_addr_domain_bidi(addr, location, warnings);
            let raw = format_addr(addr);
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
    let addr = address?.first()?;
    audit_addr_domain_bidi(addr, location, warnings);
    let raw = format_addr(addr);
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
        Some(_) | None => email.to_string(),
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
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
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
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return Vec::new(),
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

/// Result of walking a message's text bodies: the primary text body,
/// any alternate text parts, an optional sanitized HTML rendering, the
/// anchor hrefs that survived sanitization, and whether any part was
/// truncated.
#[derive(Debug)]
struct BodyExtraction {
    primary_text: String,
    alternates: Vec<String>,
    body_html: Option<String>,
    anchor_hrefs: Vec<String>,
    body_truncated: bool,
}

/// Walk `message.text_body`, enforce MIME limits, and sanitize each
/// part into a `BodyExtraction`. Emits `ParseBodyTruncated` on any
/// part whose raw byte length exceeds `MAX_BODY_BYTES`; terminal
/// `LimitExceeded` errors for part count or depth overflow.
fn extract_bodies(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<BodyExtraction, ContentError> {
    let part_count = message.parts.len();
    if part_count > MAX_MIME_PARTS {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseMimePartCountExceeded,
            detail: Some(format!("count={part_count} limit={MAX_MIME_PARTS}")),
            location: Some("mime".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "mime_parts",
            limit: MAX_MIME_PARTS,
        });
    }

    check_mime_depth(message, warnings)?;

    // Determine the part id of the first HTML body so only one HTML
    // part per message flows through `html::process`. mail-parser 0.11
    // exposes html bodies via `message.html_body: Vec<MessagePartId>`
    // (MessagePartId = u32).
    let primary_html_part_id: Option<usize> = message.html_body.first().map(|id| *id as usize);

    let mut state = BodyWalkState::default();

    for (idx, &part_id) in message.text_body.iter().enumerate() {
        let Some(part) = message.parts.get(part_id as usize) else {
            continue;
        };
        match &part.body {
            PartType::Text(s) => {
                let raw_bytes = s.as_bytes();
                process_text_part(part, raw_bytes, idx, &mut state, warnings);
            }
            PartType::Html(cow) => {
                let is_primary = primary_html_part_id == Some(part_id as usize);
                if !is_primary {
                    continue;
                }
                process_html_part(part, cow.as_bytes(), &mut state, warnings)?;
            }
            PartType::Message(_)
            | PartType::Binary(_)
            | PartType::InlineBinary(_)
            | PartType::Multipart(_) => continue,
        }
        if state.total_bytes >= MAX_TOTAL_BODY_BYTES {
            state.body_truncated = true;
            warnings.push(SecurityWarning {
                code: WarningCode::ParseBodyTruncated,
                detail: Some(format!(
                    "total={} limit={MAX_TOTAL_BODY_BYTES}",
                    state.total_bytes
                )),
                location: Some("body:aggregate".to_string()),
            });
            break;
        }
    }

    Ok(BodyExtraction {
        primary_text: state.primary_text.unwrap_or_default(),
        alternates: state.alternates,
        body_html: state.body_html,
        anchor_hrefs: state.anchor_hrefs,
        body_truncated: state.body_truncated,
    })
}

/// Mutable accumulator threaded through `extract_bodies` and its
/// per-part helpers. Keeps the main loop body small enough to stay
/// inside the workspace function-length and complexity limits.
#[derive(Debug, Default)]
struct BodyWalkState {
    primary_text: Option<String>,
    alternates: Vec<String>,
    body_html: Option<String>,
    anchor_hrefs: Vec<String>,
    body_truncated: bool,
    total_bytes: usize,
}

/// Decode and sanitize a single `text/plain` part, updating `state`
/// and pushing any new warnings (including `ParseBodyTruncated` when
/// the raw part exceeds [`MAX_BODY_BYTES`]).
fn process_text_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    idx: usize,
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) {
    if raw_bytes.len() > MAX_BODY_BYTES {
        state.body_truncated = true;
        warnings.push(SecurityWarning {
            code: WarningCode::ParseBodyTruncated,
            detail: Some(format!(
                "original={} limit={}",
                raw_bytes.len(),
                MAX_BODY_BYTES
            )),
            location: Some(format!("body:text[{idx}]")),
        });
    }
    let location = format!("body:text[{idx}]");
    let charset = part_charset(part);
    let (text, mut new_warnings) =
        unicode::sanitize(raw_bytes, charset.as_deref(), MAX_BODY_BYTES, &location);
    warnings.append(&mut new_warnings);
    state.total_bytes = state.total_bytes.saturating_add(text.len());
    if state.primary_text.is_none() {
        state.primary_text = Some(text);
    } else {
        state.alternates.push(text);
    }
}

/// Run the primary `text/html` part through [`crate::html::process`].
///
/// On success: merges the produced warnings into `warnings`, places
/// the extracted plain text at the primary text slot if empty (else
/// pushes to alternates), and stores the sanitized html and anchor
/// hrefs on `state`.
///
/// On `ContentError::LimitExceeded`: emits a `ParseBodyTruncated`
/// warning at `body:html` and continues. Other errors propagate.
fn process_html_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let charset = part_charset(part);
    match html::process(raw_bytes, charset.as_deref()) {
        Ok(result) => {
            warnings.extend(result.warnings);
            state.total_bytes = state.total_bytes.saturating_add(result.body_text.len());
            if state.primary_text.is_none() {
                state.primary_text = Some(result.body_text);
            } else {
                state.alternates.push(result.body_text);
            }
            state.body_html = Some(result.body_html);
            state.anchor_hrefs = result.anchor_hrefs;
            Ok(())
        }
        Err(ContentError::LimitExceeded { kind, limit }) => {
            state.body_truncated = true;
            warnings.push(SecurityWarning {
                code: WarningCode::ParseBodyTruncated,
                detail: Some(format!(
                    "original={} limit={limit} kind={kind}",
                    raw_bytes.len()
                )),
                location: Some("body:html".to_string()),
            });
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Read the `charset` attribute off a part's Content-Type header.
fn part_charset(part: &mail_parser::MessagePart<'_>) -> Option<String> {
    part.content_type()
        .and_then(|ct| ct.attribute("charset"))
        .map(str::to_string)
}

/// Enforce [`MAX_MIME_DEPTH`] by walking the part tree from part 0.
fn check_mime_depth(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let depth = compute_max_depth(message);
    if depth > MAX_MIME_DEPTH {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseMimeDepthExceeded,
            detail: Some(format!("depth={depth} limit={MAX_MIME_DEPTH}")),
            location: Some("mime".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: MAX_MIME_DEPTH,
        });
    }
    Ok(())
}

/// Walk the MIME tree from part 0 and return the maximum depth.
fn compute_max_depth(message: &Message<'_>) -> usize {
    debug_assert!(
        message.parts.len() <= MAX_MIME_PARTS,
        "compute_max_depth must only be called after MAX_MIME_PARTS enforcement"
    );
    depth_recursive(message, 0, 1)
}

/// Recursive helper used by [`compute_max_depth`]; visits `part_id`
/// at level `current` and returns the deepest level reachable.
fn depth_recursive(message: &Message<'_>, part_id: usize, current: usize) -> usize {
    // Defensive short-circuit: bound recursion independently of any
    // mail-parser tree invariant. If current already exceeds
    // MAX_MIME_DEPTH, the caller will reject; no need to walk deeper.
    if current > MAX_MIME_DEPTH {
        return current;
    }
    let Some(part) = message.parts.get(part_id) else {
        return current;
    };
    match &part.body {
        PartType::Multipart(child_ids) => child_ids
            .iter()
            .map(|&child_id| depth_recursive(message, child_id as usize, current + 1))
            .max()
            .unwrap_or(current),
        PartType::Message(_) => current + 1,
        PartType::Text(_) | PartType::Html(_) | PartType::Binary(_) | PartType::InlineBinary(_) => {
            current
        }
    }
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
        warnings.push(SecurityWarning {
            code: WarningCode::ParseHeaderSmugglingBlocked,
            detail: Some(detail),
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
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
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
fn split_header_lines(headers: &[u8]) -> Vec<&[u8]> {
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

/// Walk `message.attachments` and build an `AttachmentMeta` for each,
/// emitting `ParseMimeTypeMismatch` when magic-byte sniffing disagrees
/// with the declared Content-Type.
fn extract_attachments(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<AttachmentMeta> {
    let mut out = Vec::with_capacity(message.attachments.len());
    for (idx, part_id) in message.attachments.iter().enumerate() {
        let Some(part) = message.parts.get(*part_id as usize) else {
            continue;
        };
        out.push(build_attachment_meta(part, idx, warnings));
    }
    out
}

/// Construct a single `AttachmentMeta` from a part, performing magic-byte
/// sniffing and sanitizing all extracted strings.
fn build_attachment_meta(
    part: &mail_parser::MessagePart<'_>,
    idx: usize,
    warnings: &mut Vec<SecurityWarning>,
) -> AttachmentMeta {
    let declared_ct = match part.content_type() {
        Some(ct) => content_type_string(ct),
        None => "application/octet-stream".to_string(),
    };

    let body = part_bytes(part);
    let sniffed = sniff_content_types(body);
    if sniffed.len() > 1 {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseAttachmentPolyglot,
            detail: Some(format!(
                "declared={declared_ct} sniffed={}",
                sniffed.join(",")
            )),
            location: Some(format!("attachment[{idx}]")),
        });
    }
    if !sniffed.is_empty() {
        let mismatch = !sniffed
            .iter()
            .any(|s| content_types_compatible(&declared_ct, s));
        if mismatch {
            warnings.push(SecurityWarning {
                code: WarningCode::ParseMimeTypeMismatch,
                detail: Some(format!(
                    "declared={declared_ct} sniffed={}",
                    sniffed.join(",")
                )),
                location: Some(format!("attachment[{idx}]")),
            });
        }
    }

    let filename = part
        .attachment_name()
        .map(|name| sanitize_attachment_filename(name, idx, warnings));

    let content_id = part.content_id().map(|id| {
        let (text, mut ws) = unicode::sanitize(
            id.as_bytes(),
            Some("utf-8"),
            MAX_HEADER_BYTES,
            &format!("attachment[{idx}]:content_id"),
        );
        warnings.append(&mut ws);
        text
    });

    let (sanitized_ct, mut ct_ws) = unicode::sanitize(
        declared_ct.as_bytes(),
        Some("utf-8"),
        MAX_HEADER_BYTES,
        &format!("attachment[{idx}]:content_type"),
    );
    warnings.append(&mut ct_ws);

    AttachmentMeta {
        filename,
        content_type: sanitized_ct,
        size_bytes: u64::from(part.raw_len()),
        content_id,
        is_inline: is_inline(part),
    }
}

/// Sanitize a raw attachment filename for safe downstream display.
///
/// The pipeline matches the invariants the rest of `build_attachment_meta`
/// relies on: bidi-override detection, double-extension detection, the
/// shared unicode sanitizer, and `sanitize_filename` rewriting. Every
/// step that triggers a warning pushes a [`SecurityWarning`] tagged
/// with the attachment index so the caller does not need to know the
/// per-warning codes.
fn sanitize_attachment_filename(
    name: &str,
    idx: usize,
    warnings: &mut Vec<SecurityWarning>,
) -> String {
    if contains_bidi_override(name) {
        warnings.push(SecurityWarning {
            code: WarningCode::LookalikeFilenameExtensionSpoof,
            detail: Some(format!("raw={name:?},contains_bidi_override=true")),
            location: Some(format!("attachment[{idx}]:filename")),
        });
    }
    if let Some((penult, final_ext)) = detect_double_extension(name) {
        warnings.push(SecurityWarning {
            code: WarningCode::LookalikeFilenameExtensionSpoof,
            detail: Some(format!(
                "reason=double_extension,visible=.{penult},\
                 declared=.{penult}.{final_ext}"
            )),
            location: Some(format!("attachment[{idx}]:filename")),
        });
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
        warnings.push(SecurityWarning {
            code: WarningCode::ParseAttachmentFilenameRewritten,
            detail: Some(format!("original={unicode_clean:?}")),
            location: Some(format!("attachment[{idx}]:filename")),
        });
    }
    safe
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

/// Return the decoded byte payload of a part, or an empty slice for
/// container parts (nested message / multipart).
fn part_bytes<'a>(part: &'a mail_parser::MessagePart<'_>) -> &'a [u8] {
    match &part.body {
        PartType::Text(s) | PartType::Html(s) => s.as_bytes(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.as_ref(),
        PartType::Message(_) | PartType::Multipart(_) => &[],
    }
}

/// `true` if the part is an inline attachment, using either the
/// `PartType::InlineBinary` variant or an explicit `Content-Disposition:
/// inline` header.
fn is_inline(part: &mail_parser::MessagePart<'_>) -> bool {
    match &part.body {
        PartType::InlineBinary(_) => true,
        PartType::Text(_)
        | PartType::Html(_)
        | PartType::Binary(_)
        | PartType::Message(_)
        | PartType::Multipart(_) => match part.content_disposition() {
            Some(cd) => cd.is_inline(),
            None => false,
        },
    }
}

/// Render a `ContentType` as a `"type/subtype"` string, falling back to
/// just the type when the subtype is absent.
fn content_type_string(ct: &mail_parser::ContentType<'_>) -> String {
    match ct.subtype() {
        Some(sub) => format!("{}/{}", ct.ctype(), sub),
        None => ct.ctype().to_string(),
    }
}

/// Sniff the content type of `body` from its leading magic bytes.
/// Returns the list of ALL matching signatures — a single match is
/// normal, multiple matches indicate a polyglot file.
fn sniff_content_types(body: &[u8]) -> Vec<&'static str> {
    let signatures: &[(&[u8], &'static str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"%PDF", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"MZ", "application/x-msdownload"),
        (b"\x7fELF", "application/x-elf"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07\x00", "application/vnd.rar"),
        (b"Rar!\x1a\x07\x01\x00", "application/vnd.rar"),
        (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "application/x-ole-storage",
        ),
    ];
    let mut matches: Vec<&'static str> = Vec::new();
    for (sig, label) in signatures {
        if body.starts_with(sig) && !matches.contains(label) {
            matches.push(label);
        }
    }
    matches
}

/// Return `true` if the declared content type is compatible with a
/// sniffed type. Exact (case-insensitive) matches are compatible.
/// `OpenXML` / `OpenDocument` declarations are compatible with a sniffed
/// `application/zip` (both are ZIP-based office formats).
///
/// `application/octet-stream` is NOT treated as a universal wildcard —
/// caller logic in `build_attachment_meta` decides whether an empty
/// sniff result makes `application/octet-stream` acceptable.
fn content_types_compatible(declared: &str, sniffed: &str) -> bool {
    if declared.eq_ignore_ascii_case(sniffed) {
        return true;
    }
    if sniffed == "application/zip" {
        let dl = declared.to_ascii_lowercase();
        if dl.contains("openxmlformats") || dl.contains("opendocument") {
            return true;
        }
    }
    false
}

/// Extract `List-ID` / `List-Unsubscribe` / `List-Post` into a
/// `MailingListInfo`, returning `None` when none of the headers are
/// present.
fn extract_mailing_list(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<MailingListInfo> {
    let list_id = sanitize_header_value(message.list_id(), "header:list_id", warnings);
    let list_unsubscribe = sanitize_header_value(
        message.list_unsubscribe(),
        "header:list_unsubscribe",
        warnings,
    );
    let list_post = sanitize_header_value(message.list_post(), "header:list_post", warnings);

    if list_id.is_none() && list_unsubscribe.is_none() && list_post.is_none() {
        return None;
    }
    Some(MailingListInfo {
        list_id,
        list_unsubscribe,
        list_post,
    })
}

/// Coerce a `HeaderValue` to a sanitized string. Handles `Text`,
/// `TextList`, and `Address` variants — mail-parser parses `List-*`
/// headers as addresses, so we flatten them back to a display string.
fn sanitize_header_value(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::Address(address) => address
            .iter()
            .map(|addr| {
                audit_addr_domain_bidi(addr, location, warnings);
                format_addr(addr)
            })
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
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
fn sanitize_filename(name: &str, idx: usize) -> (String, bool) {
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
fn contains_bidi_override(s: &str) -> bool {
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

const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "txt", "csv", "rtf",
];

/// Reserved Windows filename stems (case-insensitive). Used by
/// [`sanitize_filename`]. Non-enum input means we identify membership
/// via a named slice rather than a `matches!` pattern.
const RESERVED_WINDOWS_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "msi", "app", "dmg", "sh", "com", "pif",
    "jar", "lnk",
];

fn detect_double_extension(name: &str) -> Option<(String, String)> {
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
fn last_extension(filename: &str) -> Option<&str> {
    filename.rsplit_once('.').map(|(_, ext)| ext)
}

/// If `raw_domain` contains any bidi-override codepoint, emit a
/// `LookalikeHomographDomain` warning with `reason=bidi_pre_strip`.
/// Detection must occur BEFORE `unicode::sanitize` strips the bidi
/// chars; afterwards no signal remains.
fn audit_domain_bidi_prestrip(
    raw_domain: &str,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    if !contains_bidi_override(raw_domain) {
        return;
    }
    let ascii = idna::domain_to_ascii(raw_domain.trim()).unwrap_or_else(|_| "invalid".to_string());
    warnings.push(SecurityWarning {
        code: WarningCode::LookalikeHomographDomain,
        detail: Some(format!("domain={ascii},reason=bidi_pre_strip")),
        location: Some(location.to_string()),
    });
}

/// Extract the domain from a `mail_parser::Addr` and run the
/// pre-strip bidi audit. No-op when the address is missing or has no
/// `@` separator.
fn audit_addr_domain_bidi(
    addr: &mail_parser::Addr<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    let Some(email) = addr.address.as_deref() else {
        return;
    };
    let Some((_local, domain)) = email.rsplit_once('@') else {
        return;
    };
    audit_domain_bidi_prestrip(domain, location, warnings);
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
#[expect(clippy::panic, reason = "test failure paths")]
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
        assert!(
            warnings[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("names=[Subject"),
            "detail should include names=[Subject..., got: {:?}",
            warnings[0].detail
        );
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
    fn parse_idn_u_label_address_emits_only_idn_informational() {
        // Raw UTF-8 U-label IDN (Russian "example.rf"). Sprint 4b's
        // lookalike pass classifies any IDN through `idna::domain_to_ascii`,
        // so a legitimate single-script Cyrillic domain produces an
        // informational `LookalikeIdnPunycode` warning but MUST NOT
        // produce a `LookalikeMixedScript` warning — pure Cyrillic is
        // single-script.
        let raw = "From: Тест <user@\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}>\r\n\
                   Subject: IDN baseline\r\n\
                   \r\n\
                   body"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(content.meta.from.is_some());
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}"));
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "single-script Cyrillic IDN must not flag mixed-script, got {:?}",
            content.security_warnings
        );
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeIdnPunycode),
            "expected informational LookalikeIdnPunycode, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn parse_idn_a_label_address_emits_only_idn_informational() {
        // Punycode A-label form of the same Cyrillic domain. Pure ASCII
        // input, so NFKC and the codepoint filter pass it through; the
        // lookalike pass decodes the `xn--` labels and emits the same
        // informational `LookalikeIdnPunycode` warning, with no
        // mixed-script signal.
        let raw = b"From: Test <user@xn--e1afmkfd.xn--p1ai>\r\n\
                    Subject: IDN A-label baseline\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("xn--e1afmkfd.xn--p1ai"));
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "punycode A-label of Cyrillic IDN must not flag mixed-script, got {:?}",
            content.security_warnings
        );
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeIdnPunycode),
            "expected informational LookalikeIdnPunycode, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn parse_extracts_text_plain_body() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    hello world";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "hello world");
        assert!(content.untrusted.alternate_parts.is_empty());
        assert!(!content.meta.body_truncated);
    }

    #[test]
    fn parse_multipart_alternative_picks_text_plain_first() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/alternative; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    plain version\r\n\
                    --BOUND\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <p>html version</p>\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "plain version");
        assert!(!content.untrusted.body_text.contains("<p>"));
    }

    #[test]
    fn content_html_only_populates_body_html_and_body_text() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <html><body><p>visible text</p></body></html>\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "visible text");
        assert!(content.untrusted.body_html.is_some());
        let body_html = content.untrusted.body_html.as_deref().unwrap();
        assert!(body_html.contains("<p>"));
        assert!(body_html.contains("visible text"));
    }

    #[test]
    fn content_html_only_with_hidden_content_emits_warning() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <html><body><p>ok</p>\
                    <div style=\"display:none\">hidden</div></body></html>\r\n";
        let content = parse_message(raw).unwrap();
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::HtmlHiddenContentDetected)),
            "expected HtmlHiddenContentDetected warning, got {:?}",
            content.security_warnings
        );
        assert!(!content.untrusted.body_text.contains("hidden"));
    }

    #[test]
    fn parse_oversized_body_emits_truncation_warning() {
        let mut raw = Vec::from(
            &b"From: a@example\r\n\
               Content-Type: text/plain; charset=utf-8\r\n\
               \r\n"[..],
        );
        raw.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 1024));
        let content = parse_message(&raw).unwrap();
        assert!(content.meta.body_truncated);
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseBodyTruncated)
        );
        assert!(content.untrusted.body_text.len() <= MAX_BODY_BYTES);
    }

    #[test]
    fn parse_enforces_aggregate_body_cap() {
        let mut raw = String::from(
            "From: a@example\r\n\
             Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
             \r\n",
        );
        let part = "a".repeat(512 * 1024);
        for _ in 0..10 {
            raw.push_str("--BOUND\r\nContent-Type: text/plain\r\n\r\n");
            raw.push_str(&part);
            raw.push_str("\r\n");
        }
        raw.push_str("--BOUND--\r\n");
        let content = parse_message(raw.as_bytes()).unwrap();
        let total = content.untrusted.body_text.len()
            + content
                .untrusted
                .alternate_parts
                .iter()
                .map(String::len)
                .sum::<usize>();
        assert!(
            total <= MAX_TOTAL_BODY_BYTES,
            "total={total} cap={MAX_TOTAL_BODY_BYTES}"
        );
        assert!(content.meta.body_truncated);
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.location.as_deref() == Some("body:aggregate"))
        );
    }

    #[test]
    fn parse_extracts_attachment_metadata() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n\
                    --BOUND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=\"pic.png\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\
                    \r\n\
                    iVBORw0KGgo=\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.attachments.len(), 1);
        let att = &content.meta.attachments[0];
        assert_eq!(att.filename.as_deref(), Some("pic.png"));
        assert_eq!(att.content_type, "image/png");
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseMimeTypeMismatch)
        );
    }

    #[test]
    fn parse_detects_mime_type_spoofing() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n\
                    --BOUND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=\"fake.png\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\
                    \r\n\
                    TVqQAAMAAAA=\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseMimeTypeMismatch)
        );
    }

    #[test]
    fn sniff_detects_elf() {
        assert_eq!(
            sniff_content_types(b"\x7fELFblah"),
            vec!["application/x-elf"]
        );
    }

    #[test]
    fn sniff_detects_macho_64bit_le() {
        assert_eq!(
            sniff_content_types(b"\xcf\xfa\xed\xfeblah"),
            vec!["application/x-mach-binary"]
        );
    }

    #[test]
    fn sniff_detects_macho_fat_binary() {
        assert_eq!(
            sniff_content_types(b"\xca\xfe\xba\xbeblah"),
            vec!["application/x-mach-binary"]
        );
    }

    #[test]
    fn sniff_detects_7z() {
        assert_eq!(
            sniff_content_types(b"7z\xbc\xaf\x27\x1cblah"),
            vec!["application/x-7z-compressed"]
        );
    }

    #[test]
    fn sniff_detects_ole2() {
        assert_eq!(
            sniff_content_types(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1blah"),
            vec!["application/x-ole-storage"]
        );
    }

    #[test]
    fn sniff_empty_for_unknown() {
        assert!(sniff_content_types(b"random text").is_empty());
    }

    #[test]
    fn content_types_octet_stream_no_longer_wildcard() {
        // application/octet-stream is no longer compatible with a specific
        // sniffed type — the caller handles the "sniff empty" case separately.
        assert!(!content_types_compatible(
            "application/octet-stream",
            "application/x-msdownload"
        ));
    }

    #[test]
    fn content_types_openxml_still_compatible_with_zip() {
        assert!(content_types_compatible(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
        ));
    }

    #[test]
    fn content_types_exact_match() {
        assert!(content_types_compatible("image/png", "image/png"));
        assert!(content_types_compatible("IMAGE/PNG", "image/png"));
    }

    #[test]
    fn parse_extracts_mailing_list_headers() {
        let raw = b"From: announce@example\r\n\
                    List-ID: <dev.example.com>\r\n\
                    List-Unsubscribe: <mailto:unsub@example>\r\n\
                    List-Post: <mailto:dev@example>\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let ml = content.meta.mailing_list.unwrap();
        assert!(
            ml.list_id
                .as_deref()
                .unwrap_or("")
                .contains("dev.example.com")
        );
        assert!(
            ml.list_unsubscribe
                .as_deref()
                .unwrap_or("")
                .contains("unsub@example")
        );
        assert!(
            ml.list_post
                .as_deref()
                .unwrap_or("")
                .contains("dev@example")
        );
    }

    #[test]
    fn parse_no_mailing_list_when_headers_absent() {
        let raw = b"From: a@example\r\n\r\nbody";
        let content = parse_message(raw).unwrap();
        assert!(content.meta.mailing_list.is_none());
    }

    #[test]
    fn parse_rejects_oversize_message() {
        let mut raw = Vec::from(&b"From: a@example\r\n\r\n"[..]);
        raw.resize(MAX_MESSAGE_BYTES + 1, b'x');
        let err = parse_message(&raw).unwrap_err();
        let ContentError::LimitExceeded { kind, limit } = err else {
            panic!("expected LimitExceeded message_bytes, got {err:?}");
        };
        assert_eq!(kind, "message_bytes");
        assert_eq!(limit, MAX_MESSAGE_BYTES);
    }

    #[test]
    fn parse_rejects_mime_depth_bomb() {
        // Build 12 properly nested multipart containers. Each level's
        // boundary opens a child whose own Content-Type declares the
        // next level's boundary.
        use std::fmt::Write as _;
        let depth = 12;
        let mut raw = String::from("From: a@example\r\n");
        raw.push_str("Content-Type: multipart/mixed; boundary=\"B0\"\r\n\r\n");
        for i in 0..depth - 1 {
            write!(raw, "--B{i}\r\n").unwrap();
            write!(
                raw,
                "Content-Type: multipart/mixed; boundary=\"B{}\"\r\n\r\n",
                i + 1
            )
            .unwrap();
        }
        write!(raw, "--B{}\r\n", depth - 1).unwrap();
        raw.push_str("Content-Type: text/plain\r\n\r\ninner\r\n");
        for i in (0..depth).rev() {
            write!(raw, "--B{i}--\r\n").unwrap();
        }
        let err = parse_message(raw.as_bytes()).unwrap_err();
        let ContentError::LimitExceeded { kind, .. } = err else {
            panic!("expected LimitExceeded, got {err:?}");
        };
        assert!(
            kind == "mime_depth" || kind == "mime_parts",
            "expected mime_depth or mime_parts, got {kind}"
        );
    }

    #[test]
    fn sanitize_filename_strips_path_separators() {
        let (out, rewritten) = sanitize_filename("../../etc/passwd", 0);
        assert!(!out.contains('/'));
        assert!(!out.contains(".."));
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_strips_backslash_traversal() {
        let (out, rewritten) = sanitize_filename("..\\..\\Windows\\System32\\evil.dll", 0);
        assert!(!out.contains('\\'));
        assert!(!out.contains(".."));
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_prefixes_reserved_windows_names() {
        let (out, rewritten) = sanitize_filename("CON.txt", 0);
        assert_eq!(out, "_CON.txt");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_trims_trailing_dots_and_spaces() {
        let (out, rewritten) = sanitize_filename("report.pdf. . ", 0);
        assert_eq!(out, "report.pdf");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_empty_fallback() {
        let (out, rewritten) = sanitize_filename("...", 7);
        assert_eq!(out, "attachment_7");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_clean_passes_through() {
        let (out, rewritten) = sanitize_filename("invoice-2026-04.pdf", 0);
        assert_eq!(out, "invoice-2026-04.pdf");
        assert!(!rewritten);
    }

    #[test]
    fn lookalike_homograph_anchor_fires_via_parse_message() {
        // HTML body with an anchor whose href domain mixes Latin with a
        // Cyrillic 'а' (U+0430). `parse_message` must invoke
        // `lookalike::audit` and surface a `LookalikeMixedScript`
        // warning located at `html:anchor_href`.
        let raw = "From: a@example\r\n\
                   Content-Type: text/html; charset=utf-8\r\n\
                   \r\n\
                   <html><body><a href=\"https://p\u{0430}ypal.com/login\">click</a></body></html>\r\n"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeMixedScript
                    && w.location.as_deref() == Some("html:anchor_href")
            }),
            "expected LookalikeMixedScript at html:anchor_href, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn contains_bidi_override_detects_rlo() {
        assert!(contains_bidi_override("invoice\u{202E}gpj.exe"));
        assert!(!contains_bidi_override("invoice.pdf"));
    }

    #[test]
    fn last_extension_returns_after_final_dot() {
        assert_eq!(last_extension("file.tar.gz"), Some("gz"));
        assert_eq!(last_extension("noext"), None);
        assert_eq!(last_extension(".hidden"), Some("hidden"));
    }

    #[test]
    fn attachment_with_rlo_bidi_extension_emits_lookalike_warning() {
        // Filename "resume_CV<RLO>gpj.exe" — visually renders as
        // "resume_CVexe.jpg" after right-to-left override is applied.
        let raw = "From: a@example\r\n\
                   Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                   \r\n\
                   --BOUND\r\n\
                   Content-Type: text/plain\r\n\
                   \r\n\
                   hello\r\n\
                   --BOUND\r\n\
                   Content-Type: application/octet-stream\r\n\
                   Content-Disposition: attachment; filename=\"resume_CV\u{202E}gpj.exe\"\r\n\
                   Content-Transfer-Encoding: base64\r\n\
                   \r\n\
                   AAAA\r\n\
                   --BOUND--\r\n"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.location.as_deref() == Some("attachment[0]:filename")
            }),
            "expected LookalikeFilenameExtensionSpoof at attachment[0]:filename, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn from_header_with_bidi_domain_emits_homograph_warning() {
        // RLO codepoint embedded in the From: header domain. Detection
        // must fire BEFORE the unicode sanitize pass strips the bidi
        // char, so it lives in `audit_addr_domain_bidi` at the raw-Addr
        // boundary.
        let raw = "From: Bob <bob@exa\u{202E}mple.com>\r\n\
                   Subject: hi\r\n\
                   \r\n\
                   body"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeHomographDomain
                    && w.location.as_deref() == Some("header:from")
                    && w.detail
                        .as_deref()
                        .unwrap_or("")
                        .contains("reason=bidi_pre_strip")
            }),
            "expected LookalikeHomographDomain bidi_pre_strip at header:from, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn nested_rfc822_attachment_reports_nonzero_size() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    outer\r\n\
                    --BOUND\r\n\
                    Content-Type: message/rfc822\r\n\
                    Content-Disposition: attachment\r\n\
                    \r\n\
                    From: inner@example\r\n\
                    Subject: nested\r\n\
                    \r\n\
                    inner body\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.attachments.len(), 1);
        assert!(content.meta.attachments[0].size_bytes > 0);
    }

    #[test]
    fn double_extension_pdf_exe_fires_spoof_warning() {
        let eml = b"From: test@example.com\r\n\
            Subject: invoice\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "expected LookalikeFilenameExtensionSpoof with double_extension, \
             got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn reply_to_extracted_into_meta() {
        let eml = b"From: sender@example.com\r\n\
            Reply-To: reply@different.com\r\n\
            To: recipient@example.com\r\n\
            Subject: test\r\n\
            \r\n\
            body\r\n";
        let content = parse_message(eml).unwrap();
        assert_eq!(
            content.meta.reply_to.as_deref(),
            Some("reply@different.com")
        );
    }

    #[test]
    fn reply_to_bidi_override_emits_warning() {
        let eml = "From: sender@example.com\r\n\
             Reply-To: attacker@evil\u{202E}.com\r\n\
             To: recipient@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n";
        let content = parse_message(eml.as_bytes()).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeHomographDomain
                    && w.location.as_deref() == Some("header:reply_to")
            }),
            "expected LookalikeHomographDomain on reply_to, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn single_extension_does_not_fire_double_extension() {
        let eml = b"From: test@example.com\r\n\
            Subject: file\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/pdf\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).unwrap();
        assert!(
            !content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "single extension should not fire double_extension spoof"
        );
    }
}
