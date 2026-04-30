//! Text / HTML body extraction and MIME-depth enforcement.

use mail_parser::{Message, PartType};

use crate::error::ContentError;
use crate::html;
use crate::output::{SecurityWarning, WarningCode};
use crate::parse::{MAX_BODY_BYTES, MAX_MIME_DEPTH, MAX_MIME_PARTS, MAX_TOTAL_BODY_BYTES};
use crate::unicode;

/// Result of walking a message's text bodies: the primary text body,
/// any alternate text parts, an optional sanitized HTML rendering, the
/// anchor hrefs that survived sanitization, and whether any part was
/// truncated.
#[derive(Debug)]
pub(super) struct BodyExtraction {
    pub(super) primary_text: String,
    pub(super) alternates: Vec<String>,
    pub(super) body_html: Option<String>,
    pub(super) anchor_hrefs: Vec<String>,
    pub(super) body_truncated: bool,
}

/// Walk `message.text_body`, enforce MIME limits, and sanitize each
/// part into a `BodyExtraction`. Emits `ParseBodyTruncated` on any
/// part whose raw byte length exceeds `MAX_BODY_BYTES`; terminal
/// `LimitExceeded` errors for part count or depth overflow.
pub(super) fn extract_bodies(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<BodyExtraction, ContentError> {
    let part_count = message.parts.len();
    if part_count > MAX_MIME_PARTS {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseMimePartCountExceeded,
            format!("count={part_count} limit={MAX_MIME_PARTS}"),
            "mime",
        ));
        return Err(ContentError::LimitExceeded {
            kind: "mime_parts",
            limit: MAX_MIME_PARTS,
        });
    }

    check_mime_depth(message, warnings)?;

    // Determine the part id of the first HTML body so only one HTML
    // part per message flows through `html::sanitize_html`. mail-parser 0.11
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
                decode_text_part(part, raw_bytes, idx, &mut state, warnings);
            }
            PartType::Html(cow) => {
                let is_primary = primary_html_part_id == Some(part_id as usize);
                if !is_primary {
                    continue;
                }
                sanitize_html_part(part, cow.as_bytes(), &mut state, warnings)?;
            }
            PartType::Message(_)
            | PartType::Binary(_)
            | PartType::InlineBinary(_)
            | PartType::Multipart(_) => continue,
        }
        if state.total_bytes >= MAX_TOTAL_BODY_BYTES {
            state.body_truncated = true;
            warnings.push(SecurityWarning::at(
                WarningCode::ParseBodyTruncated,
                format!("total={} limit={MAX_TOTAL_BODY_BYTES}", state.total_bytes),
                "body:aggregate",
            ));
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
fn decode_text_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    idx: usize,
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) {
    if raw_bytes.len() > MAX_BODY_BYTES {
        state.body_truncated = true;
        warnings.push(SecurityWarning::at(
            WarningCode::ParseBodyTruncated,
            format!("original={} limit={}", raw_bytes.len(), MAX_BODY_BYTES),
            format!("body:text[{idx}]"),
        ));
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

/// Run the primary `text/html` part through [`crate::html::sanitize_html`].
///
/// On success: merges the produced warnings into `warnings`, places
/// the extracted plain text at the primary text slot if empty (else
/// pushes to alternates), and stores the sanitized html and anchor
/// hrefs on `state`.
///
/// On `ContentError::LimitExceeded`: emits a `ParseBodyTruncated`
/// warning at `body:html` and continues. Other errors propagate.
fn sanitize_html_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let charset = part_charset(part);
    match html::sanitize_html(raw_bytes, charset.as_deref()) {
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
            warnings.push(SecurityWarning::at(
                WarningCode::ParseBodyTruncated,
                format!("original={} limit={limit} kind={kind}", raw_bytes.len()),
                "body:html",
            ));
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Read the `charset` attribute off a part's Content-Type header.
pub(super) fn part_charset(part: &mail_parser::MessagePart<'_>) -> Option<String> {
    use mail_parser::MimeHeaders as _;
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
        warnings.push(SecurityWarning::at(
            WarningCode::ParseMimeDepthExceeded,
            format!("depth={depth} limit={MAX_MIME_DEPTH}"),
            "mime",
        ));
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
