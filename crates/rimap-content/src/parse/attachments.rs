//! Attachment metadata extraction: filenames, content types, magic-byte
//! sniffing, and inline-disposition detection.

use mail_parser::{Message, MimeHeaders as _, PartType};

use crate::output::{AttachmentMeta, SecurityWarning, WarningCode};
use crate::parse::MAX_HEADER_BYTES;
use crate::parse::filename::sanitize_attachment_filename;
use crate::parse::sniff::{content_types_compatible, sniff_content_types};
use crate::unicode;

/// Walk `message.attachments` and build an `AttachmentMeta` for each,
/// emitting `ParseMimeTypeMismatch` when magic-byte sniffing disagrees
/// with the declared Content-Type.
pub(super) fn extract_attachments(
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
        warnings.push(SecurityWarning::at(
            WarningCode::ParseAttachmentPolyglot,
            format!("declared={declared_ct} sniffed={}", sniffed.join(",")),
            format!("attachment[{idx}]"),
        ));
    }
    if !sniffed.is_empty() {
        let mismatch = !sniffed
            .iter()
            .any(|s| content_types_compatible(&declared_ct, s));
        if mismatch {
            warnings.push(SecurityWarning::at(
                WarningCode::ParseMimeTypeMismatch,
                format!("declared={declared_ct} sniffed={}", sniffed.join(",")),
                format!("attachment[{idx}]"),
            ));
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
