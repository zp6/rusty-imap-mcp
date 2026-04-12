//! `download_attachment` tool handler.

use mail_parser::MimeHeaders;
use rimap_imap::types::{BodyStructure, FetchSpec, Uid};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::download;
use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for the `download_attachment` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadAttachmentInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message.
    pub uid: u32,
    /// MIME part ID of the attachment (e.g. "2", "1.2").
    pub part_id: String,
    /// Optional destination directory. Must be within the
    /// configured download root.
    pub dest_dir: Option<String>,
}

/// Execute the `download_attachment` tool.
///
/// Fetches the full message, parses it with `mail_parser`, extracts
/// the attachment part matching `part_id`, and writes it to the
/// sandbox directory.
///
/// # Errors
///
/// Returns `RimapError` on invalid input, IMAP failure, part not
/// found, or filesystem errors.
pub async fn handle(
    server: &ImapMcpServer,
    input: DownloadAttachmentInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uid = Uid::new(input.uid).ok_or_else(|| rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::InvalidInput,
        message: "UID must be non-zero".to_string(),
    })?;

    if input.part_id.is_empty() {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "part_id must not be empty".to_string(),
        });
    }

    let dest = download::resolve_dest_dir(
        input.dest_dir.as_deref(),
        &server.download_dir,
        &server.download_dir,
    )?;

    let raw = server.imap.fetch_body(&input.folder, uid).await?;

    let parsed = mail_parser::MessageParser::new()
        .parse(&raw)
        .ok_or_else(|| {
            rimap_core::RimapError::Internal(
                "failed to parse message for attachment extraction".into(),
            )
        })?;

    let (part_body, declared_type, original_filename) = find_part_by_id(&parsed, &input.part_id)?;

    let safe_filename = original_filename.as_deref().unwrap_or("attachment");

    let path = download::write_attachment(&dest, safe_filename, &part_body)?;
    let size = part_body.len();
    let sha256 = download::sha256_hex(&part_body);
    let mime_sniffed = download::sniff_mime(&part_body);

    let path_str = path.to_string_lossy().to_string();

    let mut security_warnings = Vec::new();

    // Cross-validate: fetch BODYSTRUCTURE and compare its declared
    // MIME type against what mail_parser reports. Best-effort — if
    // the fetch or lookup fails we skip validation silently.
    let spec = FetchSpec {
        bodystructure: true,
        ..FetchSpec::default()
    };
    if let Ok(msgs) = server.imap.fetch(&input.folder, &[uid], spec).await
        && let Some(bs) = msgs.into_iter().next().and_then(|m| m.bodystructure)
        && let Some(bs_type) = lookup_bodystructure_type(&bs, &input.part_id)
    {
        security_warnings.extend(cross_validate_mime_type(&bs_type, &declared_type));
    }

    // Compare declared MIME type against magic-byte detection.
    security_warnings.extend(check_sniff_mismatch(
        &declared_type,
        mime_sniffed.as_deref(),
    ));

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uid": input.uid,
            "part_id": input.part_id,
            "path": path_str,
            "size_bytes": size,
            "sha256": sha256,
            "mime_declared": declared_type,
            "mime_sniffed": mime_sniffed,
        }),
        untrusted: Some(serde_json::json!({
            "filename_original": original_filename,
        })),
        security_warnings,
    })
}

/// Compare BODYSTRUCTURE-declared MIME type against `mail_parser`'s type.
///
/// Returns a security warning if they disagree (case-insensitive).
fn cross_validate_mime_type(bodystructure_type: &str, parser_type: &str) -> Vec<serde_json::Value> {
    if bodystructure_type.eq_ignore_ascii_case(parser_type) {
        return Vec::new();
    }
    vec![serde_json::json!({
        "type": "mime_type_mismatch",
        "bodystructure_type": bodystructure_type,
        "parser_type": parser_type,
        "message":
            "BODYSTRUCTURE MIME type disagrees with parsed content type"
    })]
}

/// Compare declared MIME type against magic-byte-sniffed type.
///
/// Returns a security warning when they disagree. Returns nothing
/// when sniffing produced no result (unknown magic bytes).
fn check_sniff_mismatch(declared: &str, sniffed: Option<&str>) -> Vec<serde_json::Value> {
    let Some(sniffed) = sniffed else {
        return Vec::new();
    };
    if declared.eq_ignore_ascii_case(sniffed) {
        return Vec::new();
    }
    vec![serde_json::json!({
        "type": "mime_sniff_mismatch",
        "mime_declared": declared,
        "mime_sniffed": sniffed,
        "message":
            "declared MIME type disagrees with magic-byte detection"
    })]
}

/// Maximum recursion depth for BODYSTRUCTURE tree walking.
const MAX_BS_DEPTH: u32 = 64;

/// Look up a part's declared MIME type from a `BodyStructure` tree by
/// IMAP-style part ID (e.g. "2", "1.2").
fn lookup_bodystructure_type(bs: &BodyStructure, target_part_id: &str) -> Option<String> {
    lookup_bs_recursive(bs, &mut String::new(), target_part_id, 0)
}

/// Recursive walker that mirrors `collect_attachments` numbering.
fn lookup_bs_recursive(
    bs: &BodyStructure,
    prefix: &mut String,
    target: &str,
    depth: u32,
) -> Option<String> {
    if depth > MAX_BS_DEPTH {
        return None;
    }
    match bs {
        BodyStructure::Single {
            mime_type,
            mime_subtype,
            ..
        } => {
            let part_id = if prefix.is_empty() {
                "1".to_string()
            } else {
                prefix.clone()
            };
            if part_id == target {
                Some(format!(
                    "{}/{}",
                    mime_type.to_lowercase(),
                    mime_subtype.to_lowercase()
                ))
            } else {
                None
            }
        }
        BodyStructure::Multipart { parts, .. } => {
            for (i, part) in parts.iter().enumerate() {
                let idx = i + 1;
                let mut child = if prefix.is_empty() {
                    idx.to_string()
                } else {
                    format!("{prefix}.{idx}")
                };
                if let Some(found) = lookup_bs_recursive(part, &mut child, target, depth + 1) {
                    return Some(found);
                }
            }
            None
        }
        BodyStructure::Message { body, .. } => {
            let mut part_id = if prefix.is_empty() {
                "1".to_string()
            } else {
                prefix.clone()
            };
            lookup_bs_recursive(body, &mut part_id, target, depth + 1)
        }
    }
}

/// Find the MIME part matching `part_id` in a parsed message.
///
/// Walks the `mail_parser` parts array and reconstructs IMAP-style
/// part numbering to find the target part.
fn find_part_by_id(
    msg: &mail_parser::Message<'_>,
    target_part_id: &str,
) -> Result<(Vec<u8>, String, Option<String>), rimap_core::RimapError> {
    let part_ids = compute_part_ids(msg)?;

    for (idx, computed_id) in &part_ids {
        if computed_id == target_part_id {
            let part = msg.parts.get(*idx).ok_or_else(|| {
                rimap_core::RimapError::Internal(format!("part index {idx} out of range"))
            })?;
            let body = part.contents().to_vec();
            let content_type = if let Some(ct) = part.content_type() {
                let main = ct.ctype();
                let sub = ct.subtype().unwrap_or("octet-stream");
                format!("{main}/{sub}")
            } else {
                "application/octet-stream".to_string()
            };
            let filename = part.attachment_name().map(String::from);
            return Ok((body, content_type, filename));
        }
    }

    Err(rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::NotFound,
        message: format!("part_id {target_part_id} not found in message"),
    })
}

/// Compute IMAP-style part IDs for all leaf parts in a parsed
/// message. Returns `(part_index, imap_part_id)` pairs.
fn compute_part_ids(
    msg: &mail_parser::Message<'_>,
) -> Result<Vec<(usize, String)>, rimap_core::RimapError> {
    let mut result = Vec::new();
    let root = msg
        .parts
        .first()
        .ok_or_else(|| rimap_core::RimapError::Internal("message has no parts".into()))?;

    if root.is_multipart() {
        walk_parts(msg, 0, "", &mut result, 0)?;
    } else {
        // Single-part message: the sole part is "1".
        result.push((0, "1".to_string()));
    }

    Ok(result)
}

/// Maximum recursion depth for MIME tree walking (denial-of-service guard).
const MAX_MIME_DEPTH: u32 = 64;

/// Recursively walk parts and assign IMAP-style IDs.
fn walk_parts(
    msg: &mail_parser::Message<'_>,
    part_idx: usize,
    prefix: &str,
    out: &mut Vec<(usize, String)>,
    depth: u32,
) -> Result<(), rimap_core::RimapError> {
    if depth > MAX_MIME_DEPTH {
        return Ok(());
    }
    let part = msg.parts.get(part_idx).ok_or_else(|| {
        rimap_core::RimapError::Internal(format!("part index {part_idx} out of range"))
    })?;

    if let Some(children) = part.sub_parts() {
        for (i, &child_idx) in children.iter().enumerate() {
            let num = i + 1;
            let child_id = if prefix.is_empty() {
                num.to_string()
            } else {
                format!("{prefix}.{num}")
            };
            walk_parts(msg, child_idx as usize, &child_id, out, depth + 1)?;
        }
    } else {
        let part_id = if prefix.is_empty() {
            "1".to_string()
        } else {
            prefix.to_string()
        };
        out.push((part_idx, part_id));
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn walk_parts_respects_depth_limit() {
        let raw = b"From: a@b\r\nContent-Type: text/plain\r\n\r\nHi\r\n";
        let msg = mail_parser::MessageParser::new().parse(raw).unwrap();
        let mut out = Vec::new();
        walk_parts(&msg, 0, "", &mut out, MAX_MIME_DEPTH + 1).unwrap();
        assert!(out.is_empty());
    }

    // -- cross_validate_mime_type ------------------------------------------

    #[test]
    fn cross_validate_catches_type_mismatch() {
        let warnings = cross_validate_mime_type("image/png", "text/html");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].to_string().contains("mime_type_mismatch"));
    }

    #[test]
    fn cross_validate_passes_on_match() {
        let warnings = cross_validate_mime_type("image/png", "image/png");
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_validate_case_insensitive() {
        let warnings = cross_validate_mime_type("IMAGE/PNG", "image/png");
        assert!(warnings.is_empty());
    }

    // -- lookup_bodystructure_type ----------------------------------------

    fn single(mt: &str, sub: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mt.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size: 100,
        }
    }

    #[test]
    fn lookup_single_part_message() {
        let bs = single("image", "png");
        let result = lookup_bodystructure_type(&bs, "1");
        assert_eq!(result.as_deref(), Some("image/png"));
    }

    #[test]
    fn lookup_multipart_by_id() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![single("text", "plain"), single("application", "pdf")],
        };
        assert_eq!(
            lookup_bodystructure_type(&bs, "2").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            lookup_bodystructure_type(&bs, "1").as_deref(),
            Some("text/plain")
        );
    }

    #[test]
    fn lookup_nested_multipart() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![single("text", "plain"), single("image", "gif")],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![inner, single("application", "zip")],
        };
        assert_eq!(
            lookup_bodystructure_type(&bs, "1.2").as_deref(),
            Some("image/gif")
        );
        assert_eq!(
            lookup_bodystructure_type(&bs, "2").as_deref(),
            Some("application/zip")
        );
    }

    #[test]
    fn lookup_missing_part_id_returns_none() {
        let bs = single("text", "plain");
        assert!(lookup_bodystructure_type(&bs, "99").is_none());
    }

    #[test]
    fn lookup_respects_depth_limit() {
        let mut bs = single("application", "pdf");
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".to_string(),
                parts: vec![bs],
            };
        }
        // The deeply nested part should be unreachable.
        assert!(lookup_bodystructure_type(&bs, "1").is_none());
    }

    // -- check_sniff_mismatch -----------------------------------------------

    #[test]
    fn sniff_mismatch_produces_warning() {
        let warnings = check_sniff_mismatch("text/plain", Some("image/png"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].to_string().contains("mime_sniff_mismatch"));
    }

    #[test]
    fn sniff_match_produces_no_warning() {
        let warnings = check_sniff_mismatch("image/png", Some("image/png"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn sniff_none_produces_no_warning() {
        let warnings = check_sniff_mismatch("text/plain", None);
        assert!(warnings.is_empty());
    }

    #[test]
    fn sniff_mismatch_case_insensitive() {
        let warnings = check_sniff_mismatch("IMAGE/PNG", Some("image/png"));
        assert!(warnings.is_empty());
    }
}
