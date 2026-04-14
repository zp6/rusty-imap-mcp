//! `list_attachments` tool handler.

use rimap_imap::types::{BodyStructure, FetchSpec, Uid};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for the `list_attachments` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAttachmentsInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message.
    pub uid: u32,
}

/// Metadata for a single attachment discovered in the MIME tree.
#[derive(Debug, serde::Serialize)]
struct AttachmentInfo {
    part_id: String,
    mime_type: String,
    size_bytes: u32,
    filename: Option<String>,
}

/// Execute the `list_attachments` tool.
///
/// Fetches `BODYSTRUCTURE` for the given message and walks the MIME
/// tree to find non-text attachment parts.
///
/// # Errors
///
/// Returns `RimapError` on invalid input or IMAP failure.
pub async fn handle(
    account: &AccountState,
    input: ListAttachmentsInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uid = Uid::new(input.uid)
        .ok_or_else(|| rimap_core::RimapError::invalid_input("UID must be non-zero"))?;

    let spec = FetchSpec {
        bodystructure: true,
        ..FetchSpec::default()
    };
    let messages = account.imap.fetch(&input.folder, &[uid], spec).await?;

    let msg = messages
        .into_iter()
        .next()
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!("UID {} not found in {}", input.uid, input.folder),
        })?;

    let bodystructure = msg.bodystructure.ok_or_else(|| {
        rimap_core::RimapError::Internal("server did not return BODYSTRUCTURE".into())
    })?;

    let mut attachments = Vec::new();
    collect_attachments(&bodystructure, "", &mut attachments, 0);

    let attachment_values: Vec<serde_json::Value> = attachments
        .iter()
        .map(|a| {
            serde_json::json!({
                "part_id": a.part_id,
                "mime_type": a.mime_type,
                "size_bytes": a.size_bytes,
                "filename": a.filename,
            })
        })
        .collect();

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uid": input.uid,
            "attachment_count": attachments.len(),
        }),
        untrusted: Some(serde_json::json!({
            "attachments": attachment_values,
        })),
        security_warnings: Vec::new(),
    })
}

/// Maximum recursion depth for MIME tree walking (denial-of-service guard).
const MAX_MIME_DEPTH: u32 = 64;

use crate::tools::mime_part_id::{child_part_id, leaf_part_id};

/// Walk the `BodyStructure` tree and collect attachment parts.
///
/// IMAP part numbering: for a multipart message the top-level parts
/// are "1", "2", "3", etc. Nested multipart sub-parts are "1.1",
/// "1.2", etc. For a non-multipart (single-part) message at the
/// root, the sole part is "1".
fn collect_attachments(
    bs: &BodyStructure,
    prefix: &str,
    out: &mut Vec<AttachmentInfo>,
    depth: u32,
) {
    if depth > MAX_MIME_DEPTH {
        return;
    }
    match bs {
        BodyStructure::Single {
            mime_type,
            mime_subtype,
            params,
            size,
            ..
        } => {
            let part_id = leaf_part_id(prefix);
            if !is_inline_text(mime_type, mime_subtype) {
                let filename = extract_filename(params);
                let full_type = format!(
                    "{}/{}",
                    mime_type.to_lowercase(),
                    mime_subtype.to_lowercase()
                );
                out.push(AttachmentInfo {
                    part_id,
                    mime_type: full_type,
                    size_bytes: *size,
                    filename,
                });
            }
        }
        BodyStructure::Multipart { parts, .. } => {
            for (i, part) in parts.iter().enumerate() {
                let child = child_part_id(prefix, i + 1);
                collect_attachments(part, &child, out, depth + 1);
            }
        }
        BodyStructure::Message { body, .. } => {
            let part_id = leaf_part_id(prefix);
            // Walk into the embedded message's body structure.
            collect_attachments(body, &part_id, out, depth + 1);
        }
    }
}

/// Returns `true` for `text/plain` and `text/html`, which are
/// typically inline body parts rather than attachments.
fn is_inline_text(mime_type: &str, mime_subtype: &str) -> bool {
    mime_type.eq_ignore_ascii_case("text")
        && (mime_subtype.eq_ignore_ascii_case("plain") || mime_subtype.eq_ignore_ascii_case("html"))
}

/// Extract a filename from MIME content-type parameters.
/// Looks for `name` or `filename` (case-insensitive).
fn extract_filename(params: &[(String, String)]) -> Option<String> {
    for (key, value) in params {
        if (key.eq_ignore_ascii_case("name") || key.eq_ignore_ascii_case("filename"))
            && !value.is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(mime_type: &str, sub: &str, size: u32) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mime_type.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size,
        }
    }

    fn single_with_name(mime_type: &str, sub: &str, size: u32, name: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mime_type.to_string(),
            mime_subtype: sub.to_string(),
            params: vec![("name".to_string(), name.to_string())],
            encoding: "base64".to_string(),
            size,
        }
    }

    #[test]
    fn single_text_plain_is_not_attachment() {
        let bs = single("text", "plain", 100);
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn single_text_html_is_not_attachment() {
        let bs = single("text", "html", 200);
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn single_image_is_attachment() {
        let bs = single_with_name("image", "png", 5000, "photo.png");
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].part_id, "1");
        assert_eq!(out[0].mime_type, "image/png");
        assert_eq!(out[0].size_bytes, 5000);
        assert_eq!(out[0].filename.as_deref(), Some("photo.png"));
    }

    #[test]
    fn multipart_mixed_extracts_attachments() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                single("text", "plain", 100),
                single_with_name("application", "pdf", 20000, "report.pdf"),
                single_with_name("image", "jpeg", 8000, "cat.jpg"),
            ],
        };
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].part_id, "2");
        assert_eq!(out[0].mime_type, "application/pdf");
        assert_eq!(out[1].part_id, "3");
        assert_eq!(out[1].mime_type, "image/jpeg");
    }

    #[test]
    fn nested_multipart_numbering() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                single("text", "plain", 50),
                single_with_name("image", "gif", 1000, "anim.gif"),
            ],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                inner,
                single_with_name("application", "zip", 50000, "archive.zip"),
            ],
        };
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].part_id, "1.2");
        assert_eq!(out[0].filename.as_deref(), Some("anim.gif"));
        assert_eq!(out[1].part_id, "2");
        assert_eq!(out[1].filename.as_deref(), Some("archive.zip"));
    }

    #[test]
    fn is_inline_text_case_insensitive() {
        assert!(is_inline_text("TEXT", "PLAIN"));
        assert!(is_inline_text("Text", "Html"));
        assert!(!is_inline_text("text", "csv"));
        assert!(!is_inline_text("image", "plain"));
    }

    #[test]
    fn extract_filename_finds_name_param() {
        let params = vec![
            ("charset".to_string(), "utf-8".to_string()),
            ("name".to_string(), "doc.pdf".to_string()),
        ];
        assert_eq!(extract_filename(&params), Some("doc.pdf".to_string()));
    }

    #[test]
    fn extract_filename_returns_none_when_absent() {
        let params = vec![("charset".to_string(), "utf-8".to_string())];
        assert_eq!(extract_filename(&params), None);
    }

    #[test]
    fn deeply_nested_mime_respects_depth_limit() {
        let mut bs = single("application", "pdf", 100);
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".to_string(),
                parts: vec![bs],
            };
        }
        let mut out = Vec::new();
        collect_attachments(&bs, "", &mut out, 0);
        assert!(out.is_empty());
    }
}
