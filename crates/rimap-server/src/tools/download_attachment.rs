//! `download_attachment` tool handler.

use mail_parser::MimeHeaders;
use rimap_imap::types::Uid;
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
        security_warnings: Vec::new(),
    })
}

/// Find the MIME part matching `part_id` in a parsed message.
///
/// Walks the `mail_parser` parts array and reconstructs IMAP-style
/// part numbering to find the target part.
fn find_part_by_id(
    msg: &mail_parser::Message<'_>,
    target_part_id: &str,
) -> Result<(Vec<u8>, String, Option<String>), rimap_core::RimapError> {
    let part_ids = compute_part_ids(msg);

    for (idx, computed_id) in &part_ids {
        if computed_id == target_part_id {
            let part = &msg.parts[*idx];
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
fn compute_part_ids(msg: &mail_parser::Message<'_>) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let root = &msg.parts[0];

    if root.is_multipart() {
        walk_parts(msg, 0, "", &mut result);
    } else {
        // Single-part message: the sole part is "1".
        result.push((0, "1".to_string()));
    }

    result
}

/// Recursively walk parts and assign IMAP-style IDs.
fn walk_parts(
    msg: &mail_parser::Message<'_>,
    part_idx: usize,
    prefix: &str,
    out: &mut Vec<(usize, String)>,
) {
    let part = &msg.parts[part_idx];

    if let Some(children) = part.sub_parts() {
        for (i, &child_idx) in children.iter().enumerate() {
            let num = i + 1;
            let child_id = if prefix.is_empty() {
                num.to_string()
            } else {
                format!("{prefix}.{num}")
            };
            walk_parts(msg, child_idx as usize, &child_id, out);
        }
    } else {
        let part_id = if prefix.is_empty() {
            "1".to_string()
        } else {
            prefix.to_string()
        };
        out.push((part_idx, part_id));
    }
}
