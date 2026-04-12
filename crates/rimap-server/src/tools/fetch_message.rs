//! `fetch_message` tool handler.

use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for the `fetch_message` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchMessageInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message to fetch.
    pub uid: u32,
    /// Include sanitized HTML body in the response.
    pub include_html: Option<bool>,
    /// Truncate body text (and HTML if included) to this many bytes.
    pub max_body_bytes: Option<usize>,
}

/// Execute the `fetch_message` tool.
pub async fn handle(
    server: &ImapMcpServer,
    input: FetchMessageInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let include_html = input.include_html.unwrap_or(false);
    if include_html {
        use rimap_core::tool::ToolName;
        server
            .guard
            .matrix()
            .check(ToolName::FetchMessageHtml)
            .map_err(|e| rimap_core::RimapError::Authz {
                code: e.code(),
                message: e.to_string(),
            })?;
    }

    let uid = Uid::new(input.uid).ok_or_else(|| rimap_core::RimapError::Authz {
        code: rimap_core::error::ErrorCode::InvalidInput,
        message: "UID must be non-zero".to_string(),
    })?;

    let raw = server.imap.fetch_body(&input.folder, uid).await?;
    let raw_size = raw.len();

    let content = crate::content::parse_message_async(raw)
        .await
        .map_err(|e| rimap_core::RimapError::Internal(e.to_string()))?;

    let mut body_text = content.untrusted.body_text;
    let mut body_html = if include_html {
        content.untrusted.body_html
    } else {
        None
    };

    let mut truncated = content.meta.body_truncated;

    if let Some(max) = input.max_body_bytes {
        if body_text.len() > max {
            truncate_string(&mut body_text, max);
            truncated = true;
        }
        if let Some(html) = &mut body_html
            && html.len() > max
        {
            truncate_string(html, max);
            truncated = true;
        }
    }

    let attachments: Vec<serde_json::Value> = content
        .meta
        .attachments
        .iter()
        .map(|a| {
            serde_json::json!({
                "filename": a.filename,
                "content_type": a.content_type,
                "size_bytes": a.size_bytes,
                "content_id": a.content_id,
                "is_inline": a.is_inline,
            })
        })
        .collect();

    let warnings: Vec<serde_json::Value> = content
        .security_warnings
        .iter()
        .map(|w| {
            serde_json::json!({
                "code": w.code,
                "detail": w.detail,
                "location": w.location,
            })
        })
        .collect();

    let mut untrusted = serde_json::json!({
        "body_text": body_text,
        "subject": content.meta.subject,
        "from": content.meta.from,
        "to": content.meta.to,
        "cc": content.meta.cc,
        "reply_to": content.meta.reply_to,
        "date": content.meta.date,
        "attachments": attachments,
    });

    if let Some(html) = body_html {
        untrusted["body_html"] = serde_json::json!(html);
    }

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uid": input.uid,
            "message_id": content.meta.message_id,
            "size": raw_size,
            "truncated": truncated,
        }),
        untrusted: Some(untrusted),
        security_warnings: warnings,
    })
}

/// Truncate a string to at most `max` bytes on a valid UTF-8
/// boundary.
fn truncate_string(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    // Find the last valid char boundary at or before `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}
