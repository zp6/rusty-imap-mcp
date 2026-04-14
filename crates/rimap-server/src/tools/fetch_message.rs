//! `fetch_message` tool handler.

use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;
use crate::response::ToolResponse;

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
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when `uid == 0`
/// or when the body fails `rimap-content` parse/limits (malformed, MIME
/// depth/parts cap). Returns `RimapError::Imap { ... }` for IMAP-layer
/// failures (network, timeout, protocol, attachment-too-large). The upstream
/// `DispatchGuard::pre_dispatch` layer may also return `Authz { code: PostureDenied }`
/// for `FetchMessageHtml` when `include_html=true` and posture forbids it.
pub async fn handle(
    account: &AccountState,
    input: FetchMessageInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // The `FetchMessageHtml` posture check happens upstream in
    // `refine_tool_name` + `DispatchGuard::pre_dispatch`; this handler just reads
    // the include_html flag.
    let include_html = input.include_html.unwrap_or(false);

    let uid = Uid::new(input.uid)
        .ok_or_else(|| rimap_core::RimapError::invalid_input("UID must be non-zero"))?;

    let raw = account.imap.fetch_body(&input.folder, uid).await?;
    let raw_size = raw.len();

    let content = crate::content::parse_message_async(raw)
        .await
        .map_err(|e| {
            // Malformed input and cap-exceeded are caller-side problems;
            // surface them as INVALID_PARAMS via the InvalidInput code so
            // MCP clients see accurate guidance. Only genuine parser bugs
            // (if any) would fall through to Internal — none exist today
            // because ContentError has no Internal variant.
            rimap_core::RimapError::invalid_input(e.to_string())
        })?;

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

#[cfg(test)]
mod tests {
    use super::truncate_string;

    #[test]
    fn truncate_below_max_is_noop() {
        let mut s = String::from("hello");
        truncate_string(&mut s, 100);
        assert_eq!(s, "hello");
    }

    #[test]
    fn truncate_at_exact_max_is_noop() {
        let mut s = String::from("hello");
        truncate_string(&mut s, 5);
        assert_eq!(s, "hello");
    }

    #[test]
    fn truncate_lops_off_trailing_bytes() {
        let mut s = String::from("hello world");
        truncate_string(&mut s, 5);
        assert_eq!(s, "hello");
    }

    #[test]
    fn truncate_respects_utf8_char_boundary() {
        // "héllo" — 'é' is 2 bytes (UTF-8: 0xc3 0xa9). Truncating to byte 2
        // would slice through the multibyte char, so the helper must back up
        // to byte 1 ("h").
        let mut s = String::from("héllo");
        truncate_string(&mut s, 2);
        assert_eq!(s, "h");
        assert!(s.is_char_boundary(s.len()));
    }

    #[test]
    fn truncate_to_zero_yields_empty_string() {
        let mut s = String::from("anything");
        truncate_string(&mut s, 0);
        assert_eq!(s, "");
    }

    #[test]
    fn truncate_keeps_full_multibyte_char_when_possible() {
        // "ab中cd" — '中' is 3 bytes (0xe4 0xb8 0xad). max=5 should keep
        // "ab中" (bytes 0..5), since byte 5 IS a char boundary.
        let mut s = String::from("ab中cd");
        truncate_string(&mut s, 5);
        assert_eq!(s, "ab中");
    }
}
