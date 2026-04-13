//! `create_draft` tool handler: compose a draft email and APPEND it
//! to the Drafts folder with a `$PendingReview` keyword.

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;
use crate::tools::message_builder::{self, ComposeInput};

/// Input for `create_draft` — identical to shared `ComposeInput`.
pub type CreateDraftInput = ComposeInput;

/// `create_draft` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: CreateDraftInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;
    let from_addr = &server.config.config.imap.username;
    let raw_msg = message_builder::build_message(server, from_addr, &input).await?;

    let drafts_folder = "Drafts";
    let result = server
        .imap
        .append_message(
            drafts_folder,
            &raw_msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await?;

    let generated_msg_id = mail_parser::MessageParser::new()
        .parse(&raw_msg)
        .and_then(|m| m.message_id().map(ToString::to_string));

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": drafts_folder,
            "uid": result.uid.map(rimap_imap::types::Uid::get),
            "message_id": generated_msg_id,
            "keywords": ["$PendingReview"],
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
