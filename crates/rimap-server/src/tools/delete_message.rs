//! `delete_message` tool handler: flag as \Deleted and move to Trash.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::registry::AccountState;
use crate::response::ToolResponse;

/// Input for `delete_message`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteMessageInput {
    /// Source folder containing the message.
    pub folder: String,
    /// UID of the message to delete.
    pub uid: u32,
}

/// `delete_message` handler.
pub async fn handle(
    account: &AccountState,
    input: DeleteMessageInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uid =
        rimap_imap::types::Uid::new(input.uid).ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "uid must be non-zero".into(),
        })?;

    let trash_folder = "Trash";
    let result = account
        .imap
        .delete_message(&input.folder, uid, trash_folder)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "source_folder": input.folder,
            "uid": input.uid,
            "moved_to_trash": result.moved_to_trash,
            "trash_folder": trash_folder,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
