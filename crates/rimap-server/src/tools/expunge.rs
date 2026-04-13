//! `expunge` tool handler: permanently remove \Deleted messages from a folder.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `expunge`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpungeInput {
    /// Folder to expunge.
    pub folder: String,
}

/// `expunge` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: ExpungeInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    server
        .folder_guard
        .check_expunge(&input.folder)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    let (deleted_uids, expunged_count) = server.imap.expunge(&input.folder).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "expunged_count": expunged_count,
            "deleted_uids_before_expunge": deleted_uids
                .iter()
                .map(|u| u.get())
                .collect::<Vec<_>>(),
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
