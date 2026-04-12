//! `list_folders` tool handler.

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Execute the `list_folders` tool.
pub async fn handle(server: &ImapMcpServer) -> Result<ToolResponse, rimap_core::RimapError> {
    let folders = server.imap.list_folders("*").await?;

    let mut folder_entries = Vec::with_capacity(folders.len());
    for folder in &folders {
        let status = server
            .imap
            .status(&folder.name, rimap_imap::types::StatusItems::all())
            .await?;

        folder_entries.push(serde_json::json!({
            "name": folder.name,
            "delimiter": folder.delimiter,
            "flags": folder.attributes,
            "exists": status.messages,
            "unseen": status.unseen,
            "uid_validity": status.uid_validity,
        }));
    }

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folders": folder_entries,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
