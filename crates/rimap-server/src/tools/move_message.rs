//! `move_message` tool handler.

use rimap_imap::types::Uid;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;
use crate::tools::flags::resolve_uids;

/// Input for `move_message`.
#[derive(Debug, Deserialize)]
pub struct MoveInput {
    /// Source folder.
    pub source_folder: String,
    /// Destination folder.
    pub dest_folder: String,
    /// Single UID.
    pub uid: Option<u32>,
    /// Batch of UIDs (max 100).
    pub uids: Option<Vec<u32>>,
}

/// Execute the `move_message` tool.
pub async fn handle(
    server: &ImapMcpServer,
    input: MoveInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let results = server
        .imap
        .move_messages(&input.source_folder, &input.dest_folder, &uids)
        .await?;

    let moves: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "old_uid": r.old_uid.get(),
                "new_uid": r.new_uid.map(Uid::get),
            })
        })
        .collect();

    Ok(ToolResponse {
        meta: serde_json::json!({
            "source_folder": input.source_folder,
            "dest_folder": input.dest_folder,
            "moves": moves,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
