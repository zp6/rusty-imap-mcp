//! `expunge` tool handler: permanently remove \Deleted messages from a folder.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::registry::AccountState;
use crate::response::ToolResponse;

/// Input for `expunge`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpungeInput {
    /// Folder to expunge.
    pub folder: String,
}

/// `expunge` handler.
pub async fn handle(
    account: &AccountState,
    input: ExpungeInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    account
        .folder_guard
        .check_expunge(&input.folder)
        .map_err(rimap_core::RimapError::from)?;

    let (deleted_uids, expunged_count) = account.imap.expunge(&input.folder).await?;

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
