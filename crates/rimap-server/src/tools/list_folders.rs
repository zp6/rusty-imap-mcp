//! `list_folders` tool handler.

use crate::registry::AccountState;
use crate::response::ToolResponse;

/// Execute the `list_folders` tool.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` if the server rejects LIST or any
/// of the per-folder STATUS calls. The upstream
/// `DispatchGuard::pre_dispatch` gate may also return `PostureDenied`.
pub async fn handle(account: &AccountState) -> Result<ToolResponse, rimap_core::RimapError> {
    let folders = account.imap.list_folders("*").await?;

    let mut folder_entries = Vec::with_capacity(folders.len());
    for folder in &folders {
        let status = account
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
