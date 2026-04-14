//! `expunge` tool handler: permanently remove \Deleted messages from a folder.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `expunge`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpungeInput {
    /// Folder to expunge.
    pub folder: String,
}

/// Trusted metadata for an `expunge` response.
#[derive(Debug, Serialize)]
pub struct ExpungeMeta {
    /// Folder that was expunged.
    pub folder: String,
    /// Number of messages permanently removed.
    pub expunged_count: u32,
    /// UIDs that had the `\Deleted` flag set before expunge.
    pub deleted_uids_before_expunge: Vec<u32>,
}

/// `expunge` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: ExpungeDenied }` when the folder
/// is not in `expunge_folders`. Returns `RimapError::Imap { ... }` for
/// IMAP-layer failures. The upstream `DispatchGuard::pre_dispatch` gate
/// may also return `PostureDenied`.
pub async fn handle(
    account: &AccountState,
    input: ExpungeInput,
) -> Result<ToolResponse<ExpungeMeta>, rimap_core::RimapError> {
    account.folder_guard.check_expunge(&input.folder)?;

    let (deleted_uids, expunged_count) = account.imap.expunge(&input.folder).await?;

    Ok(ToolResponse {
        meta: ExpungeMeta {
            folder: input.folder,
            expunged_count,
            deleted_uids_before_expunge: deleted_uids.iter().map(|u| u.get()).collect(),
        },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
