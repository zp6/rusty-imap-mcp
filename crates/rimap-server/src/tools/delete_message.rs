//! `delete_message` tool handler: flag as \Deleted and move to Trash.
//!
//! The destination folder name is hard-coded to `"Trash"` by design:
//! IMAP servers almost universally use this exact spelling (RFC 6154
//! `\Trash` SPECIAL-USE mailbox maps to `Trash` at every mainstream
//! provider). If a deployment needs a different folder, the right seam
//! is a per-account `trash_folder` config override — not a per-call
//! argument — so that the gesture of "delete" is consistent.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;
use crate::response::ToolResponse;

/// Input for `delete_message`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteMessageInput {
    /// Source folder containing the message.
    pub folder: String,
    /// UID of the message to delete.
    pub uid: u32,
}

/// Target folder for `delete_message`. Hard-coded per the module-level
/// doc; a config override is the right seam if a deployment needs to
/// diverge from this.
const TRASH_FOLDER: &str = "Trash";

/// `delete_message` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when `uid == 0`.
/// Returns `RimapError::Imap { ... }` for IMAP-layer failures (server
/// rejects the MOVE/COPY/STORE or the source folder is missing). The
/// upstream `DispatchGuard::pre_dispatch` gate may return
/// `PostureDenied`.
pub async fn handle(
    account: &AccountState,
    input: DeleteMessageInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uid = rimap_imap::types::Uid::new(input.uid)
        .ok_or_else(|| rimap_core::RimapError::invalid_input("uid must be non-zero"))?;

    let result = account
        .imap
        .delete_message(&input.folder, uid, TRASH_FOLDER)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "source_folder": input.folder,
            "uid": input.uid,
            "moved_to_trash": result.moved_to_trash,
            "trash_folder": TRASH_FOLDER,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
