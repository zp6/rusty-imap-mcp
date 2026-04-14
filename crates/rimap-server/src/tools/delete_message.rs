//! `delete_message` tool handler: flag as \Deleted and move to Trash.
//!
//! The destination folder name is hard-coded to `"Trash"` by design:
//! IMAP servers almost universally use this exact spelling (RFC 6154
//! `\Trash` SPECIAL-USE mailbox maps to `Trash` at every mainstream
//! provider). If a deployment needs a different folder, the right seam
//! is a per-account `trash_folder` config override — not a per-call
//! argument — so that the gesture of "delete" is consistent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `delete_message`.
///
/// # Shape
///
/// This tool intentionally takes a single scalar `uid: u32` rather than a
/// batch. The asymmetry with batch-capable tools (`flag`, `add_label`,
/// `move_message`) is deliberate: batch shapes (`uid` XOR `uids`) are
/// reserved for commutative, idempotent mutations where per-UID ordering
/// does not matter and results fan out uniformly. Read-side and
/// destructive single-target tools keep a scalar `uid` so the response
/// schema and error semantics stay unambiguous.
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

/// Trusted metadata for a `delete_message` response.
#[derive(Debug, Serialize)]
pub struct DeleteMessageMeta {
    /// Always `true` when the handler returns `Ok`.
    pub deleted: bool,
    /// Source folder the message was deleted from.
    pub folder: String,
    /// UID of the deleted message.
    pub uid: u32,
    /// Whether the message was moved to the trash folder.
    pub moved_to_trash: bool,
    /// Trash folder the message was moved to.
    pub destination: &'static str,
}

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
) -> Result<ToolResponse<DeleteMessageMeta>, rimap_core::RimapError> {
    let uid = rimap_imap::types::Uid::new(input.uid)
        .ok_or_else(|| rimap_core::RimapError::invalid_input("uid must be non-zero"))?;

    let result = account
        .imap
        .delete_message(&input.folder, uid, TRASH_FOLDER)
        .await?;

    Ok(ToolResponse {
        meta: DeleteMessageMeta {
            deleted: true,
            folder: input.folder,
            uid: input.uid,
            moved_to_trash: result.moved_to_trash,
            destination: TRASH_FOLDER,
        },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
