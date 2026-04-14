//! `move_message` tool handler.

use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::flags::resolve_uids;

/// Input for `move_message`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveMessageInput {
    /// Source folder.
    pub folder: String,
    /// Destination folder.
    pub destination: String,
    /// Single UID.
    pub uid: Option<u32>,
    /// Batch of UIDs (max 100).
    pub uids: Option<Vec<u32>>,
}

/// Per-UID move result entry.
#[derive(Debug, Serialize)]
pub struct MoveEntry {
    /// Source UID that was moved.
    pub old_uid: u32,
    /// Destination UID assigned by the server, if returned.
    pub new_uid: Option<u32>,
}

/// Trusted metadata for a `move_message` response.
#[derive(Debug, Serialize)]
pub struct MoveMessageMeta {
    /// Source folder.
    pub folder: String,
    /// Destination folder.
    pub destination: String,
    /// Per-UID move results.
    pub moves: Vec<MoveEntry>,
}

/// Execute the `move_message` tool.
///
/// `move_message` does not invoke [`rimap_authz::FolderGuard`] directly
/// because `FolderGuard`'s `check_protected` / `check_expunge` API is
/// single-name: it asks whether one folder may be created, renamed, or
/// expunged, which does not fit a pairwise `(source, dest)` move. The
/// posture matrix gates the capability itself — `Move` is only in the
/// `Destructive` posture — and per-folder rules for the destination are
/// enforced by the IMAP server's own ACLs when the COPY+EXPUNGE
/// fallback runs. If richer per-folder policy is ever needed for move,
/// extend `FolderGuard` with a `check_move(src, dst)` method rather
/// than open-coding the two individual checks here.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// `uid`/`uids` (zero, both/neither set, batch over 100). Returns
/// `RimapError::Imap { ... }` for IMAP-layer failures.
pub async fn handle(
    account: &AccountState,
    input: MoveMessageInput,
) -> Result<ToolResponse<MoveMessageMeta>, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let outcome = account
        .imap
        .move_messages(&input.folder, &input.destination, &uids)
        .await?;

    let moves: Vec<MoveEntry> = outcome
        .results
        .iter()
        .map(|r| MoveEntry {
            old_uid: r.old_uid.get(),
            new_uid: r.new_uid.map(Uid::get),
        })
        .collect();

    let mut warnings: Vec<rimap_content::SecurityWarning> = Vec::new();
    if outcome.used_fallback {
        warnings.push(rimap_content::SecurityWarning::new(
            rimap_content::WarningCode::ServerNonAtomicMoveFallback,
            None,
            None,
        ));
    }

    Ok(ToolResponse {
        meta: MoveMessageMeta {
            folder: input.folder,
            destination: input.destination,
            moves,
        },
        untrusted: None,
        security_warnings: warnings,
    })
}
