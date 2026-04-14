//! `move_message` tool handler.

use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::flags::resolve_uids;

/// Input for `move_message`.
#[derive(Debug, Deserialize, JsonSchema)]
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
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// `uid`/`uids` (zero, both/neither set, batch over 100). Returns
/// `RimapError::Imap { ... }` for IMAP-layer failures.
pub async fn handle(
    account: &AccountState,
    input: MoveInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let outcome = account
        .imap
        .move_messages(&input.source_folder, &input.dest_folder, &uids)
        .await?;

    let moves: Vec<serde_json::Value> = outcome
        .results
        .iter()
        .map(|r| {
            serde_json::json!({
                "old_uid": r.old_uid.get(),
                "new_uid": r.new_uid.map(Uid::get),
            })
        })
        .collect();

    let mut warnings = Vec::new();
    if outcome.used_fallback {
        warnings.push(serde_json::json!({
            "type": "non_atomic_move",
            "message": "Server lacks MOVE capability; \
                used non-atomic COPY+DELETE+EXPUNGE fallback. \
                Other messages with \\Deleted flag in the source \
                folder may have been expunged.",
        }));
    }

    Ok(ToolResponse {
        meta: serde_json::json!({
            "source_folder": input.source_folder,
            "dest_folder": input.dest_folder,
            "moves": moves,
        }),
        untrusted: None,
        security_warnings: warnings,
    })
}
