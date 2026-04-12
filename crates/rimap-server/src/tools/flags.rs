//! Flag mutation tool handlers: `mark_read`, `mark_unread`, `flag`,
//! `unflag`.

use rimap_imap::types::{Flag, FlagAction, Uid};
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for flag mutation tools.
#[derive(Debug, Deserialize)]
pub struct FlagInput {
    /// Target folder.
    pub folder: String,
    /// Single UID.
    pub uid: Option<u32>,
    /// Batch of UIDs (max 100).
    pub uids: Option<Vec<u32>>,
}

/// `mark_read` handler.
pub async fn handle_mark_read(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        server,
        input,
        &[Flag::Seen],
        FlagAction::Add,
    ))
    .await
}

/// `mark_unread` handler.
pub async fn handle_mark_unread(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        server,
        input,
        &[Flag::Seen],
        FlagAction::Remove,
    ))
    .await
}

/// `flag` handler.
pub async fn handle_flag(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        server,
        input,
        &[Flag::Flagged],
        FlagAction::Add,
    ))
    .await
}

/// `unflag` handler.
pub async fn handle_unflag(
    server: &ImapMcpServer,
    input: FlagInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        server,
        input,
        &[Flag::Flagged],
        FlagAction::Remove,
    ))
    .await
}

async fn handle_flag_op(
    server: &ImapMcpServer,
    input: FlagInput,
    flags: &[Flag],
    action: FlagAction,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let updated = server
        .imap
        .store_flags(&input.folder, &uids, flags, action)
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "uids_updated": updated_ids,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Resolve `uid` or `uids` from input to a `Vec<Uid>`.
pub fn resolve_uids(
    uid: Option<u32>,
    uids: Option<Vec<u32>>,
) -> Result<Vec<Uid>, rimap_core::RimapError> {
    match (uid, uids) {
        (Some(u), None) => {
            let uid = Uid::new(u)
                .ok_or_else(|| rimap_core::RimapError::Internal("UID must be non-zero".into()))?;
            Ok(vec![uid])
        }
        (None, Some(us)) => {
            let mut result = Vec::with_capacity(us.len());
            for u in us {
                let uid = Uid::new(u).ok_or_else(|| {
                    rimap_core::RimapError::Internal("UID must be non-zero".into())
                })?;
                result.push(uid);
            }
            Ok(result)
        }
        (Some(_), Some(_)) => Err(rimap_core::RimapError::Internal(
            "provide uid or uids, not both".into(),
        )),
        (None, None) => Err(rimap_core::RimapError::Internal(
            "provide uid or uids".into(),
        )),
    }
}
