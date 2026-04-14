//! Flag mutation tool handlers: `mark_read`, `mark_unread`, `flag`,
//! `unflag`.
//!
//! # Errors (applies to all four handlers)
//!
//! Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
//! `uid`/`uids` input (zero, both/neither set, batch over 100). Returns
//! `RimapError::Imap { ... }` for IMAP-layer failures. The upstream
//! `DispatchGuard::pre_dispatch` gate may return `PostureDenied`.

use rimap_imap::types::{Flag, FlagAction, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for flag mutation tools.
///
/// # Shape
///
/// This tool accepts either a single `uid` or a batch `uids` (XOR; max
/// 100). The asymmetry with single-target tools (`fetch_message`,
/// `list_attachments`, `download_attachment`, `delete_message`) is
/// deliberate: batch shapes are reserved for commutative, idempotent
/// mutations where per-UID ordering does not matter and results fan out
/// uniformly. Read-side and destructive single-target tools keep a
/// scalar `uid` so the response schema and error semantics stay
/// unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlagInput {
    /// Target folder.
    pub folder: String,
    /// Single UID.
    pub uid: Option<u32>,
    /// Batch of UIDs (max 100).
    pub uids: Option<Vec<u32>>,
}

/// Trusted metadata for a flag mutation response.
#[derive(Debug, Serialize)]
pub struct FlagsMeta {
    /// Folder the flags were updated in.
    pub folder: String,
    /// UIDs that were updated.
    pub uids_updated: Vec<u32>,
}

/// `mark_read` handler.
pub async fn handle_mark_read(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Seen],
        FlagAction::Add,
    ))
    .await
}

/// `mark_unread` handler.
pub async fn handle_mark_unread(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Seen],
        FlagAction::Remove,
    ))
    .await
}

/// `flag` handler.
pub async fn handle_flag(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Flagged],
        FlagAction::Add,
    ))
    .await
}

/// `unflag` handler.
pub async fn handle_unflag(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Flagged],
        FlagAction::Remove,
    ))
    .await
}

async fn handle_flag_op(
    account: &AccountState,
    input: FlagInput,
    flags: &[Flag],
    action: FlagAction,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    let uids = resolve_uids(input.uid, input.uids)?;
    let updated = account
        .imap
        .store_flags(&input.folder, &uids, flags, action)
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();

    Ok(ToolResponse {
        meta: FlagsMeta {
            folder: input.folder,
            uids_updated: updated_ids,
        },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Maximum number of UIDs in a single batch operation.
pub(crate) const MAX_BATCH_UIDS: usize = 100;

/// Resolve `uid` or `uids` from input to a `Vec<Uid>`.
pub fn resolve_uids(
    uid: Option<u32>,
    uids: Option<Vec<u32>>,
) -> Result<Vec<Uid>, rimap_core::RimapError> {
    match (uid, uids) {
        (Some(u), None) => {
            let uid = Uid::new(u)
                .ok_or_else(|| rimap_core::RimapError::invalid_input("UID must be non-zero"))?;
            Ok(vec![uid])
        }
        (None, Some(us)) => {
            if us.len() > MAX_BATCH_UIDS {
                return Err(rimap_core::RimapError::invalid_input(format!(
                    "uids batch size {} exceeds maximum of {MAX_BATCH_UIDS}",
                    us.len()
                )));
            }
            let mut result = Vec::with_capacity(us.len());
            for u in us {
                let uid = Uid::new(u)
                    .ok_or_else(|| rimap_core::RimapError::invalid_input("UID must be non-zero"))?;
                result.push(uid);
            }
            Ok(result)
        }
        (Some(_), Some(_)) => Err(rimap_core::RimapError::invalid_input(
            "provide uid or uids, not both",
        )),
        (None, None) => Err(rimap_core::RimapError::invalid_input("provide uid or uids")),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn resolve_uids_single() {
        let result = resolve_uids(Some(42), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get(), 42);
    }

    #[test]
    fn resolve_uids_batch_within_limit() {
        let uids: Vec<u32> = (1..=100).collect();
        let result = resolve_uids(None, Some(uids)).unwrap();
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn resolve_uids_batch_exceeds_limit() {
        let uids: Vec<u32> = (1..=101).collect();
        let result = resolve_uids(None, Some(uids));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn resolve_uids_rejects_zero() {
        let result = resolve_uids(Some(0), None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("non-zero"));
    }

    #[test]
    fn resolve_uids_rejects_both() {
        let result = resolve_uids(Some(1), Some(vec![2]));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_uids_rejects_neither() {
        let result = resolve_uids(None, None);
        assert!(result.is_err());
    }
}
