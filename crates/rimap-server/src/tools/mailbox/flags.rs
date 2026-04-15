//! Flag mutation tool handlers: `mark_read`, `mark_unread`, `flag`,
//! `unflag`.
//!
//! # Errors (applies to all four handlers)
//!
//! The `uid`/`uids` shape is validated at deserialize time via
//! [`rimap_core::UidSelector`] — ambiguous or empty payloads fail with a
//! JSON-Schema error before the handler runs. Returns
//! `RimapError::Imap { ... }` for IMAP-layer failures. The upstream
//! `DispatchGuard::pre_dispatch` gate may return `PostureDenied`.

use rimap_core::UidSelector;
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
    /// UID target: `{"uid": N}` or `{"uids": [...]}`.
    #[serde(flatten)]
    pub target: UidSelector,
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
    let uids: Vec<Uid> = input
        .target
        .into_uids()
        .into_iter()
        .map(Uid::from)
        .collect();
    let updated = account
        .imap
        .store_flags(&input.folder, &uids, flags, action)
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();

    Ok(ToolResponse::meta_only(FlagsMeta {
        folder: input.folder,
        uids_updated: updated_ids,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn flag_input_parses_single_shape() {
        let input: FlagInput = serde_json::from_str(r#"{"folder": "INBOX", "uid": 42}"#).unwrap();
        assert_eq!(input.folder, "INBOX");
        let uids: Vec<u32> = input.target.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(uids, vec![42]);
    }

    #[test]
    fn flag_input_parses_batch_shape() {
        let input: FlagInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uids": [1, 2, 3]}"#).unwrap();
        let got: Vec<u32> = input.target.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn flag_input_rejects_both_uid_shapes() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uid": 1, "uids": [2]}"#)
                .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_neither_uid_shape() {
        let err = serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX"}"#).unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_empty_batch() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uids": []}"#).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_oversized_batch() {
        let uids: Vec<u32> = (1..=101).collect();
        let json =
            serde_json::to_string(&serde_json::json!({"folder": "INBOX", "uids": uids})).unwrap();
        let err = serde_json::from_str::<FlagInput>(&json).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_zero_uid() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uid": 0}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}"
        );
    }
}
