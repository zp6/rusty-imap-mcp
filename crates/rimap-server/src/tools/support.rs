//! Cross-cutting helpers shared by `retrieval` and `mailbox` handlers.

use rimap_imap::types::{FetchSpec, FetchedMessage, Uid};

use crate::boot::registry::AccountState;

/// Fetch exactly one message by UID, mapping an empty result to
/// `Authz { code: NotFound }`.
///
/// Several handlers (`list_attachments`, `list_labels`, ...) share this
/// preamble: request a single UID with a caller-chosen `FetchSpec`, then
/// treat an empty response as "UID not present in folder". Each caller
/// keeps its own `FetchSpec` so only the dedup-worthy code is centralized.
///
/// # Errors
///
/// - `RimapError::Authz { code: NotFound }` if the server returned no
///   message for `uid` in `folder`.
/// - Propagates `RimapError::Imap { ... }` from the underlying
///   `SELECT` / `UID FETCH`.
pub(crate) async fn fetch_single_by_uid(
    account: &AccountState,
    folder: &str,
    uid: Uid,
    spec: FetchSpec,
) -> Result<FetchedMessage, rimap_core::RimapError> {
    let messages = account.imap.fetch(folder, &[uid], spec).await?;
    messages
        .into_iter()
        .next()
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!("message UID {} not found in folder '{}'", uid.get(), folder),
        })
}
