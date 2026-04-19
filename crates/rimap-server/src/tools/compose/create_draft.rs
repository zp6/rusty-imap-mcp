//! `create_draft` tool handler: compose a draft email and APPEND it
//! to the Drafts folder with a `$PendingReview` keyword.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::compose::message_builder::{self, ComposeInput};

/// Input for `create_draft` — identical to shared `ComposeInput`.
pub type CreateDraftInput = ComposeInput;

/// Trusted metadata for a `create_draft` response.
#[derive(Debug, Serialize)]
pub struct CreateDraftMeta {
    /// Folder the draft was appended to.
    pub folder: String,
    /// UID assigned by the server, if returned.
    pub uid: Option<u32>,
    /// RFC 2822 `Message-ID` assigned to the draft.
    pub message_id: Option<String>,
    /// IMAP keywords applied to the draft.
    pub keywords: Vec<&'static str>,
}

/// `create_draft` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// recipient addresses, subject/body size violations, or bad threading
/// headers. Returns `RimapError::Imap { ... }` on APPEND failure.
/// Returns `RimapError::Internal` if `message_builder::build_message`
/// or `apply_threading_headers` reports an unrecoverable construction
/// failure (should not happen with validated input). The upstream
/// `DispatchGuard::pre_dispatch` gate returns
/// `Authz { code: PostureDenied }` when posture forbids draft creation.
pub async fn handle(
    account: &AccountState,
    input: CreateDraftInput,
) -> Result<ToolResponse<CreateDraftMeta>, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;
    let from_addr = account.imap.username();
    let raw_msg = message_builder::build_message(account, from_addr, &input).await?;

    let drafts_folder: &str = account.special_use.drafts().unwrap_or("Drafts");
    let result = account
        .imap
        .append_message(
            drafts_folder,
            &raw_msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await?;

    let generated_msg_id = rimap_content::extract_message_id(&raw_msg);

    Ok(ToolResponse::meta_only(CreateDraftMeta {
        folder: drafts_folder.to_string(),
        uid: result.uid.map(rimap_imap::types::Uid::get),
        message_id: generated_msg_id,
        keywords: vec!["$PendingReview"],
    }))
}
