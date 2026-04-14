//! Folder management tool handlers: create, rename, delete.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `create_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFolderInput {
    /// Folder to create.
    pub folder: String,
}

/// Input for `rename_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFolderInput {
    /// Current folder name.
    pub folder: String,
    /// New folder name.
    pub new_folder: String,
}

/// Input for `delete_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFolderInput {
    /// Folder to delete.
    pub folder: String,
}

/// `create_folder` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: ProtectedFolder, ... }` if the name
/// is protected (including INBOX). Returns `RimapError::Imap { code:
/// InvalidInput, ... }` if the folder name fails
/// `validate_folder_name` (empty, too long, forbidden chars).
/// Propagates `RimapError::Imap { ... }` from the underlying CREATE.
pub async fn handle_create(
    account: &AccountState,
    input: CreateFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    account
        .folder_guard
        .check_protected(&input.folder, "create")?;

    account.imap.create_folder(&input.folder).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "created": true,
            "folder": input.folder,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `rename_folder` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: ProtectedFolder, ... }` if either
/// the source or destination name is protected (including INBOX).
/// Returns `RimapError::Imap { code: InvalidInput, ... }` if either
/// name fails `validate_folder_name`. Propagates `RimapError::Imap
/// { ... }` from the underlying RENAME.
pub async fn handle_rename(
    account: &AccountState,
    input: RenameFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    account
        .folder_guard
        .check_rename(&input.folder, &input.new_folder)?;

    account
        .imap
        .rename_folder(&input.folder, &input.new_folder)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "renamed": true,
            "old_folder": input.folder,
            "new_folder": input.new_folder,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `delete_folder` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: ProtectedFolder, ... }` if the name
/// is protected. Returns `RimapError::Authz { code: ExpungeDenied, ... }`
/// if expunge is not permitted for the folder. Returns
/// `RimapError::Imap { code: InvalidInput, ... }` if the folder name
/// fails `validate_folder_name`. Propagates `RimapError::Imap { ... }`
/// from STATUS and DELETE.
pub async fn handle_delete(
    account: &AccountState,
    input: DeleteFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    account
        .folder_guard
        .check_protected(&input.folder, "delete")?;

    account.folder_guard.check_expunge(&input.folder)?;

    let status = account
        .imap
        .status(
            &input.folder,
            rimap_imap::types::StatusItems {
                messages: true,
                recent: false,
                uid_next: false,
                uid_validity: false,
                unseen: false,
            },
        )
        .await?;
    let message_count = status.messages.unwrap_or(0);

    account.imap.delete_folder(&input.folder).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "folder": input.folder,
            "message_count": message_count,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_authz::FolderGuard;
    use rimap_core::error::ErrorCode;

    #[test]
    fn rename_to_protected_folder_rejected() {
        let guard = FolderGuard::new(&["Sent".into(), "Drafts".into()], &[]);
        let err = guard.check_rename("temp", "Sent").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }

    #[test]
    fn rename_to_inbox_rejected() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_rename("temp", "INBOX").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }

    #[test]
    fn create_inbox_rejected_even_with_empty_protected_list() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_protected("INBOX", "create").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }
}
