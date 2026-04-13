//! Folder management tool handlers: create, rename, delete.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `create_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFolderInput {
    /// Name of the folder to create.
    pub name: String,
}

/// Input for `rename_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFolderInput {
    /// Current folder name.
    pub old_name: String,
    /// New folder name.
    pub new_name: String,
}

/// Input for `delete_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFolderInput {
    /// Name of the folder to delete.
    pub name: String,
}

/// `create_folder` handler.
pub async fn handle_create(
    server: &ImapMcpServer,
    input: CreateFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    server
        .folder_guard
        .check_protected(&input.name, "create")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    server.imap.create_folder(&input.name).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "created": true,
            "folder": input.name,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `rename_folder` handler.
pub async fn handle_rename(
    server: &ImapMcpServer,
    input: RenameFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    server
        .folder_guard
        .check_rename(&input.old_name, &input.new_name)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    server
        .imap
        .rename_folder(&input.old_name, &input.new_name)
        .await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "renamed": true,
            "old_name": input.old_name,
            "new_name": input.new_name,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// `delete_folder` handler.
pub async fn handle_delete(
    server: &ImapMcpServer,
    input: DeleteFolderInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    server
        .folder_guard
        .check_protected(&input.name, "delete")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    server
        .folder_guard
        .check_expunge(&input.name)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;

    let status = server
        .imap
        .status(
            &input.name,
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

    server.imap.delete_folder(&input.name).await?;

    Ok(ToolResponse {
        meta: serde_json::json!({
            "deleted": true,
            "folder": input.name,
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
