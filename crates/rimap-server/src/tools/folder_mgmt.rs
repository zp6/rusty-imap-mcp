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
    let protected = &server.config.config.security.protected_folders;
    if protected
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&input.name))
    {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: format!(
                "cannot create folder `{}`: name collides with a protected folder",
                input.name
            ),
        });
    }

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
        .check_protected(&input.old_name, "rename")
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
