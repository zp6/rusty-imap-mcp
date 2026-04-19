//! `list_folders` tool handler.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// A single folder entry in a `list_folders` response.
#[derive(Debug, Serialize)]
pub struct FolderEntry {
    /// Folder name.
    pub name: String,
    /// Hierarchy delimiter character reported by the server.
    pub delimiter: Option<char>,
    /// IMAP folder attribute flags (e.g. `"\\HasNoChildren"`).
    pub flags: Vec<String>,
    /// Number of messages in the folder, if available.
    pub exists: Option<u32>,
    /// Number of unseen messages, if available.
    pub unseen: Option<u32>,
    /// UID validity value for the folder, if available.
    pub uid_validity: Option<u32>,
}

/// Trusted metadata for a `list_folders` response.
#[derive(Debug, Serialize)]
pub struct ListFoldersMeta {
    /// All folders returned by the server.
    pub folders: Vec<FolderEntry>,
}

/// Execute the `list_folders` tool.
///
/// Non-selectable folders (RFC 3501 `\Noselect` namespace parents such as
/// Gmail's `[Gmail]`, RFC 5258 `\NonExistent` entries) are returned with
/// `exists`/`unseen`/`uid_validity` left as `None`. Running `STATUS`
/// against them is a protocol error on strict servers and would abort the
/// whole tool call.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` if the server rejects LIST or any
/// of the per-folder STATUS calls against a selectable folder. The
/// upstream `DispatchGuard::pre_dispatch` gate may also return
/// `PostureDenied`.
pub async fn handle(
    account: &AccountState,
) -> Result<ToolResponse<ListFoldersMeta>, rimap_core::RimapError> {
    let folders = account.imap.list_folders("*").await?;

    let status_items = rimap_imap::types::StatusItems {
        messages: true,
        recent: false,
        uid_next: false,
        uid_validity: true,
        unseen: true,
    };

    let mut folder_entries = Vec::with_capacity(folders.len());
    for folder in folders {
        let (exists, unseen, uid_validity) = if folder.selectable {
            let status = account.imap.status(&folder.name, status_items).await?;
            (status.messages, status.unseen, status.uid_validity)
        } else {
            (None, None, None)
        };

        folder_entries.push(FolderEntry {
            name: folder.name,
            delimiter: folder.delimiter,
            flags: folder.attributes,
            exists,
            unseen,
            uid_validity,
        });
    }

    Ok(ToolResponse::meta_only(ListFoldersMeta {
        folders: folder_entries,
    }))
}
