//! `list_folders` tool handler.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

const MAX_FOLDER_NAME_BYTES: usize = 1024;

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
    /// Security warnings accumulated while sanitizing folder names and
    /// flags against bidi overrides, zero-width characters, and C0/C1
    /// control bytes (#98). Serialized only when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<rimap_content::output::SecurityWarning>,
}

/// Sanitize a list of `Folder` entries for inclusion in the `list_folders`
/// MCP response. Returns the sanitized `FolderEntry` list and the
/// accumulated security warnings.
///
/// Folder names and flags are run through `rimap_content::unicode::sanitize`
/// so server-controlled bidi overrides, zero-width characters, and C0/C1
/// stripping are surfaced as structured warnings rather than riding
/// unfiltered under the trusted `meta` envelope (#98).
///
/// Used only from unit tests; `handle` inlines the same logic to merge
/// `FolderStatus` data at construction time.
#[cfg(test)]
pub(crate) fn sanitize_folder_entries(
    folders: Vec<rimap_imap::types::Folder>,
) -> (
    Vec<FolderEntry>,
    Vec<rimap_content::output::SecurityWarning>,
) {
    let mut entries = Vec::with_capacity(folders.len());
    let mut warnings = Vec::new();

    for folder in folders {
        let (clean_name, name_warnings) = rimap_content::unicode::sanitize(
            folder.name.as_bytes(),
            None,
            MAX_FOLDER_NAME_BYTES,
            "folder.name",
        );
        warnings.extend(name_warnings);

        let flags: Vec<String> = folder
            .attributes
            .iter()
            .map(|attr| {
                let raw = attr.as_wire_str();
                let (clean, flag_warnings) = rimap_content::unicode::sanitize(
                    raw.as_bytes(),
                    None,
                    MAX_FOLDER_NAME_BYTES,
                    "folder.flag",
                );
                warnings.extend(flag_warnings);
                clean
            })
            .collect();

        entries.push(FolderEntry {
            name: clean_name,
            delimiter: folder.delimiter,
            flags,
            exists: None,
            unseen: None,
            uid_validity: None,
        });
    }

    (entries, warnings)
}

/// Execute the `list_folders` tool.
///
/// Non-selectable folders (RFC 3501 `\Noselect` namespace parents such as
/// Gmail's `[Gmail]`, RFC 5258 `\NonExistent` entries) are returned with
/// `exists`/`unseen`/`uid_validity` left as `None`.
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
    let pairs = account.imap.list_folders_with_status("*").await?;

    let mut entries = Vec::with_capacity(pairs.len());
    let mut warnings: Vec<rimap_content::output::SecurityWarning> = Vec::new();

    for (folder, status) in pairs {
        let (clean_name, name_warnings) = rimap_content::unicode::sanitize(
            folder.name.as_bytes(),
            None,
            MAX_FOLDER_NAME_BYTES,
            "folder.name",
        );
        warnings.extend(name_warnings);

        let flags: Vec<String> = folder
            .attributes
            .iter()
            .map(|attr| {
                let raw = attr.as_wire_str();
                let (clean, flag_warnings) = rimap_content::unicode::sanitize(
                    raw.as_bytes(),
                    None,
                    MAX_FOLDER_NAME_BYTES,
                    "folder.flag",
                );
                warnings.extend(flag_warnings);
                clean
            })
            .collect();

        entries.push(FolderEntry {
            name: clean_name,
            delimiter: folder.delimiter,
            flags,
            exists: status.as_ref().and_then(|s| s.messages),
            unseen: status.as_ref().and_then(|s| s.unseen),
            uid_validity: status.as_ref().and_then(|s| s.uid_validity),
        });
    }

    Ok(ToolResponse::meta_only(ListFoldersMeta {
        folders: entries,
        security_warnings: warnings,
    }))
}

#[cfg(test)]
mod tests {
    use super::sanitize_folder_entries;
    use rimap_imap::types::{Folder, FolderAttribute};

    #[test]
    fn sanitizes_bidi_in_folder_name_and_emits_warning() {
        let folders = vec![Folder {
            name: "Inbox\u{202e}gnilleS".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert!(
            !entries[0].name.contains('\u{202e}'),
            "sanitized name should not contain U+202E, got: {:?}",
            entries[0].name,
        );
        assert!(
            !warnings.is_empty(),
            "sanitize should have produced a bidi-stripped warning",
        );
    }

    #[test]
    fn no_warnings_for_clean_folder_name() {
        let folders = vec![Folder {
            name: "INBOX".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "INBOX");
        assert!(
            warnings.is_empty(),
            "clean name should produce no warnings, got: {warnings:?}"
        );
    }
}
