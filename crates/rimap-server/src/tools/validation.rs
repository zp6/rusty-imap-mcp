//! Cross-cutting input-validation helpers for tool handlers.

use rimap_authz::folder_name::FolderName;
use rimap_core::RimapError;

/// Validate `name` as a structurally well-formed IMAP folder, mapping
/// any rejection into [`RimapError::invalid_input`] prefixed with
/// `label`. The prefix names the field the client passed in (e.g.
/// `"folder"`, `"destination"`, `"drafts folder"`) so the resulting
/// error text points at the offending input.
///
/// Consolidates the `FolderName::new(...).map_err(|e| ...)` shape
/// repeated across `move_message`, `create_draft`, and
/// `message_builder`'s threading check. `send_email` does NOT use
/// this helper because its resolved-Sent-folder failure routes
/// through `sent_copy.failed` rather than returning an error to the
/// caller.
///
/// # Errors
///
/// Returns [`RimapError::invalid_input`] when [`FolderName::new`]
/// rejects `name`.
pub(crate) fn validate_folder_input(label: &str, name: &str) -> Result<(), RimapError> {
    FolderName::new(name).map_err(|e| RimapError::invalid_input(format!("{label}: {e}")))?;
    Ok(())
}
