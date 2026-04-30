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
/// used at the top of every folder-taking tool handler plus
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::validate_folder_input;

    #[test]
    fn accepts_well_formed_folder() {
        assert!(validate_folder_input("folder", "INBOX").is_ok());
        assert!(validate_folder_input("drafts folder", "[Gmail]/Drafts").is_ok());
    }

    #[test]
    fn rejects_bidi_override_with_label_in_message() {
        let err = validate_folder_input("folder", "INBOX\u{202e}txt").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("folder:"),
            "expected label prefix in error, got: {msg}",
        );
    }

    #[test]
    fn rejects_unicode_tag_characters() {
        // U+E0041 is a Tag Character (prompt-injection vector).
        let err = validate_folder_input("folder", "Work\u{e0041}").unwrap_err();
        assert!(err.to_string().contains("folder:"));
    }

    #[test]
    fn label_is_forwarded_into_error_text() {
        let err = validate_folder_input("destination", "bad\0folder").unwrap_err();
        assert!(
            err.to_string().contains("destination:"),
            "expected 'destination:' prefix, got: {err}",
        );
    }
}
