//! Folder management: CREATE, RENAME, DELETE.

use crate::connection::ImapSession;
use crate::error::ImapError;

/// Validate a folder name for CREATE / RENAME / DELETE / STORE.
///
/// Thin wrapper around [`rimap_core::FolderName::new`]: the actual
/// rule set is the workspace-canonical one, this function only maps
/// [`rimap_core::FolderNameError`] into [`ImapError::InvalidInput`].
/// Server-returned names go through the separate, intentionally more
/// permissive [`super::folders::validate_server_folder_name`] instead.
///
/// # Errors
///
/// Returns [`ImapError::InvalidInput`] when the canonical validator
/// rejects the name. The original `reason` is collapsed to a static
/// label because [`ImapError::InvalidInput::reason`] is `&'static str`;
/// the rejected codepoints/characters are not echoed back to clients.
pub(crate) fn validate_folder_name(name: &str) -> Result<(), ImapError> {
    rimap_core::FolderName::new(name).map_err(|_| ImapError::InvalidInput {
        field: "folder_name",
        reason: "folder name failed structural validation",
    })?;
    Ok(())
}

/// CREATE a new mailbox.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` for invalid names.
/// Propagates protocol errors from async-imap.
pub(crate) async fn create_folder(session: &mut ImapSession, name: &str) -> Result<(), ImapError> {
    validate_folder_name(name)?;
    session
        .create(name)
        .await
        .map_err(super::folders::map_err)?;
    Ok(())
}

/// RENAME a mailbox.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` for invalid `old_name` or `new_name`.
/// Propagates protocol errors from async-imap.
pub(crate) async fn rename_folder(
    session: &mut ImapSession,
    old_name: &str,
    new_name: &str,
) -> Result<(), ImapError> {
    validate_folder_name(old_name)?;
    validate_folder_name(new_name)?;
    session
        .rename(old_name, new_name)
        .await
        .map_err(super::folders::map_err)?;
    Ok(())
}

/// DELETE a mailbox and all its contents.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` for invalid names.
/// Propagates protocol errors from async-imap.
pub(crate) async fn delete_folder(session: &mut ImapSession, name: &str) -> Result<(), ImapError> {
    validate_folder_name(name)?;
    session
        .delete(name)
        .await
        .map_err(super::folders::map_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_empty_name_rejected() {
        assert!(validate_folder_name("").is_err());
    }

    #[test]
    fn validate_long_name_rejected() {
        let long = "a".repeat(256);
        assert!(validate_folder_name(&long).is_err());
    }

    #[test]
    fn validate_control_characters_rejected() {
        assert!(validate_folder_name("bad\0name").is_err());
        assert!(validate_folder_name("bad\r\nname").is_err());
        assert!(validate_folder_name("bad\x01name").is_err());
        assert!(validate_folder_name("bad\x7fname").is_err());
    }

    #[test]
    fn validate_traversal_rejected() {
        assert!(validate_folder_name("../escape").is_err());
        assert!(validate_folder_name("a/../b").is_err());
    }

    #[test]
    fn validate_normal_name_accepted() {
        assert!(validate_folder_name("Archives").is_ok());
        assert!(validate_folder_name("Work/Projects").is_ok());
        assert!(validate_folder_name("a".repeat(255).as_str()).is_ok());
    }

    #[test]
    fn validate_folder_name_rejects_dot_segment() {
        assert!(validate_folder_name("a/./b").is_err());
        assert!(validate_folder_name("./a").is_err());
        assert!(validate_folder_name("a/.").is_err());
    }

    #[test]
    fn validate_folder_name_rejects_dotdot_segment() {
        assert!(validate_folder_name("a/../b").is_err());
        assert!(validate_folder_name("../a").is_err());
        assert!(validate_folder_name("a/..").is_err());
    }

    #[test]
    fn validate_folder_name_accepts_legitimate_dots_in_segment() {
        // Legitimate: "Receipts..2024" is a name with dots in the middle,
        // not a path traversal. The old substring check rejected it.
        assert!(validate_folder_name("Mail/Receipts..2024").is_ok());
        assert!(validate_folder_name("my.folder").is_ok());
    }

    #[test]
    fn validate_folder_name_rejects_bidi_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — common spoofing vector.
        assert!(validate_folder_name("folder\u{202e}txt").is_err());
    }

    #[test]
    fn validate_folder_name_rejects_zero_width_joiner() {
        // U+200D ZERO WIDTH JOINER.
        assert!(validate_folder_name("evil\u{200d}folder").is_err());
    }
}
