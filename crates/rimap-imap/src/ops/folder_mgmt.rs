//! Folder management: CREATE, RENAME, DELETE.

use crate::connection::ImapSession;
use crate::error::ImapError;

const MAX_FOLDER_NAME_BYTES: usize = 255;

/// Validate a folder name for CREATE or RENAME target.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` for empty names, names exceeding
/// 255 bytes, names containing control characters, or path traversal attempts.
pub(crate) fn validate_folder_name(name: &str) -> Result<(), ImapError> {
    if name.is_empty() {
        return Err(ImapError::InvalidInput {
            field: "folder_name",
            reason: "folder name must not be empty",
        });
    }
    if name.len() > MAX_FOLDER_NAME_BYTES {
        return Err(ImapError::InvalidInput {
            field: "folder_name",
            reason: "folder name exceeds 255 bytes",
        });
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ImapError::InvalidInput {
            field: "folder_name",
            reason: "folder name contains control characters",
        });
    }
    if name.contains("..") {
        return Err(ImapError::InvalidInput {
            field: "folder_name",
            reason: "folder name contains path traversal",
        });
    }
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
}
