//! Folder safety checks: protected folders and expunge allowlist.

use crate::error::AuthzError;
use crate::folder_name::FolderName;

/// Runtime folder safety guard built from config.
#[derive(Debug, Clone)]
pub struct FolderGuard {
    protected: Vec<String>,
    expunge_allowed: Vec<String>,
}

/// Decode Modified UTF-7 (if applicable) and lowercase for
/// case-insensitive comparison. If decoding fails, fall back to
/// ASCII-lowercased input — we compare against that so a malformed
/// encoding cannot silently bypass the guard.
fn normalize(folder: &str) -> String {
    let decoded = utf7_imap::decode_utf7_imap(folder.to_string());
    decoded.to_lowercase()
}

impl FolderGuard {
    /// Build from config values. Both lists are normalized (Modified
    /// UTF-7 decoded, then lowercased) for IMAP-aware case-insensitive
    /// matching.
    #[must_use]
    pub fn new(protected_folders: &[String], expunge_folders: &[String]) -> Self {
        Self {
            protected: protected_folders.iter().map(|f| normalize(f)).collect(),
            expunge_allowed: expunge_folders.iter().map(|f| normalize(f)).collect(),
        }
    }

    /// Check whether folder can be deleted or renamed.
    /// INBOX is always rejected. Validates folder name structure
    /// before comparison.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if validation fails.
    /// Returns [`AuthzError::ProtectedFolder`] if the folder is INBOX
    /// or appears in the protected list.
    pub fn check_protected(&self, folder: &str, operation: &'static str) -> Result<(), AuthzError> {
        FolderName::new(folder)?;
        let norm = normalize(folder);
        if norm == "inbox" || self.protected.contains(&norm) {
            return Err(AuthzError::ProtectedFolder {
                folder: folder.to_string(),
                operation,
            });
        }
        Ok(())
    }

    /// Check that neither `old_name` nor `new_name` is protected.
    /// Both names are validated and compared using IMAP-aware
    /// normalization.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if either name
    /// fails validation. Returns [`AuthzError::ProtectedFolder`]
    /// if either name is in the protected list or is INBOX.
    pub fn check_rename(&self, old_name: &str, new_name: &str) -> Result<(), AuthzError> {
        self.check_protected(old_name, "rename")?;
        self.check_protected(new_name, "rename")?;
        Ok(())
    }

    /// Check that neither the source nor the destination of a move is
    /// protected. Both names are validated and compared using
    /// IMAP-aware normalization. Delegates to [`Self::check_protected`]
    /// so INBOX is always rejected as either side of a move.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if either name
    /// fails validation. Returns [`AuthzError::ProtectedFolder`]
    /// if either name is in the protected list or is INBOX.
    pub fn check_move(&self, src: &str, dst: &str) -> Result<(), AuthzError> {
        self.check_protected(src, "move")?;
        self.check_protected(dst, "move")?;
        Ok(())
    }

    /// Check whether folder is in the expunge allowlist. Validates
    /// folder name structure before comparison.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if validation fails.
    /// Returns [`AuthzError::ExpungeDenied`] if the folder is not in
    /// the expunge allowlist.
    pub fn check_expunge(&self, folder: &str) -> Result<(), AuthzError> {
        FolderName::new(folder)?;
        let norm = normalize(folder);
        if !self.expunge_allowed.contains(&norm) {
            return Err(AuthzError::ExpungeDenied {
                folder: folder.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FolderGuard;
    use crate::error::AuthzError;

    fn guard() -> FolderGuard {
        FolderGuard::new(
            &[
                "INBOX".into(),
                "Sent".into(),
                "Drafts".into(),
                "Trash".into(),
            ],
            &["Trash".into()],
        )
    }

    #[test]
    fn inbox_always_protected_even_if_not_in_list() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_protected("INBOX", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("inbox", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("Inbox", "rename"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn protected_folder_rejected_case_insensitive() {
        let g = guard();
        assert!(matches!(
            g.check_protected("sent", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("SENT", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn unprotected_folder_allowed() {
        let g = guard();
        assert!(g.check_protected("Archives", "delete").is_ok());
        assert!(g.check_protected("Old Mail", "rename").is_ok());
    }

    #[test]
    fn expunge_allowed_for_listed_folder() {
        let g = guard();
        assert!(g.check_expunge("Trash").is_ok());
        assert!(g.check_expunge("trash").is_ok());
        assert!(g.check_expunge("TRASH").is_ok());
    }

    #[test]
    fn expunge_denied_for_unlisted_folder() {
        let g = guard();
        assert!(matches!(
            g.check_expunge("INBOX"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
        assert!(matches!(
            g.check_expunge("Sent"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn empty_expunge_list_denies_everything() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_expunge("Trash"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn folder_name_validation_runs_in_check_protected() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_protected("test\0folder", "delete"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn folder_name_validation_runs_in_check_expunge() {
        let g = FolderGuard::new(&[], &["Trash".into()]);
        assert!(matches!(
            g.check_expunge("test\0folder"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn rename_rejects_protected_old_name() {
        let g = guard();
        assert!(matches!(
            g.check_rename("Sent", "Archive"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn rename_rejects_protected_new_name() {
        let g = guard();
        assert!(matches!(
            g.check_rename("MyFolder", "INBOX"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn rename_allows_unprotected_both() {
        let g = guard();
        assert!(g.check_rename("Old", "New").is_ok());
    }

    #[test]
    fn move_rejects_protected_source() {
        let g = guard();
        assert!(matches!(
            g.check_move("Sent", "Archive"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn move_rejects_protected_destination() {
        let g = guard();
        assert!(matches!(
            g.check_move("MyFolder", "INBOX"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn move_rejects_inbox_source_even_when_not_listed() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_move("INBOX", "Archive"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn move_allows_unprotected_both() {
        let g = guard();
        assert!(g.check_move("Old", "New").is_ok());
    }

    #[test]
    fn move_validates_folder_names() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_move("test\0folder", "Archive"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
        assert!(matches!(
            g.check_move("Archive", "test\0folder"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }
}
