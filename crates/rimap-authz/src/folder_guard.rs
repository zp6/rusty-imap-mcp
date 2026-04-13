//! Folder safety checks: protected folders and expunge allowlist.

use crate::error::AuthzError;

/// Runtime folder safety guard built from config.
#[derive(Debug, Clone)]
pub struct FolderGuard {
    protected: Vec<String>,
    expunge_allowed: Vec<String>,
}

impl FolderGuard {
    /// Build from config values. Both lists are lowercased for
    /// case-insensitive matching.
    #[must_use]
    pub fn new(protected_folders: &[String], expunge_folders: &[String]) -> Self {
        Self {
            protected: protected_folders.iter().map(|f| f.to_lowercase()).collect(),
            expunge_allowed: expunge_folders.iter().map(|f| f.to_lowercase()).collect(),
        }
    }

    /// Check whether folder can be deleted or renamed.
    /// INBOX is always rejected.
    ///
    /// # Errors
    /// Returns [`AuthzError::ProtectedFolder`] if the folder is INBOX or
    /// appears in the protected list.
    pub fn check_protected(&self, folder: &str, operation: &'static str) -> Result<(), AuthzError> {
        let lower = folder.to_lowercase();
        if lower == "inbox" || self.protected.contains(&lower) {
            return Err(AuthzError::ProtectedFolder {
                folder: folder.to_string(),
                operation,
            });
        }
        Ok(())
    }

    /// Check whether folder is in the expunge allowlist.
    ///
    /// # Errors
    /// Returns [`AuthzError::ExpungeDenied`] if the folder is not in the
    /// expunge allowlist.
    pub fn check_expunge(&self, folder: &str) -> Result<(), AuthzError> {
        let lower = folder.to_lowercase();
        if !self.expunge_allowed.contains(&lower) {
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
}
