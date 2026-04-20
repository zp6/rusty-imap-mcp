//! Validated IMAP folder name newtype.
//!
//! The actual validator now lives in [`rimap_core::folder_name`] so
//! both this crate (APPEND and folder-mutation paths via [`FolderGuard`])
//! and `rimap-imap` (CREATE / RENAME / DELETE / STORE / etc.) can
//! delegate to a single source of truth.
//!
//! [`FolderGuard`]: crate::FolderGuard

pub use rimap_core::folder_name::{FolderName, FolderNameError};

use crate::error::AuthzError;

impl From<FolderNameError> for AuthzError {
    fn from(err: FolderNameError) -> Self {
        AuthzError::InvalidFolderName {
            reason: err.reason.to_string(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    //! Smoke tests confirming the `From<FolderNameError> for AuthzError`
    //! mapping; the underlying validation rules are covered exhaustively
    //! in `rimap_core::folder_name::tests`.

    use super::FolderName;
    use crate::error::AuthzError;

    fn err_via_authz(name: &str) -> AuthzError {
        FolderName::new(name).map_err(AuthzError::from).unwrap_err()
    }

    #[test]
    fn rejection_maps_to_authz_invalid_folder_name() {
        assert!(matches!(
            err_via_authz(""),
            AuthzError::InvalidFolderName { .. }
        ));
        assert!(matches!(
            err_via_authz("test\0folder"),
            AuthzError::InvalidFolderName { .. }
        ));
    }

    #[test]
    fn authz_error_carries_canonical_reason() {
        match err_via_authz("") {
            AuthzError::InvalidFolderName { reason } => {
                assert!(reason.contains("empty"), "got reason: {reason}");
            }
            other => panic!("expected InvalidFolderName, got {other:?}"),
        }
    }

    #[test]
    fn valid_inbox_round_trips_through_canonical() {
        let f = FolderName::new("INBOX").unwrap();
        assert_eq!(f.as_str(), "INBOX");
    }
}
