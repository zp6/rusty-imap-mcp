//! Validated IMAP folder name newtype.
//!
//! Rejects structurally invalid names before they reach the IMAP
//! layer, closing injection and traversal vectors at the
//! authorization boundary.

use std::fmt;

use crate::error::AuthzError;

/// A structurally validated IMAP folder name.
///
/// Invariants enforced by [`FolderName::new`]:
/// - non-empty and not whitespace-only
/// - at most 255 bytes
/// - no NUL bytes
/// - no control characters (0x00–0x1F except TAB, plus 0x7F)
/// - no path traversal (`..` component)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderName(String);

impl FolderName {
    /// Validate and wrap a raw folder name string.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if any structural
    /// check fails.
    pub fn new(raw: &str) -> Result<Self, AuthzError> {
        validate(raw)?;
        Ok(Self(raw.to_string()))
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FolderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Run all structural checks on a raw folder name.
fn validate(raw: &str) -> Result<(), AuthzError> {
    if raw.is_empty() {
        return Err(invalid("folder name must not be empty"));
    }
    if raw.trim().is_empty() {
        return Err(invalid("folder name must not be whitespace-only"));
    }
    if raw.len() > 255 {
        return Err(invalid("folder name exceeds 255-byte limit"));
    }
    for byte in raw.bytes() {
        if byte == 0x00 {
            return Err(invalid("folder name contains NUL byte"));
        }
        // Control chars 0x01–0x1F (except TAB 0x09) and DEL 0x7F
        let is_control = (byte <= 0x1F && byte != 0x09) || byte == 0x7F;
        if is_control {
            return Err(invalid("folder name contains control character"));
        }
    }
    if contains_traversal(raw) {
        return Err(invalid("folder name contains path traversal (..)"));
    }
    Ok(())
}

/// Check whether any path segment is exactly `..`.
fn contains_traversal(raw: &str) -> bool {
    // IMAP uses `/` as the common hierarchy delimiter; some servers
    // use `.`. Check both.
    for delim in ['/', '.'] {
        for segment in raw.split(delim) {
            if segment == ".." {
                return true;
            }
        }
    }
    false
}

fn invalid(reason: &str) -> AuthzError {
    AuthzError::InvalidFolderName {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::FolderName;
    use crate::error::AuthzError;

    #[test]
    fn valid_inbox() {
        let f = FolderName::new("INBOX").unwrap();
        assert_eq!(f.as_str(), "INBOX");
        assert_eq!(f.to_string(), "INBOX");
    }

    #[test]
    fn valid_with_spaces() {
        assert!(FolderName::new("My Folder").is_ok());
    }

    #[test]
    fn valid_gmail_hierarchy() {
        assert!(FolderName::new("[Gmail]/Trash").is_ok());
    }

    #[test]
    fn valid_archive_year() {
        assert!(FolderName::new("Archives/2024").is_ok());
    }

    #[test]
    fn reject_empty() {
        assert!(matches!(
            FolderName::new(""),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn reject_whitespace_only() {
        assert!(matches!(
            FolderName::new("   "),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn reject_exceeds_255_bytes() {
        let long = "a".repeat(256);
        assert!(matches!(
            FolderName::new(&long),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn accept_exactly_255_bytes() {
        let exact = "a".repeat(255);
        assert!(FolderName::new(&exact).is_ok());
    }

    #[test]
    fn reject_nul_byte() {
        assert!(matches!(
            FolderName::new("test\0folder"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn reject_control_chars() {
        // CR, LF, BEL
        for ch in ['\r', '\n', '\x07'] {
            let name = format!("test{ch}folder");
            assert!(
                matches!(
                    FolderName::new(&name),
                    Err(AuthzError::InvalidFolderName { .. })
                ),
                "should reject control char {ch:?}"
            );
        }
    }

    #[test]
    fn reject_del() {
        assert!(matches!(
            FolderName::new("test\x7Ffolder"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn allow_tab() {
        assert!(FolderName::new("test\tfolder").is_ok());
    }

    #[test]
    fn reject_path_traversal_slash() {
        assert!(matches!(
            FolderName::new("foo/../bar"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn reject_path_traversal_bare() {
        assert!(matches!(
            FolderName::new(".."),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn reject_path_traversal_dot_delim() {
        // With `.` as hierarchy delimiter, `a...b` has a `..`
        // segment between the dots: split on `.` yields ["a","","","b"]
        // — no segment is exactly `..`. But `foo/..` does.
        assert!(matches!(
            FolderName::new("foo/.."),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn display_matches_inner() {
        let f = FolderName::new("Sent").unwrap();
        assert_eq!(format!("{f}"), "Sent");
    }
}
