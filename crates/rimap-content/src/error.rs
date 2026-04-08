//! Error type for the rimap-content pipeline.

use thiserror::Error;

/// Errors returned by [`crate::parse_message`]. A successful parse
/// returns `Ok(Content)` — warnings (including header-smuggling
/// detections that dropped an offending header) are reported via
/// `Content::security_warnings`, not via this enum.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ContentError {
    /// The message could not be parsed as RFC 5322. This is a hard
    /// failure — `mail-parser` rejected the byte stream entirely.
    #[error("malformed message: {reason}")]
    Malformed {
        /// Short description of what went wrong.
        reason: String,
    },

    /// A hard limit was exceeded. The caller should reject the message.
    /// `kind` names which limit tripped; `limit` is the compile-time
    /// constant value.
    #[error("content limit exceeded: {kind} (limit={limit})")]
    LimitExceeded {
        /// Which limit was exceeded (e.g. `"mime_depth"`, `"mime_parts"`,
        /// `"header_count"`).
        kind: &'static str,
        /// The compile-time limit value that was exceeded.
        limit: usize,
    },

    /// Character-set decoding failed and no replacement strategy could
    /// produce valid UTF-8. This should be vanishingly rare because
    /// `encoding_rs` always returns replacement characters on failure.
    #[error("text decoding failed: {reason}")]
    Decoding {
        /// Short description of the decoding failure.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_exceeded_display() {
        let err = ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: 8,
        };
        assert_eq!(
            err.to_string(),
            "content limit exceeded: mime_depth (limit=8)"
        );
    }

    #[test]
    fn malformed_display() {
        let err = ContentError::Malformed {
            reason: "unterminated boundary".to_string(),
        };
        assert_eq!(err.to_string(), "malformed message: unterminated boundary");
    }
}
