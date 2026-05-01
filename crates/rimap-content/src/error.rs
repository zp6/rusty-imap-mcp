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

    /// Third-party MIME parser (`mail-parser`) panicked on the input.
    /// The panic was caught at the `rimap-content` boundary; the
    /// process is intact. Callers should treat this as a hard rejection
    /// of the message, equivalent to `Malformed` for control-flow
    /// purposes, but distinct for audit and alerting (a panic means an
    /// attacker found a way to crash the parser, not just bad bytes).
    #[error("third-party MIME parser panicked on input")]
    ParserPanic,
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

    #[test]
    fn parser_panic_display() {
        let err = ContentError::ParserPanic;
        assert_eq!(err.to_string(), "third-party MIME parser panicked on input");
    }
}
