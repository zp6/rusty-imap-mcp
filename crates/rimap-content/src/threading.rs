//! Threading-header extraction (Message-ID / In-Reply-To / References).
//!
//! Thin typed wrapper over `mail_parser` so tool handlers do not need
//! to `use mail_parser::*` directly. Produces `ThreadingHeaders` from
//! raw RFC 5322 bytes.

use crate::parse::MAX_HEADER_BYTES;
use crate::unicode;

/// Parsed threading headers.
///
/// `message_id`, entries of `references`, and `in_reply_to` are
/// stripped of `<` / `>` delimiters and routed through the same
/// Unicode sanitizer used for `ContentMeta::message_id`. Warnings
/// emitted by the sanitizer are dropped — callers that care about
/// unicode-level warnings on raw-bytes input should use
/// `parse_message` instead.
#[derive(Debug, Clone, Default)]
pub struct ThreadingHeaders {
    /// `Message-ID` of the referenced message, if present.
    pub message_id: Option<String>,
    /// Parsed `References:` chain, one entry per ID.
    pub references: Vec<String>,
    /// Parsed `In-Reply-To:` value, if present.
    pub in_reply_to: Option<String>,
}

/// Extract Message-ID, In-Reply-To, and References headers from raw
/// RFC 5322 bytes. Returns an empty `ThreadingHeaders` when the input
/// is not parseable.
#[must_use]
pub fn extract_threading_headers(raw: &[u8]) -> ThreadingHeaders {
    let Some(parsed) = mail_parser::MessageParser::new().parse(raw) else {
        return ThreadingHeaders::default();
    };

    let message_id = parsed
        .message_id()
        .map(|id| sanitize_msg_id(id, "header:message_id"));
    let in_reply_to = match parsed.in_reply_to() {
        mail_parser::HeaderValue::Text(t) => Some(sanitize_msg_id(t, "header:in_reply_to")),
        mail_parser::HeaderValue::TextList(_)
        | mail_parser::HeaderValue::Address(_)
        | mail_parser::HeaderValue::DateTime(_)
        | mail_parser::HeaderValue::ContentType(_)
        | mail_parser::HeaderValue::Received(_)
        | mail_parser::HeaderValue::Empty => None,
    };

    let mut references = Vec::new();
    match parsed.references() {
        mail_parser::HeaderValue::Text(t) => {
            references.push(sanitize_msg_id(t, "header:references"));
        }
        mail_parser::HeaderValue::TextList(list) => {
            for r in list {
                references.push(sanitize_msg_id(r, "header:references"));
            }
        }
        mail_parser::HeaderValue::Address(_)
        | mail_parser::HeaderValue::DateTime(_)
        | mail_parser::HeaderValue::ContentType(_)
        | mail_parser::HeaderValue::Received(_)
        | mail_parser::HeaderValue::Empty => {}
    }

    ThreadingHeaders {
        message_id,
        references,
        in_reply_to,
    }
}

/// Strip `<`, `>`, CR, LF, NUL from a Message-ID value, then route
/// the remainder through the shared Unicode sanitizer. Warnings are
/// discarded — this helper is used by lightweight consumers that do
/// not collect `SecurityWarning`s.
fn sanitize_msg_id(id: &str, location: &str) -> String {
    let stripped: String = id
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '\0' && *c != '<' && *c != '>')
        .collect();
    let (clean, _warnings) = unicode::sanitize(
        stripped.as_bytes(),
        Some("utf-8"),
        MAX_HEADER_BYTES,
        location,
    );
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_three_headers() {
        let raw = b"From: a@b\r\n\
                    Message-ID: <root@example.com>\r\n\
                    In-Reply-To: <parent@example.com>\r\n\
                    References: <g1@example.com> <parent@example.com>\r\n\
                    \r\n\
                    body\r\n";
        let h = extract_threading_headers(raw);
        assert_eq!(h.message_id.as_deref(), Some("root@example.com"));
        assert_eq!(h.in_reply_to.as_deref(), Some("parent@example.com"));
        assert_eq!(h.references, vec!["g1@example.com", "parent@example.com"]);
    }

    #[test]
    fn missing_headers_yield_empty() {
        let raw = b"From: a@b\r\n\r\nbody\r\n";
        let h = extract_threading_headers(raw);
        assert!(h.message_id.is_none());
        assert!(h.in_reply_to.is_none());
        assert!(h.references.is_empty());
    }

    #[test]
    fn unparsable_yields_empty() {
        let h = extract_threading_headers(&[]);
        assert!(h.message_id.is_none());
    }

    #[test]
    fn strips_angle_brackets_and_crlf() {
        let raw = b"From: a@b\r\n\
                    Message-ID: <id\r\n@host>\r\n\
                    \r\n\
                    body\r\n";
        let h = extract_threading_headers(raw);
        // mail_parser may or may not tolerate CRLF inside Message-ID;
        // the test just requires angle brackets are gone and the
        // extracted value does not contain <, >, CR, LF.
        if let Some(mid) = h.message_id {
            assert!(!mid.contains('<') && !mid.contains('>'));
            assert!(!mid.contains('\r') && !mid.contains('\n'));
        }
    }
}
