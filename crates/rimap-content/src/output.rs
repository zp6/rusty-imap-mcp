//! Output types for the rimap-content pipeline.
//!
//! [`Content`] is the single top-level return type produced by
//! [`crate::parse_message`]. Every field is `#[non_exhaustive]` so that
//! Sprint 4b can add HTML- and look-alike-specific variants without
//! breaking downstream callers.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Top-level parsed message payload.
///
/// Consumers read `meta` for trusted structural information (headers,
/// attachment metadata, mailing-list markers), `untrusted` for
/// sanitized text that may still contain attacker-controlled content,
/// and `security_warnings` for the list of pipeline warnings emitted
/// during parsing.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    /// Trusted structural metadata extracted from the message.
    pub meta: ContentMeta,
    /// Sanitized text parts. All strings here have passed the unicode
    /// pipeline; any codepoint-class warnings are recorded in
    /// `security_warnings`.
    pub untrusted: Untrusted,
    /// Ordered list of warnings emitted during parsing. Order is
    /// deterministic within a single `parse_message` call but callers
    /// should not rely on cross-version ordering.
    pub security_warnings: Vec<SecurityWarning>,
}

/// Trusted structural metadata extracted from message headers and
/// MIME structure. Every string field has been routed through the
/// unicode pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentMeta {
    /// Parsed `From:` header, sanitized. `None` if absent.
    pub from: Option<String>,
    /// Parsed `To:` header recipients, sanitized.
    pub to: Vec<String>,
    /// Parsed `Cc:` header recipients, sanitized.
    pub cc: Vec<String>,
    /// Parsed `Subject:` header, sanitized. `None` if absent.
    pub subject: Option<String>,
    /// Parsed `Date:` header as a UTC-normalized `OffsetDateTime`.
    pub date: Option<OffsetDateTime>,
    /// Parsed `Message-ID:` header value (without angle brackets), sanitized.
    pub message_id: Option<String>,
    /// Parsed `In-Reply-To:` header value (without angle brackets), sanitized.
    pub in_reply_to: Option<String>,
    /// Parsed `References:` header values (without angle brackets), sanitized.
    pub references: Vec<String>,
    /// Mailing-list markers if `List-*` headers were present.
    pub mailing_list: Option<MailingListInfo>,
    /// Attachment metadata for every non-inline part.
    pub attachments: Vec<AttachmentMeta>,
    /// Original message size in bytes before any truncation or sanitization.
    pub original_size_bytes: u64,
    /// `true` if the body was truncated because it exceeded
    /// [`crate::parse::MAX_BODY_BYTES`].
    pub body_truncated: bool,
}

/// Mailing-list markers extracted from `List-*` headers.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MailingListInfo {
    /// Value of `List-ID:` if present.
    pub list_id: Option<String>,
    /// Value of `List-Unsubscribe:` if present.
    pub list_unsubscribe: Option<String>,
    /// Value of `List-Post:` if present.
    pub list_post: Option<String>,
}

/// Metadata for a single attachment part. Body bytes are not retained.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Decoded filename if available (from `Content-Disposition` or
    /// `Content-Type` name parameter), sanitized.
    pub filename: Option<String>,
    /// Declared content type (e.g. `"image/png"`), sanitized.
    pub content_type: String,
    /// Size of the attachment body in bytes (post-transfer-decoding).
    pub size_bytes: u64,
    /// Value of `Content-ID:` if present (without angle brackets), sanitized.
    pub content_id: Option<String>,
    /// `true` if the disposition was `inline`.
    pub is_inline: bool,
}

/// Sanitized text payload from the message body.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Untrusted {
    /// The primary `text/plain` body part, post-unicode-sanitization.
    /// Empty if no text/plain part was found.
    pub body_text: String,
    /// Other `text/*` parts (e.g. additional alternatives), each
    /// independently sanitized.
    pub alternate_parts: Vec<String>,
}

/// A single warning emitted by the content pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    /// Classification of the warning.
    pub code: WarningCode,
    /// Short human-readable context (e.g. a counter of stripped
    /// codepoints). `None` when no additional detail is available.
    pub detail: Option<String>,
    /// Logical location in the message (e.g. `"header:subject"`,
    /// `"body:part[2]"`, `"attachment[0]"`). `None` for crate-wide events.
    pub location: Option<String>,
}

/// Classification of pipeline warnings. New variants will be added in
/// Sprint 4b for HTML and look-alike detection — the enum is
/// `#[non_exhaustive]` so matches must include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// Zero-width codepoints were present in input text and stripped.
    UnicodeZeroWidthStripped,
    /// Bidi-override codepoints were present in input text and stripped.
    UnicodeBidiOverrideStripped,
    /// C0 or C1 control codepoints (other than tab and newline) were stripped.
    UnicodeC0C1Stripped,
    /// A header containing a raw CRLF inside an RFC 2047 encoded-word
    /// was dropped before parsing continued.
    ParseHeaderSmugglingBlocked,
    /// An attachment's declared content type did not match the magic
    /// bytes of its body.
    ParseMimeTypeMismatch,
    /// The message body exceeded `MAX_BODY_BYTES` and was truncated.
    ParseBodyTruncated,
    /// MIME nesting depth exceeded `MAX_MIME_DEPTH`. Emitted alongside
    /// a terminal `ContentError::LimitExceeded`.
    ParseMimeDepthExceeded,
    /// MIME part count exceeded `MAX_MIME_PARTS`. Emitted alongside a
    /// terminal `ContentError::LimitExceeded`.
    ParseMimePartCountExceeded,
    /// Header count exceeded `MAX_HEADER_COUNT`. Emitted alongside a
    /// terminal `ContentError::LimitExceeded`.
    ParseHeaderCountExceeded,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn content_default_meta_is_empty() {
        let meta = ContentMeta::default();
        assert!(meta.from.is_none());
        assert!(meta.to.is_empty());
        assert_eq!(meta.original_size_bytes, 0);
        assert!(!meta.body_truncated);
    }

    #[test]
    fn warning_code_serializes_snake_case() {
        let code = WarningCode::UnicodeZeroWidthStripped;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"unicode_zero_width_stripped\"");
    }

    #[test]
    fn warning_code_c0_c1_serialization_label() {
        let code = WarningCode::UnicodeC0C1Stripped;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"unicode_c0_c1_stripped\"");
    }

    #[test]
    fn warning_code_roundtrips_through_json() {
        let original = WarningCode::ParseHeaderSmugglingBlocked;
        let json = serde_json::to_string(&original).unwrap();
        let parsed: WarningCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn security_warning_round_trip() {
        let warning = SecurityWarning {
            code: WarningCode::ParseBodyTruncated,
            detail: Some("original=1048577 truncated=1048576".to_string()),
            location: Some("body:part[0]".to_string()),
        };
        let json = serde_json::to_string(&warning).unwrap();
        let parsed: SecurityWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, warning.code);
        assert_eq!(parsed.detail, warning.detail);
        assert_eq!(parsed.location, warning.location);
    }
}
