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
    /// Sanitized HTML view of the message body, when the message
    /// carries a `text/html` part. `None` when no HTML body exists.
    ///
    /// Produced by the `html` module via an allowlist-based ammonia
    /// pipeline with remote content (images, scripts, stylesheets, and
    /// other network-fetching elements) stripped.
    pub body_html: Option<String>,
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
    /// An attachment matched multiple magic-byte signatures (polyglot
    /// file). This frequently indicates a deliberate attempt to bypass
    /// content-type sniffing by encoding one file type as another.
    ParseAttachmentPolyglot,
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
    /// An attachment filename contained path separators, parent
    /// references, reserved Windows names, or other unsafe characters
    /// and was rewritten to a safe form.
    ParseAttachmentFilenameRewritten,
    /// HTML content contained hidden elements (e.g. `display:none`,
    /// `visibility:hidden`, `opacity:0`, off-screen positioning,
    /// zero font size, or background-color-matching text). Hidden
    /// content is stripped from `body_text` but may remain in
    /// `body_html` when the posture allows HTML exposure. Detail format:
    /// `method=<display_none|visibility_hidden|opacity_0|offscreen|zero_font|color_match>`
    /// optionally followed by `,count=N` when summarized.
    HtmlHiddenContentDetected,
    /// An HTML anchor's visible text contained a URL-looking token
    /// whose registrable domain differs from the anchor's `href`
    /// registrable domain. Detail format:
    /// `text_domain=<ascii>,href_domain=<ascii>`.
    HtmlLinkTextHrefMismatch,
    /// One or more `<script>` elements were removed during HTML
    /// sanitization. Detail format: `count=N`.
    HtmlScriptStripped,
    /// One or more `<style>` elements were removed during HTML
    /// sanitization. Detail format: `count=N`.
    HtmlStyleStripped,
    /// One or more `<img>` elements had their `src`/`srcset`
    /// attributes removed during HTML sanitization to prevent
    /// remote tracking-pixel loads. Detail format: `count=N`.
    HtmlRemoteImageStripped,
    /// A domain label contained characters from multiple Unicode
    /// scripts outside the TR39 Highly Restrictive profile. Detail
    /// format: `domain=<punycode>,scripts=<S1+S2>`.
    LookalikeMixedScript,
    /// A domain's TR39 skeleton matched a different domain's
    /// skeleton, indicating a homograph attack, OR bidi-override
    /// characters were stripped from the domain before processing.
    /// Detail format: `domain=<punycode>,skeleton_match=<other_punycode>`
    /// or `domain=<punycode>,reason=bidi_pre_strip`.
    LookalikeHomographDomain,
    /// A domain was processed in punycode form (xn--) and the
    /// Unicode U-label form is reported for informational use.
    /// Detail format: `domain=<punycode>,ulabel=<unicode>`.
    LookalikeIdnPunycode,
    /// A filename's visible extension differs from its extension
    /// after bidi-override stripping, indicating an RLO-bidi
    /// extension spoof. Detail format:
    /// `visible=<after_strip>,declared=<original>`.
    LookalikeFilenameExtensionSpoof,
}

/// Severity classification for [`WarningCode`] variants. Sprint 5
/// posture rules can use this to partition warnings into
/// informational signals vs. adversarial signals without each
/// caller maintaining its own classification table.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    /// Emitted for normal-operation events (e.g. a legitimate
    /// newsletter larger than `MAX_BODY_BYTES`).
    Informational,
    /// Emitted when the pipeline detected and mitigated an attack
    /// signature or a policy violation.
    Adversarial,
}

impl WarningCode {
    /// Classify this warning code by severity.
    ///
    /// The match is deliberately non-wildcarded so adding a new
    /// [`WarningCode`] variant inside this crate forces an explicit
    /// severity decision via compile error. `#[non_exhaustive]` only
    /// requires a wildcard for downstream matches, not for matches
    /// inside the defining crate.
    #[must_use]
    pub fn severity(&self) -> WarningSeverity {
        match self {
            WarningCode::UnicodeZeroWidthStripped
            | WarningCode::UnicodeBidiOverrideStripped
            | WarningCode::UnicodeC0C1Stripped
            | WarningCode::ParseHeaderSmugglingBlocked
            | WarningCode::ParseMimeTypeMismatch
            | WarningCode::ParseAttachmentPolyglot
            | WarningCode::ParseMimeDepthExceeded
            | WarningCode::ParseMimePartCountExceeded
            | WarningCode::ParseHeaderCountExceeded
            | WarningCode::ParseAttachmentFilenameRewritten
            | WarningCode::HtmlHiddenContentDetected
            | WarningCode::HtmlLinkTextHrefMismatch
            | WarningCode::HtmlScriptStripped
            | WarningCode::LookalikeMixedScript
            | WarningCode::LookalikeHomographDomain
            | WarningCode::LookalikeFilenameExtensionSpoof => WarningSeverity::Adversarial,
            WarningCode::ParseBodyTruncated
            | WarningCode::HtmlStyleStripped
            | WarningCode::HtmlRemoteImageStripped
            | WarningCode::LookalikeIdnPunycode => WarningSeverity::Informational,
        }
    }
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
    fn parse_attachment_polyglot_label() {
        let code = WarningCode::ParseAttachmentPolyglot;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"parse_attachment_polyglot\"");
    }

    #[test]
    fn parse_attachment_filename_rewritten_label() {
        let code = WarningCode::ParseAttachmentFilenameRewritten;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"parse_attachment_filename_rewritten\"");
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
    fn severity_classifies_known_variants() {
        // Compile-time exhaustiveness is enforced by the non-wildcarded
        // match in severity(). This test pins a few known mappings.
        assert_eq!(
            WarningCode::ParseBodyTruncated.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::ParseHeaderSmugglingBlocked.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::ParseAttachmentFilenameRewritten.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::ParseAttachmentPolyglot.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlHiddenContentDetected.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlLinkTextHrefMismatch.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlScriptStripped.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlStyleStripped.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::HtmlRemoteImageStripped.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::LookalikeMixedScript.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::LookalikeHomographDomain.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::LookalikeIdnPunycode.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::LookalikeFilenameExtensionSpoof.severity(),
            WarningSeverity::Adversarial
        );
    }

    #[test]
    fn new_warning_variants_serialize_snake_case() {
        let cases = [
            (
                WarningCode::HtmlHiddenContentDetected,
                "html_hidden_content_detected",
            ),
            (
                WarningCode::HtmlLinkTextHrefMismatch,
                "html_link_text_href_mismatch",
            ),
            (WarningCode::HtmlScriptStripped, "html_script_stripped"),
            (WarningCode::HtmlStyleStripped, "html_style_stripped"),
            (
                WarningCode::HtmlRemoteImageStripped,
                "html_remote_image_stripped",
            ),
            (WarningCode::LookalikeMixedScript, "lookalike_mixed_script"),
            (
                WarningCode::LookalikeHomographDomain,
                "lookalike_homograph_domain",
            ),
            (WarningCode::LookalikeIdnPunycode, "lookalike_idn_punycode"),
            (
                WarningCode::LookalikeFilenameExtensionSpoof,
                "lookalike_filename_extension_spoof",
            ),
        ];
        for (code, expected) in cases {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
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
