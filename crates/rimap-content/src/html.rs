//! HTML processing pipeline for rimap-content.
//!
//! Parses `text/html` bodies via `scraper`, detects hidden-element and
//! anchor/href phishing signals, extracts sanitized plain text, and
//! produces an ammonia-sanitized HTML rendering with remote content
//! stripped. The only consumer of `scraper`, `ammonia`, and `linkify`
//! in the workspace.
//!
//! The single public (crate-visible) entrypoint is [`process`].
//!
//! Until Task 12 wires `process` into `parse::extract_bodies`, the
//! module's items are only exercised by the in-module unit tests, so
//! non-test builds suppress dead-code warnings module-wide.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by parse::extract_bodies in Sprint 4b Task 12"
    )
)]

use std::sync::LazyLock;

use ammonia::Builder;
use scraper::Selector;

use crate::error::ContentError;
use crate::output::SecurityWarning;

/// Result of processing a single HTML body part.
#[derive(Debug, Clone)]
pub(crate) struct HtmlResult {
    /// Plain text extracted from the HTML, already run through
    /// `unicode::sanitize`.
    pub body_text: String,
    /// Ammonia-sanitized HTML (allowlist minus remote content).
    pub body_html: String,
    /// Anchor hrefs surviving sanitization, in document order.
    /// Consumed by `lookalike::audit`.
    pub anchor_hrefs: Vec<String>,
    /// Warnings produced during parse, detection, and sanitization.
    pub warnings: Vec<SecurityWarning>,
}

/// Maximum raw HTML body size. Matches `MAX_BODY_BYTES` from parse.rs.
pub(crate) const MAX_HTML_BYTES: usize = 1024 * 1024;

/// Maximum anchor-text length scanned by `linkify` during href-mismatch
/// detection.
pub(crate) const MAX_ANCHOR_TEXT_SCAN: usize = 4 * 1024;

/// Cap on individual hidden-content hits before summarization.
pub(crate) const MAX_HIDDEN_HITS: usize = 64;

/// Cap on individual href-mismatch hits before summarization.
pub(crate) const MAX_MISMATCH_HITS: usize = 32;

/// `kind` value used for [`ContentError::LimitExceeded`] when the raw
/// HTML body exceeds [`MAX_HTML_BYTES`].
pub(crate) const HTML_BODY_LIMIT_KIND: &str = "html_body";

/// Compile a const CSS selector string. The `expect` is unreachable for
/// const selector inputs and is exercised at first use of each
/// `LazyLock` so the lint expectation is fulfilled.
#[expect(
    clippy::expect_used,
    reason = "const CSS selector strings cannot fail at runtime"
)]
fn compile_selector(src: &'static str) -> Selector {
    Selector::parse(src).expect("rimap-content: invalid const CSS selector")
}

/// Selector matching anchor elements with an `href` attribute.
static SEL_ANCHOR: LazyLock<Selector> = LazyLock::new(|| compile_selector("a[href]"));
/// Selector matching `<img>` elements.
static SEL_IMG: LazyLock<Selector> = LazyLock::new(|| compile_selector("img"));
/// Selector matching `<script>` elements.
static SEL_SCRIPT: LazyLock<Selector> = LazyLock::new(|| compile_selector("script"));
/// Selector matching `<style>` elements.
static SEL_STYLE: LazyLock<Selector> = LazyLock::new(|| compile_selector("style"));
/// Selector matching every descendant of `<body>`, used by hidden-element
/// detection in Task 7.
static SEL_BODY_ALL: LazyLock<Selector> = LazyLock::new(|| compile_selector("body *"));

/// Shared ammonia builder. Configuration lands in Task 10.
static AMMONIA_BUILDER: LazyLock<Builder<'static>> = LazyLock::new(build_ammonia_builder);

/// Build the ammonia `Builder` used for Sprint 4b html sanitization.
///
/// Restricts URL schemes, strips `<img>` remote sources while preserving
/// `alt`/`width`/`height`. See the design spec §4.6 for the rationale.
fn build_ammonia_builder() -> Builder<'static> {
    // Implementation lands in Task 10. Return default for now.
    Builder::default()
}

/// Process a raw HTML body into sanitized text + html + warnings.
///
/// Returns [`ContentError::LimitExceeded`] if `raw` exceeds
/// [`MAX_HTML_BYTES`].
pub(crate) fn process(raw: &[u8]) -> Result<HtmlResult, ContentError> {
    // Warm the LazyLocks so the const selectors and ammonia builder are
    // exercised on first call. This both validates them at runtime and
    // keeps them out of dead-code analysis until later tasks consume them.
    let _ = (
        &*SEL_ANCHOR,
        &*SEL_IMG,
        &*SEL_SCRIPT,
        &*SEL_STYLE,
        &*SEL_BODY_ALL,
        &*AMMONIA_BUILDER,
    );
    if raw.len() > MAX_HTML_BYTES {
        return Err(ContentError::LimitExceeded {
            kind: HTML_BODY_LIMIT_KIND,
            limit: MAX_HTML_BYTES,
        });
    }
    // Stubs filled in Tasks 6–11.
    Ok(HtmlResult {
        body_text: String::new(),
        body_html: String::new(),
        anchor_hrefs: Vec::new(),
        warnings: Vec::new(),
    })
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn process_oversize_input_returns_limit_exceeded() {
        let huge = vec![b'<'; MAX_HTML_BYTES + 1];
        let err = process(&huge).expect_err("oversize input must error");
        match err {
            ContentError::LimitExceeded { kind, limit } => {
                assert_eq!(kind, HTML_BODY_LIMIT_KIND);
                assert_eq!(limit, MAX_HTML_BYTES);
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn process_empty_input_returns_empty_result() {
        let result = process(b"").expect("empty input is valid");
        assert!(result.body_text.is_empty());
        assert!(result.body_html.is_empty());
        assert!(result.anchor_hrefs.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn compile_selector_accepts_valid_const() {
        let _ = compile_selector("a[href]");
    }

    #[test]
    fn constants_are_referenced() {
        // The size, anchor-scan, and hit caps will be consumed by
        // Tasks 7/8/10. Reference them here so test builds don't trip
        // dead-code while the production call sites are still stubs.
        let _ = (
            MAX_HTML_BYTES,
            MAX_ANCHOR_TEXT_SCAN,
            MAX_HIDDEN_HITS,
            MAX_MISMATCH_HITS,
        );
    }

    #[test]
    fn lazylocks_initialize_without_panic() {
        // Touch each LazyLock so the compile_selector expectation is
        // exercised even if the process() warming pattern changes later.
        let _ = &*SEL_ANCHOR;
        let _ = &*SEL_IMG;
        let _ = &*SEL_SCRIPT;
        let _ = &*SEL_STYLE;
        let _ = &*SEL_BODY_ALL;
        let _ = &*AMMONIA_BUILDER;
    }
}
