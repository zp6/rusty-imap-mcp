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

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use ammonia::Builder;
use scraper::{Html, Selector};

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

/// Stable identifier for an element we've decided is hidden. Used by
/// `extract_text` (Task 9) to skip hidden subtrees.
///
/// `scraper` does not give us a stable `ElementRef` across re-parses,
/// so we identify hidden elements by their position in a pre-order
/// walk of the document tree (a `usize` index). This is sufficient for
/// a single processing pass.
pub(crate) type ElementIndex = usize;

/// Categorization of how an element was hidden from a recipient.
///
/// Each variant corresponds to a distinct CSS pattern that effectively
/// removes content from rendering, used by hidden-content detection in
/// [`detect_hidden`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HiddenMethod {
    /// `display: none` — element omitted from layout entirely.
    DisplayNone,
    /// `visibility: hidden` — element occupies space but is invisible.
    VisibilityHidden,
    /// `opacity: 0` — element is fully transparent.
    OpacityZero,
    /// Absolute or fixed positioning placing the element far off-screen.
    OffScreen,
    /// `font-size: 0` — text collapses to zero rendered size.
    ZeroFont,
    /// `color` and `background-color` strings are byte-identical.
    ColorMatch,
}

impl HiddenMethod {
    /// Stable identifier used in `SecurityWarning::detail` strings.
    pub(crate) fn as_detail(self) -> &'static str {
        match self {
            HiddenMethod::DisplayNone => "display_none",
            HiddenMethod::VisibilityHidden => "visibility_hidden",
            HiddenMethod::OpacityZero => "opacity_0",
            HiddenMethod::OffScreen => "offscreen",
            HiddenMethod::ZeroFont => "zero_font",
            HiddenMethod::ColorMatch => "color_match",
        }
    }
}

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
/// Restricts URL schemes to `{http, https, mailto, tel}` and locks
/// `<img>` attributes to `{alt, width, height}`, dropping `src`,
/// `srcset`, and other remote-fetching surfaces. Ammonia's defaults
/// already strip `<script>`, `<style>`, and event handler attributes.
fn build_ammonia_builder() -> Builder<'static> {
    let mut builder = Builder::default();
    let schemes: HashSet<&'static str> = ["http", "https", "mailto", "tel"].into_iter().collect();
    builder.url_schemes(schemes);
    let mut tag_attrs: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attrs.insert("img", ["alt", "width", "height"].into_iter().collect());
    builder.tag_attributes(tag_attrs);
    builder
}

/// Count elements in `document` matching `selector`.
fn count_matching(document: &Html, selector: &Selector) -> usize {
    document.select(selector).count()
}

/// Count `<img>` elements in `document` whose `src` attribute is
/// present and non-empty after trimming.
fn count_img_with_src(document: &Html) -> usize {
    document
        .select(&SEL_IMG)
        .filter(|el| el.value().attr("src").is_some_and(|s| !s.trim().is_empty()))
        .count()
}

/// Parse a single `style="..."` attribute value into lowercased
/// `(property, value)` pairs.
///
/// Very permissive: declarations are split on `;`, then each
/// declaration is split on its first `:`. Empty properties or values
/// are dropped. The intent is "does this style contain X", not full
/// CSS conformance.
fn parse_inline_style(style: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for decl in style.split(';') {
        let Some((prop, val)) = decl.split_once(':') else {
            continue;
        };
        let prop = prop.trim().to_ascii_lowercase();
        let val = val.trim().to_ascii_lowercase();
        if prop.is_empty() || val.is_empty() {
            continue;
        }
        pairs.push((prop, val));
    }
    pairs
}

/// Parse a CSS length like `-9999px` into a pixel count.
///
/// Returns `None` for non-pixel units (em, rem, %, etc.) — they are
/// treated as non-offscreen by design (inline-style-only scope).
fn parse_px(val: &str) -> Option<f64> {
    let stripped = val.strip_suffix("px").unwrap_or(val);
    stripped.trim().parse::<f64>().ok()
}

/// Return `true` when an `opacity` value parses to (approximately) zero.
fn opacity_is_zero(val: &str) -> bool {
    let stripped = val.trim_end_matches('%').trim();
    stripped
        .parse::<f64>()
        .ok()
        .is_some_and(|n| n <= f64::EPSILON)
}

/// Return `true` when a `font-size` value parses to (approximately) zero.
fn font_size_is_zero(val: &str) -> bool {
    let digits: String = val
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits
        .parse::<f64>()
        .ok()
        .is_some_and(|n| n <= f64::EPSILON)
}

/// Accumulator for off-screen / color-match detection across an inline
/// style declaration list.
#[derive(Default)]
struct StyleHints {
    position: Option<String>,
    left_px: Option<f64>,
    top_px: Option<f64>,
    color: Option<String>,
    bg_color: Option<String>,
}

impl StyleHints {
    fn record(&mut self, prop: &str, val: &str) {
        match prop {
            "position" => self.position = Some(val.to_string()),
            "left" => self.left_px = parse_px(val),
            "top" => self.top_px = parse_px(val),
            "color" => self.color = Some(val.to_string()),
            "background-color" => self.bg_color = Some(val.to_string()),
            _ => {}
        }
    }

    fn is_offscreen(&self) -> bool {
        let positioned = matches!(self.position.as_deref(), Some("absolute" | "fixed"));
        if !positioned {
            return false;
        }
        let off_left = self.left_px.is_some_and(|v| v <= -1000.0);
        let off_top = self.top_px.is_some_and(|v| v <= -1000.0);
        off_left || off_top
    }

    fn is_color_match(&self) -> bool {
        matches!(
            (self.color.as_ref(), self.bg_color.as_ref()),
            (Some(c), Some(bg)) if c == bg
        )
    }
}

/// Check a single declaration for an immediate hidden-method match.
///
/// Returns `Some` only for self-contained patterns (display, visibility,
/// opacity, font-size). Multi-property patterns (off-screen, color
/// match) accumulate via [`StyleHints`] and are resolved by the caller.
fn classify_single_declaration(prop: &str, val: &str) -> Option<HiddenMethod> {
    match prop {
        "display" if val == "none" => Some(HiddenMethod::DisplayNone),
        "visibility" if val == "hidden" => Some(HiddenMethod::VisibilityHidden),
        "opacity" if opacity_is_zero(val) => Some(HiddenMethod::OpacityZero),
        "font-size" if font_size_is_zero(val) => Some(HiddenMethod::ZeroFont),
        _ => None,
    }
}

/// Classify an inline `style` string into a [`HiddenMethod`], if any.
fn classify_inline_style(style: &str) -> Option<HiddenMethod> {
    let pairs = parse_inline_style(style);
    let mut hints = StyleHints::default();
    for (prop, val) in &pairs {
        if let Some(method) = classify_single_declaration(prop, val) {
            return Some(method);
        }
        hints.record(prop, val);
    }
    if hints.is_offscreen() {
        return Some(HiddenMethod::OffScreen);
    }
    if hints.is_color_match() {
        return Some(HiddenMethod::ColorMatch);
    }
    None
}

/// Extract the registrable domain from a URL-looking string.
///
/// Returns `None` for empty input, relative URLs, `mailto:`/`tel:`/
/// `javascript:`/`data:` schemes, single-label hosts, and any input the
/// PSL parser cannot resolve to a registrable domain.
fn extract_registrable_domain(url_or_host: &str) -> Option<String> {
    let trimmed = url_or_host.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("mailto:")
        || lowered.starts_with("tel:")
        || lowered.starts_with("javascript:")
        || lowered.starts_with("data:")
    {
        return None;
    }
    let after_scheme = lowered
        .split_once("://")
        .map_or(lowered.as_str(), |(_, rest)| rest);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches("www.");
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    let ascii = idna::domain_to_ascii(host).ok()?;
    let domain = addr::parse_domain_name(ascii.as_str()).ok()?;
    Some(domain.root()?.to_string())
}

/// A single href-mismatch hit recorded by [`detect_mismatches`].
#[derive(Debug, Clone)]
struct MismatchHit {
    text_domain: String,
    href_domain: String,
}

/// Walk every `<a href>` and report cases where a URL-looking token in
/// the anchor text resolves to a different registrable domain than the
/// `href` attribute.
///
/// Returns `(hits, overflow)`. `hits` contains at most
/// [`MAX_MISMATCH_HITS`] entries; `overflow` counts additional mismatches
/// past the cap so the caller can emit a summary warning.
fn detect_mismatches(document: &Html) -> (Vec<MismatchHit>, usize) {
    let mut hits = Vec::new();
    let mut overflow: usize = 0;
    let mut finder = linkify::LinkFinder::new();
    finder.url_must_have_scheme(false);
    for anchor in document.select(&SEL_ANCHOR) {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        let Some(href_domain) = extract_registrable_domain(href) else {
            continue;
        };
        let mut text: String = anchor.text().collect::<Vec<&str>>().join(" ");
        if text.len() > MAX_ANCHOR_TEXT_SCAN {
            text.truncate(MAX_ANCHOR_TEXT_SCAN);
        }
        let mut link_iter = finder
            .links(&text)
            .filter(|l| l.kind() == &linkify::LinkKind::Url);
        let Some(link) = link_iter.next() else {
            continue;
        };
        let Some(text_domain) = extract_registrable_domain(link.as_str()) else {
            continue;
        };
        if text_domain.eq_ignore_ascii_case(&href_domain) {
            continue;
        }
        if hits.len() < MAX_MISMATCH_HITS {
            hits.push(MismatchHit {
                text_domain,
                href_domain,
            });
        } else {
            overflow += 1;
        }
    }
    (hits, overflow)
}

/// Walk the document and collect hidden-element hits plus their
/// tree-order indices (so text extraction can skip them later).
///
/// Returns `(hits, overflow)`. `hits` contains at most
/// [`MAX_HIDDEN_HITS`] entries; `overflow` is the count of additional
/// hidden elements detected past the cap so the caller can emit a
/// summary warning.
fn detect_hidden(document: &Html) -> (Vec<(ElementIndex, HiddenMethod)>, usize) {
    let mut hits = Vec::new();
    let mut overflow: usize = 0;
    for (idx, element) in document.select(&SEL_BODY_ALL).enumerate() {
        let Some(style) = element.value().attr("style") else {
            continue;
        };
        let Some(method) = classify_inline_style(style) else {
            continue;
        };
        if hits.len() < MAX_HIDDEN_HITS {
            hits.push((idx, method));
        } else {
            overflow += 1;
        }
    }
    (hits, overflow)
}

/// Extract plain text from the document, skipping hidden elements
/// and non-content tags (`<script>`, `<style>`, `<noscript>`,
/// `<template>`, `<head>`, `<title>`).
///
/// `hidden_indices` is the set of element indices produced by
/// [`detect_hidden`]; it is consulted during a pre-order recursion
/// over `<body>`'s descendants. The recursion increments a shared
/// counter once per element child encountered, matching the
/// enumeration order of `select(&SEL_BODY_ALL)` so the two index
/// spaces stay aligned.
///
/// The collected buffer is whitespace-normalized via
/// [`normalize_whitespace`] and then routed through
/// [`crate::unicode::sanitize`] to share the unicode pipeline used by
/// the rest of `rimap-content`. Any warnings produced by the
/// sanitizer are returned alongside the text so the caller can merge
/// them into the [`HtmlResult`] warnings list.
fn extract_text(
    document: &Html,
    hidden_indices: &HashSet<ElementIndex>,
) -> (String, Vec<SecurityWarning>) {
    let mut buf = String::new();
    let body_selector = compile_selector("body");
    if let Some(body_el) = document.select(&body_selector).next() {
        let mut counter: usize = 0;
        for child in body_el.children() {
            if let Some(child_el) = scraper::ElementRef::wrap(child) {
                walk_element(child_el, hidden_indices, &mut buf, &mut counter);
            } else if let Some(text) = child.value().as_text() {
                push_text(&mut buf, text);
            }
        }
    }
    let normalized = normalize_whitespace(&buf);
    crate::unicode::sanitize(
        normalized.as_bytes(),
        Some("utf-8"),
        MAX_HTML_BYTES,
        "body:html",
    )
}

/// Recursive helper for [`extract_text`].
///
/// Visits `el` (already counted by the caller against
/// `hidden_indices`), short-circuiting on non-content tags, then
/// walks its children: element children recurse via this function,
/// text children are appended to `out`. Each element child increments
/// `counter` exactly once before its hidden-skip check, mirroring the
/// pre-order enumeration in [`detect_hidden`].
fn collect_visible_text(
    el: scraper::ElementRef<'_>,
    hidden_indices: &HashSet<ElementIndex>,
    out: &mut String,
    counter: &mut usize,
) {
    let tag = el.value().name();
    if matches!(
        tag,
        "script" | "style" | "noscript" | "template" | "head" | "title"
    ) {
        return;
    }
    for child in el.children() {
        if let Some(child_el) = scraper::ElementRef::wrap(child) {
            walk_element(child_el, hidden_indices, out, counter);
        } else if let Some(text) = child.value().as_text() {
            push_text(out, text);
        }
    }
}

/// Increment the counter for `child_el`, skip if hidden, otherwise
/// recurse via [`collect_visible_text`]. Extracted so the body-root
/// loop and the recursive walker share identical counting semantics.
fn walk_element(
    child_el: scraper::ElementRef<'_>,
    hidden_indices: &HashSet<ElementIndex>,
    out: &mut String,
    counter: &mut usize,
) {
    let my_idx = *counter;
    *counter += 1;
    if hidden_indices.contains(&my_idx) {
        return;
    }
    collect_visible_text(child_el, hidden_indices, out, counter);
}

/// Append a text node's contents to `out`, inserting a separating
/// space when the buffer is non-empty and does not already end in
/// whitespace. Internal whitespace is left intact for
/// [`normalize_whitespace`] to collapse.
fn push_text(out: &mut String, text: &str) {
    if !out.is_empty() && !out.ends_with(char::is_whitespace) {
        out.push(' ');
    }
    out.push_str(text);
}

/// Collapse runs of ASCII/Unicode whitespace in `s` to single spaces
/// and trim leading/trailing whitespace.
fn normalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    let trimmed = out.trim_end();
    trimmed.to_string()
}

/// Process a raw HTML body into sanitized text + html + warnings.
///
/// # Arguments
///
/// * `raw` - Raw HTML body bytes as received from the MIME part.
/// * `charset` - Optional charset label from the MIME `Content-Type`
///   header (e.g. `Some("iso-8859-1")`). When `None`, `unicode::decode`
///   falls back to `encoding_rs` auto-detection (UTF-8 with BOM sniffing
///   then Windows-1252). Invalid bytes are replaced with U+FFFD.
///
/// # Errors
///
/// Returns [`ContentError::LimitExceeded`] if `raw` exceeds
/// [`MAX_HTML_BYTES`].
pub(crate) fn process(raw: &[u8], charset: Option<&str>) -> Result<HtmlResult, ContentError> {
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
    let decoded = crate::unicode::decode(raw, charset);
    let document = Html::parse_document(&decoded);
    let (hidden_hits, hidden_overflow) = detect_hidden(&document);
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    for (_idx, method) in &hidden_hits {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlHiddenContentStripped,
            detail: Some(format!("method={}", method.as_detail())),
            location: Some("body:html".to_string()),
        });
    }
    if hidden_overflow > 0 {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlHiddenContentStripped,
            detail: Some(format!("method=mixed,additional_hits={hidden_overflow}")),
            location: Some("body:html".to_string()),
        });
    }
    let (mismatches, mismatch_overflow) = detect_mismatches(&document);
    for hit in &mismatches {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlLinkTextHrefMismatch,
            detail: Some(format!(
                "text_domain={},href_domain={}",
                hit.text_domain, hit.href_domain
            )),
            location: Some("html:anchor".to_string()),
        });
    }
    if mismatch_overflow > 0 {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlLinkTextHrefMismatch,
            detail: Some(format!("additional_hits={mismatch_overflow}")),
            location: Some("html:anchor".to_string()),
        });
    }
    let hidden_indices: HashSet<ElementIndex> = hidden_hits.iter().map(|(idx, _)| *idx).collect();
    let (body_text, mut text_warnings) = extract_text(&document, &hidden_indices);
    warnings.append(&mut text_warnings);
    let body_html = sanitize_body(&document, &decoded, &mut warnings);
    // anchor_hrefs filled in Task 11.
    Ok(HtmlResult {
        body_text,
        body_html,
        anchor_hrefs: Vec::new(),
        warnings,
    })
}

/// Stage 7: count pre-sanitize remote-content elements on the
/// scraper-parsed `document`, run `ammonia::clean` on `decoded`, and
/// emit `HtmlScriptStripped` / `HtmlStyleStripped` /
/// `HtmlRemoteImageStripped` warnings when the pre-sanitize count is
/// non-zero. Returns the sanitized HTML string.
///
/// The counting deliberately runs against the same `Html` value used
/// by all earlier detection stages (html5ever 0.39 via scraper), not
/// against ammonia's internal parse (html5ever 0.35). This means a
/// crafted divergence between the two tokenizers is observable as a
/// warning-count vs. `body_html` mismatch — see the Task 17 corpus.
fn sanitize_body(document: &Html, decoded: &str, warnings: &mut Vec<SecurityWarning>) -> String {
    let script_count = count_matching(document, &SEL_SCRIPT);
    let style_count = count_matching(document, &SEL_STYLE);
    let remote_img_count = count_img_with_src(document);
    let body_html = AMMONIA_BUILDER.clean(decoded).to_string();
    if script_count > 0 {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlScriptStripped,
            detail: Some(format!("count={script_count}")),
            location: Some("body:html".to_string()),
        });
    }
    if style_count > 0 {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlStyleStripped,
            detail: Some(format!("count={style_count}")),
            location: Some("body:html".to_string()),
        });
    }
    if remote_img_count > 0 {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlRemoteImageStripped,
            detail: Some(format!("count={remote_img_count}")),
            location: Some("body:html".to_string()),
        });
    }
    body_html
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn process_oversize_input_returns_limit_exceeded() {
        let huge = vec![b'<'; MAX_HTML_BYTES + 1];
        let err = process(&huge, None).expect_err("oversize input must error");
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
        let result = process(b"", None).expect("empty input is valid");
        assert!(result.body_text.is_empty());
        // ammonia returns an empty string for empty input.
        assert!(result.body_html.is_empty());
        assert!(result.anchor_hrefs.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn process_minimal_html_document_parses_without_panic() {
        let html = b"<!DOCTYPE html><html><head><title>Hi</title></head>\
            <body><p>hello</p></body></html>";
        let result = process(html, Some("utf-8")).expect("valid html parses");
        assert_eq!(result.body_text, "hello");
        assert!(result.body_html.contains("<p>hello</p>"));
        assert!(result.anchor_hrefs.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn process_unclosed_tags_does_not_error() {
        // scraper/html5ever recovers from malformed input rather than
        // erroring; verify the pipeline tolerates it.
        let html = b"<html><body><p>oops<div><span>still here";
        let result = process(html, None).expect("malformed html still parses");
        assert!(result.body_text.contains("oops"));
        assert!(result.body_text.contains("still here"));
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
    fn classify_display_none() {
        assert_eq!(
            classify_inline_style("display: none"),
            Some(HiddenMethod::DisplayNone)
        );
        assert_eq!(
            classify_inline_style("DISPLAY:NONE;color:red"),
            Some(HiddenMethod::DisplayNone)
        );
    }

    #[test]
    fn classify_visibility_hidden() {
        assert_eq!(
            classify_inline_style("visibility: hidden"),
            Some(HiddenMethod::VisibilityHidden)
        );
    }

    #[test]
    fn classify_opacity_zero() {
        assert_eq!(
            classify_inline_style("opacity: 0"),
            Some(HiddenMethod::OpacityZero)
        );
        assert_eq!(
            classify_inline_style("opacity: 0.0"),
            Some(HiddenMethod::OpacityZero)
        );
    }

    #[test]
    fn classify_font_size_zero() {
        assert_eq!(
            classify_inline_style("font-size: 0"),
            Some(HiddenMethod::ZeroFont)
        );
        assert_eq!(
            classify_inline_style("font-size: 0px"),
            Some(HiddenMethod::ZeroFont)
        );
    }

    #[test]
    fn classify_offscreen_absolute() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -9999px"),
            Some(HiddenMethod::OffScreen)
        );
        assert_eq!(
            classify_inline_style("position: fixed; top: -5000px"),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_color_match() {
        assert_eq!(
            classify_inline_style("color: #ffffff; background-color: #ffffff"),
            Some(HiddenMethod::ColorMatch)
        );
        assert_eq!(
            classify_inline_style("color: white; background-color: white"),
            Some(HiddenMethod::ColorMatch)
        );
    }

    #[test]
    fn classify_visible_styles_return_none() {
        assert_eq!(classify_inline_style("color: red"), None);
        assert_eq!(classify_inline_style("font-weight: bold"), None);
        assert_eq!(
            classify_inline_style("position: absolute; left: 10px"),
            None
        );
        assert_eq!(classify_inline_style("opacity: 0.5"), None);
    }

    #[test]
    fn process_detects_display_none_in_body() {
        let input = br#"<html><body>
            <p>visible</p>
            <div style="display: none">HIDDEN SECRET</div>
        </body></html>"#;
        let result = process(input, None).expect("process should succeed");
        let hit = result
            .warnings
            .iter()
            .find(|w| {
                matches!(
                    w.code,
                    crate::output::WarningCode::HtmlHiddenContentStripped
                )
            })
            .expect("expected HtmlHiddenContentStripped warning");
        assert_eq!(hit.detail.as_deref(), Some("method=display_none"));
        assert_eq!(hit.location.as_deref(), Some("body:html"));
    }

    #[test]
    fn process_hidden_hit_cap_summarizes_overflow() {
        use std::fmt::Write as _;
        let mut body = String::from("<html><body>");
        for i in 0..(MAX_HIDDEN_HITS + 5) {
            write!(body, r#"<span style="display: none">hidden {i}</span>"#)
                .expect("write to String never fails");
        }
        body.push_str("</body></html>");
        let result = process(body.as_bytes(), None).expect("process should succeed");
        let hidden_warnings: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w.code,
                    crate::output::WarningCode::HtmlHiddenContentStripped
                )
            })
            .collect();
        assert_eq!(hidden_warnings.len(), MAX_HIDDEN_HITS + 1);
        let overflow = hidden_warnings
            .last()
            .expect("at least one warning")
            .detail
            .as_deref()
            .expect("overflow warning has detail");
        assert!(overflow.contains("additional_hits=5"), "got {overflow}");
        assert!(overflow.contains("method=mixed"), "got {overflow}");
    }

    #[test]
    fn mismatch_fires_for_different_domains() {
        let input = br#"<html><body>
            <a href="https://attacker.example/login">Visit bank.example.com now</a>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        let mismatch = result
            .warnings
            .iter()
            .find(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch))
            .expect("expected mismatch warning");
        let detail = mismatch.detail.as_deref().expect("detail present");
        // Detail records the registrable (PSL root), so `bank.example.com`
        // collapses to `example.com` here. The plan-text spec asserted the
        // raw subdomain, but that contradicts the matching-subdomain test
        // and the documented behavior of `extract_registrable_domain`.
        assert!(detail.contains("text_domain=example.com"), "got {detail}");
        assert!(
            detail.contains("href_domain=attacker.example"),
            "got {detail}"
        );
        assert_eq!(mismatch.location.as_deref(), Some("html:anchor"));
    }

    #[test]
    fn mismatch_does_not_fire_for_matching_subdomain() {
        let input = br#"<html><body>
            <a href="https://bank.example.com/auth">Go to login.bank.example.com</a>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch)),
            "should not fire for matching registrable domain: {:?}",
            result.warnings
        );
    }

    #[test]
    fn mismatch_does_not_fire_for_click_here_text() {
        let input = br#"<html><body>
            <a href="https://attacker.example">click here</a>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch)),
            "should not fire when anchor text has no URL token"
        );
    }

    #[test]
    fn mismatch_skips_mailto_and_relative_hrefs() {
        let input = br#"<html><body>
            <a href="mailto:foo@example.com">visit example.com</a>
            <a href="/relative/path">relative.example</a>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch))
        );
    }

    #[test]
    fn extract_text_returns_visible_body_text() {
        let input = br#"<html>
            <head><title>should be skipped</title></head>
            <body>
                <p>visible paragraph</p>
                <script>alert(1)</script>
                <style>.x{color:red}</style>
                <div style="display:none">hidden secret</div>
                <p>second paragraph</p>
            </body>
        </html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            result.body_text.contains("visible paragraph"),
            "got {:?}",
            result.body_text
        );
        assert!(
            result.body_text.contains("second paragraph"),
            "got {:?}",
            result.body_text
        );
        assert!(!result.body_text.contains("alert(1)"));
        assert!(!result.body_text.contains("should be skipped"));
        assert!(
            !result.body_text.contains("hidden secret"),
            "hidden leaked: {:?}",
            result.body_text
        );
        assert!(!result.body_text.contains(".x{color:red}"));
    }

    #[test]
    fn extract_text_normalizes_whitespace() {
        let input = b"<html><body><p>hello    world</p>   <p>line\t\ttwo</p></body></html>";
        let result = process(input, None).expect("ok");
        assert!(!result.body_text.contains("    "));
        assert!(!result.body_text.contains("\t\t"));
        assert!(result.body_text.contains("hello world"));
        assert!(result.body_text.contains("line two"));
    }

    #[test]
    fn extract_text_empty_body_returns_empty_string() {
        let input = b"<html><head><title>t</title></head><body></body></html>";
        let result = process(input, None).expect("ok");
        assert!(result.body_text.is_empty(), "got {:?}", result.body_text);
    }

    #[test]
    fn extract_text_index_alignment_skips_only_hidden_elements() {
        // Three sibling spans, the middle one hidden via display:none.
        // Visible siblings on either side must survive; the hidden one
        // and its text must not. This pins the index alignment between
        // detect_hidden's SEL_BODY_ALL enumeration and extract_text's
        // pre-order recursion.
        let input = br#"<html><body>
            <span>alpha</span>
            <span style="display:none">SECRET</span>
            <span>omega</span>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            result.body_text.contains("alpha"),
            "got {:?}",
            result.body_text
        );
        assert!(
            result.body_text.contains("omega"),
            "got {:?}",
            result.body_text
        );
        assert!(
            !result.body_text.contains("SECRET"),
            "hidden text leaked, alignment broken: {:?}",
            result.body_text
        );
    }

    #[test]
    fn extract_text_index_alignment_handles_nested_hidden() {
        // Hidden element with a visible-text descendant: the entire
        // hidden subtree must be omitted. A later visible sibling at a
        // larger index confirms the counter advanced past the skipped
        // descendants in lock-step with detect_hidden.
        let input = br#"<html><body>
            <p>before</p>
            <div style="display:none"><span>nested hidden</span><em>still hidden</em></div>
            <p>after</p>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(result.body_text.contains("before"));
        assert!(result.body_text.contains("after"));
        assert!(!result.body_text.contains("nested hidden"));
        assert!(!result.body_text.contains("still hidden"));
    }

    #[test]
    fn sanitize_produces_body_html_with_safe_tags() {
        let input = b"<html><body><p>hello <strong>world</strong></p></body></html>";
        let result = process(input, None).expect("ok");
        assert!(result.body_html.contains("<p>"));
        assert!(result.body_html.contains("<strong>"));
        assert!(result.body_html.contains("hello"));
    }

    #[test]
    fn sanitize_strips_script_and_warns() {
        let input = br"<html><body><p>ok</p><script>evil()</script></body></html>";
        let result = process(input, None).expect("ok");
        assert!(!result.body_html.contains("<script"));
        assert!(!result.body_html.contains("evil()"));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlScriptStripped))
        );
    }

    #[test]
    fn sanitize_strips_style_and_warns() {
        let input = br"<html><body><style>.x{color:red}</style><p>ok</p></body></html>";
        let result = process(input, None).expect("ok");
        assert!(!result.body_html.contains("<style"));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlStyleStripped))
        );
    }

    #[test]
    fn sanitize_strips_img_src_preserves_alt_and_warns() {
        let input = br#"<html><body>
            <img src="https://tracker.example/px.gif" alt="invoice attached" width="1" height="1">
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(!result.body_html.contains("tracker.example"));
        assert!(!result.body_html.contains("src="));
        assert!(result.body_html.contains("alt=\"invoice attached\""));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlRemoteImageStripped))
        );
    }

    #[test]
    fn sanitize_drops_javascript_url_from_anchor() {
        let input = br#"<html><body><a href="javascript:alert(1)">click</a></body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(!result.body_html.contains("javascript:"));
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
