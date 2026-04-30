//! Anchor-text vs. `href` domain-mismatch detection.

use std::sync::LazyLock;

use scraper::{Html, Selector};

use crate::html::MAX_ANCHOR_TEXT_SCAN;
use crate::html::MAX_MISMATCH_HITS;
use crate::html::hidden::compile_selector;
use crate::unicode::truncate_graphemes;

/// Selector matching anchor elements with an `href` attribute.
pub(super) static SEL_ANCHOR: LazyLock<Selector> = LazyLock::new(|| compile_selector("a[href]"));
/// Selector matching `<img>` elements.
pub(super) static SEL_IMG: LazyLock<Selector> = LazyLock::new(|| compile_selector("img"));

/// Collect an anchor's text into a single space-joined string and cap
/// it at [`MAX_ANCHOR_TEXT_SCAN`] bytes on a grapheme-cluster boundary.
///
/// The cap exists because the linkify URL scan downstream is O(n) over
/// the input length, and the cap protects against denial-of-service
/// from anchors with megabyte-scale text. The grapheme-cluster boundary
/// guarantees the truncation never lands inside a multi-byte UTF-8
/// sequence (which would panic `String::truncate`).
fn collect_anchor_text(anchor: &scraper::ElementRef<'_>) -> String {
    let text: String = anchor.text().collect::<Vec<&str>>().join(" ");
    truncate_graphemes(&text, MAX_ANCHOR_TEXT_SCAN)
}

/// Extract the registrable domain from a URL-looking string.
///
/// Returns `None` for empty input, relative URLs, `mailto:`/`tel:`/
/// `javascript:`/`data:` schemes, single-label hosts, and any input the
/// PSL parser cannot resolve to a registrable domain.
pub(super) fn extract_registrable_domain(url_or_host: &str) -> Option<String> {
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
pub(super) struct MismatchHit {
    pub(super) text_domain: String,
    pub(super) href_domain: String,
}

/// Count elements in `document` matching `selector`.
pub(super) fn count_matching(document: &Html, selector: &Selector) -> usize {
    document.select(selector).count()
}

/// Count `<img>` elements in `document` whose `src` attribute is
/// present and non-empty after trimming.
pub(super) fn count_img_with_src(document: &Html) -> usize {
    document
        .select(&SEL_IMG)
        .filter(|el| el.value().attr("src").is_some_and(|s| !s.trim().is_empty()))
        .count()
}

/// Walk every `<a href>` and report cases where a URL-looking token in
/// the anchor text resolves to a different registrable domain than the
/// `href` attribute.
///
/// Returns `(hits, overflow, unparsable_hrefs)`. `hits` contains at most
/// [`MAX_MISMATCH_HITS`] entries; `overflow` counts additional mismatches
/// past the cap so the caller can emit a summary warning.
pub(super) fn detect_mismatches(
    document: &Html,
) -> (Vec<MismatchHit>, usize, Vec<(String, String)>) {
    let mut hits = Vec::new();
    let mut overflow: usize = 0;
    let mut unparsable_hrefs: Vec<(String, String)> = Vec::new();
    let mut finder = linkify::LinkFinder::new();
    finder.url_must_have_scheme(false);
    for anchor in document.select(&SEL_ANCHOR) {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        let Some(href_domain) = extract_registrable_domain(href) else {
            let text = collect_anchor_text(&anchor);
            let has_url_text = finder
                .links(&text)
                .any(|l| l.kind() == &linkify::LinkKind::Url);
            if has_url_text {
                unparsable_hrefs.push((href.to_string(), text.trim().to_string()));
            }
            continue;
        };
        let text = collect_anchor_text(&anchor);
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
    (hits, overflow, unparsable_hrefs)
}
