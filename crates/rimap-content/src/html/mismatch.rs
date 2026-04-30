//! Anchor-text vs. `href` domain-mismatch detection.

use std::sync::LazyLock;

use scraper::{Html, Selector};

use crate::html::MAX_ANCHOR_TEXT_SCAN;
use crate::html::MAX_MISMATCH_HITS;
use crate::html::hidden::compile_selector;

/// Selector matching anchor elements with an `href` attribute.
pub(super) static SEL_ANCHOR: LazyLock<Selector> = LazyLock::new(|| compile_selector("a[href]"));
/// Selector matching `<img>` elements.
pub(super) static SEL_IMG: LazyLock<Selector> = LazyLock::new(|| compile_selector("img"));

/// Return the largest index `<= index` that lies on a UTF-8 char boundary.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod char_boundary_tests {
    use super::floor_char_boundary;

    #[test]
    fn ascii_index_is_unchanged() {
        let s = "hello world";
        assert_eq!(floor_char_boundary(s, 5), 5);
    }

    #[test]
    fn index_beyond_len_clamps_to_len() {
        let s = "abc";
        assert_eq!(floor_char_boundary(s, 100), 3);
    }

    #[test]
    fn multibyte_at_split_walks_back_to_boundary() {
        // U+4E2D (Chinese "middle") is 3 bytes: e4 b8 ad.
        // A 2-byte string of "中" has bytes [e4, b8, ad]; index 1 and 2
        // land mid-codepoint and must walk back to 0 (the only valid
        // boundary <= 2).
        let s = "中";
        assert_eq!(s.len(), 3);
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 0);
        assert_eq!(floor_char_boundary(s, 2), 0);
        assert_eq!(floor_char_boundary(s, 3), 3);
    }

    #[test]
    fn truncate_at_floor_boundary_does_not_panic() {
        // Reproduces the original bug: truncating mid-codepoint panics.
        // Walking back to the floor boundary makes truncate safe.
        let mut s = String::new();
        for _ in 0..2000 {
            s.push('中'); // 3 bytes per char → 6000 bytes total
        }
        let cap = 4096; // mid-codepoint
        let boundary = floor_char_boundary(&s, cap);
        assert!(boundary <= cap);
        assert!(s.is_char_boundary(boundary));
        s.truncate(boundary); // would panic without the floor walk
    }
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
            let mut text: String = anchor.text().collect::<Vec<&str>>().join(" ");
            if text.len() > MAX_ANCHOR_TEXT_SCAN {
                let boundary = floor_char_boundary(&text, MAX_ANCHOR_TEXT_SCAN);
                text.truncate(boundary);
            }
            let has_url_text = finder
                .links(&text)
                .any(|l| l.kind() == &linkify::LinkKind::Url);
            if has_url_text {
                unparsable_hrefs.push((href.to_string(), text.trim().to_string()));
            }
            continue;
        };
        let mut text: String = anchor.text().collect::<Vec<&str>>().join(" ");
        if text.len() > MAX_ANCHOR_TEXT_SCAN {
            let boundary = floor_char_boundary(&text, MAX_ANCHOR_TEXT_SCAN);
            text.truncate(boundary);
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
    (hits, overflow, unparsable_hrefs)
}
