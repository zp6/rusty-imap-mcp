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
    // cargo-mutants: known-equivalent — `||` vs `&&` here is observably
    // identical given that `host.is_empty()` implies `!host.contains('.')`.
    // The only case the operators differ on is `is_empty=false &&
    // !contains('.')=true` (a non-empty single-label host); both `||`
    // and `&&` then send control through the idna+addr lookup, which
    // returns `None` for any single-label host (no registrable domain
    // exists above a TLD). `is_empty=true && !contains('.')=false` is
    // unreachable: an empty string contains no `.`.
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
            // cargo-mutants: known-equivalent — `> with >=` here is
            // observably identical. At `text.len() == MAX_ANCHOR_TEXT_SCAN`,
            // `truncate(MAX_ANCHOR_TEXT_SCAN)` is a documented no-op
            // (`String::truncate` does nothing when `new_len >= len`),
            // so the only case the operators differ on produces no
            // mutation in `text`.
            if text.len() > MAX_ANCHOR_TEXT_SCAN {
                text.truncate(MAX_ANCHOR_TEXT_SCAN);
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
        // cargo-mutants: known-equivalent — `> with >=` is observably
        // identical here for the same reason as the unparsable-branch
        // truncation above: `truncate(MAX_ANCHOR_TEXT_SCAN)` is a no-op
        // at `text.len() == MAX_ANCHOR_TEXT_SCAN`.
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
    (hits, overflow, unparsable_hrefs)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod mismatch_tests {
    use scraper::Html;

    use super::{detect_mismatches, extract_registrable_domain};
    use crate::html::{MAX_ANCHOR_TEXT_SCAN, MAX_MISMATCH_HITS};

    #[test]
    fn extract_registrable_domain_rejects_mailto_scheme() {
        // Kills `|| with &&` mutation at line 42 (the `||` joining the
        // mailto: check to the rest of the chain). Under `&&`, only an
        // input that satisfies all four `starts_with` checks
        // simultaneously would early-return — no real input matches
        // every scheme — so a `mailto://example.com` payload falls
        // through and resolves to a registrable domain.
        assert_eq!(
            extract_registrable_domain("mailto://example.com"),
            None,
            "mailto:// must short-circuit even when the URL form has //",
        );
    }

    #[test]
    fn extract_registrable_domain_rejects_tel_scheme() {
        // Kills `|| with &&` mutation at line 43.
        assert_eq!(extract_registrable_domain("tel://example.com"), None);
    }

    #[test]
    fn extract_registrable_domain_rejects_javascript_scheme() {
        // Kills `|| with &&` mutation at line 44.
        assert_eq!(extract_registrable_domain("javascript://example.com"), None,);
    }

    #[test]
    fn extract_registrable_domain_rejects_data_scheme() {
        // The `data:` line itself does not have a `||` mutation, but
        // this anchor pins the scheme list and prevents future drift.
        assert_eq!(extract_registrable_domain("data://example.com"), None);
    }

    /// Build an HTML document with `count` distinct mismatched anchors:
    /// each anchor's href and text resolve to different registrable
    /// domains so each one becomes an entry in `detect_mismatches`'s
    /// hits list.
    fn build_n_mismatched_anchors(count: usize) -> Html {
        let mut body = String::new();
        for i in 0..count {
            // text says `evil-{i}.example`; href points at `actual.com`.
            use std::fmt::Write as _;
            write!(
                body,
                "<a href=\"https://actual.com\">https://evil-{i}.example</a>",
            )
            .unwrap();
        }
        Html::parse_document(&format!("<html><body>{body}</body></html>"))
    }

    /// Build an anchor document whose text is `MAX_ANCHOR_TEXT_SCAN + 1`
    /// padding bytes followed by `https://evil.example` — i.e. the URL
    /// sits past the truncation cap. Used to exercise both
    /// `detect_mismatches` truncation guards (parsable + unparsable href
    /// branches): the original truncates and linkify finds no URL; the
    /// `< with` and `> with ==` mutations skip truncation and linkify
    /// then sees the post-cap URL.
    fn build_anchor_with_url_past_cap(href: &str) -> Html {
        let padding = "x".repeat(MAX_ANCHOR_TEXT_SCAN + 1);
        Html::parse_document(&format!(
            "<html><body><a href=\"{href}\">{padding} https://evil.example</a></body></html>",
        ))
    }

    #[test]
    fn detect_mismatches_truncates_anchor_text_for_parsable_href() {
        // Kills `> with <` and `> with ==` on the parsable-href branch
        // truncation guard.
        let document = build_anchor_with_url_past_cap("https://actual.com");
        let (hits, _overflow, _unparsable) = detect_mismatches(&document);
        assert!(
            hits.is_empty(),
            "URL placed past MAX_ANCHOR_TEXT_SCAN must be truncated away; got {hits:?}",
        );
    }

    #[test]
    fn detect_mismatches_truncates_anchor_text_for_unparsable_href() {
        // Kills `> with <` and `> with ==` on the unparsable-href branch
        // truncation guard. The single-label host fails PSL parsing so
        // control takes the unparsable branch.
        let document = build_anchor_with_url_past_cap("https://noserver/path");
        let (_hits, _overflow, unparsable) = detect_mismatches(&document);
        assert!(
            unparsable.is_empty(),
            "URL placed past MAX_ANCHOR_TEXT_SCAN must be truncated before linkify; got {unparsable:?}",
        );
    }

    #[test]
    fn detect_mismatches_caps_hits_at_max_and_counts_overflow() {
        // Construct MAX+2 distinct mismatches.
        // Original: hits.len()=MAX, overflow=2.
        // Kills `< with <=` (line 128): under `<=`, hits.len()=MAX+1
        //   and overflow=1.
        // Kills `+= with -=` (line 134): underflow on `overflow`
        //   panics in debug; the test fails before assert.
        // Kills `+= with *=` (line 134): overflow stays 0.
        let document = build_n_mismatched_anchors(MAX_MISMATCH_HITS + 2);
        let (hits, overflow, _) = detect_mismatches(&document);
        assert_eq!(
            hits.len(),
            MAX_MISMATCH_HITS,
            "hits cap should fire at MAX_MISMATCH_HITS, got {}",
            hits.len(),
        );
        assert_eq!(overflow, 2, "overflow must count the post-cap mismatches");
    }
}
