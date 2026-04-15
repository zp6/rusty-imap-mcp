//! Hidden-element detection by inline-style classification.

use std::sync::LazyLock;

use scraper::{Html, Selector};

use crate::html::ElementIndex;
use crate::html::HiddenMethod;
use crate::html::MAX_HIDDEN_HITS;
use crate::html::style_parse::classify_inline_style;

/// Compile a const CSS selector string. The `expect` is unreachable for
/// const selector inputs and is exercised at first use of each
/// `LazyLock` so the lint expectation is fulfilled.
#[expect(
    clippy::expect_used,
    reason = "const CSS selector strings cannot fail at runtime"
)]
pub(super) fn compile_selector(src: &'static str) -> Selector {
    Selector::parse(src).expect("rimap-content: invalid const CSS selector")
}

/// Selector matching every descendant of `<body>`, used by hidden-element
/// detection.
pub(super) static SEL_BODY_ALL: LazyLock<Selector> = LazyLock::new(|| compile_selector("body *"));

/// Walk the document and collect hidden-element hits plus their
/// tree-order indices (so text extraction can skip them later).
///
/// Returns `(hits, overflow)`. `hits` contains at most
/// [`MAX_HIDDEN_HITS`] entries; `overflow` is the count of additional
/// hidden elements detected past the cap so the caller can emit a
/// summary warning.
pub(super) fn detect_hidden(document: &Html) -> (Vec<(ElementIndex, HiddenMethod)>, usize) {
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
