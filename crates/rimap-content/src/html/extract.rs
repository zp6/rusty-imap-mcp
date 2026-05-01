//! Plain-text extraction from the parsed HTML document, skipping
//! hidden and non-content subtrees.

use std::collections::HashSet;

use scraper::Html;

use crate::html::ElementIndex;
use crate::html::MAX_HTML_BYTES;
use crate::html::hidden::compile_selector;
use crate::html::mismatch::SEL_ANCHOR;
use crate::output::SecurityWarning;

/// HTML tags whose contents are not considered user-visible body text
/// and are therefore skipped during hidden-text extraction. Named slice
/// avoids both `matches!` (banned by project style) and a wildcard
/// match arm against a non-enum `&str` input.
const NON_CONTENT_TAGS: &[&str] = &["script", "style", "noscript", "template", "head", "title"];

/// Extract plain text from the document, skipping hidden elements
/// and non-content tags (`<script>`, `<style>`, `<noscript>`,
/// `<template>`, `<head>`, `<title>`).
///
/// `hidden_indices` is the set of element indices produced by
/// [`crate::html::hidden::detect_hidden`]; it is consulted during a
/// pre-order recursion over `<body>`'s descendants. The recursion
/// increments a shared counter once per element child encountered,
/// matching the enumeration order of `select(&SEL_BODY_ALL)` so the
/// two index spaces stay aligned.
///
/// The collected buffer is whitespace-normalized via
/// [`normalize_whitespace`] and then routed through
/// [`crate::unicode::sanitize`] to share the unicode pipeline used by
/// the rest of `rimap-content`. Any warnings produced by the
/// sanitizer are returned alongside the text so the caller can merge
/// them into the result warnings list.
pub(super) fn extract_text(
    document: &Html,
    hidden_indices: &HashSet<ElementIndex>,
) -> (String, Vec<SecurityWarning>) {
    let mut buf = String::new();
    let body_selector = compile_selector("body");
    if let Some(body_el) = document.select(&body_selector).next() {
        let mut counter: usize = 0;
        walk_children(body_el, hidden_indices, &mut buf, &mut counter);
    }
    let normalized = normalize_whitespace(&buf);
    crate::unicode::sanitize(
        normalized.as_bytes(),
        Some("utf-8"),
        MAX_HTML_BYTES,
        "body:html",
    )
}

/// Walk `children` of an element, recursing into each element child via
/// [`walk_element`] and appending plain text. CDATA comments suppress
/// the next adjacent text node so CDATA marker bookkeeping does not
/// leak into the output. Shared between the body-root loop and the
/// recursive element walker to keep counting semantics identical.
fn walk_children(
    parent: scraper::ElementRef<'_>,
    hidden_indices: &HashSet<ElementIndex>,
    out: &mut String,
    counter: &mut usize,
) {
    let mut after_cdata = false;
    for child in parent.children() {
        if let Some(child_el) = scraper::ElementRef::wrap(child) {
            after_cdata = false;
            walk_element(child_el, hidden_indices, out, counter);
        } else if child
            .value()
            .as_comment()
            .is_some_and(|c| c.starts_with("[CDATA["))
        {
            after_cdata = true;
        } else if let Some(text) = child.value().as_text()
            && !after_cdata
        {
            push_text(out, text);
        }
    }
}

/// Recursive helper for [`extract_text`].
///
/// Visits `el` (already counted by the caller against
/// `hidden_indices`), short-circuiting on non-content tags, then
/// walks its children: element children recurse via this function,
/// text children are appended to `out`. Each element child increments
/// `counter` exactly once before its hidden-skip check, mirroring the
/// pre-order enumeration in [`crate::html::hidden::detect_hidden`].
fn collect_visible_text(
    el: scraper::ElementRef<'_>,
    hidden_indices: &HashSet<ElementIndex>,
    out: &mut String,
    counter: &mut usize,
) {
    let tag = el.value().name();
    if NON_CONTENT_TAGS.contains(&tag) {
        return;
    }
    walk_children(el, hidden_indices, out, counter);
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
///
/// Text nodes containing `]]>` are skipped as a secondary defense
/// against CDATA leaks. html5ever treats `<![CDATA[` in non-SVG/
/// `MathML` context as a bogus comment; content between inner tags
/// and `]]>` leaks as text nodes. The primary defense is the
/// `after_cdata` flag in [`walk_children`], which suppresses text
/// siblings that immediately follow a CDATA bogus-comment node
/// (covering the unclosed-CDATA case where `]]>` is absent).
fn push_text(out: &mut String, text: &str) {
    if text.contains("]]>") {
        return;
    }
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

/// Re-parse the ammonia-sanitized `body_html` and collect every
/// surviving `<a href>` value in document order. Consumed by
/// `lookalike::audit`.
///
/// The re-parse is intentional: ammonia's output is the canonical
/// "what the recipient might click", and we want anchor hrefs that
/// reflect post-sanitization reality (so e.g. `javascript:` URLs
/// stripped by the ammonia allowlist do not appear here).
pub(super) fn collect_anchor_hrefs(sanitized_html: &str) -> Vec<String> {
    let doc = Html::parse_document(sanitized_html);
    doc.select(&SEL_ANCHOR)
        .filter_map(|a| a.value().attr("href").map(str::to_string))
        .collect()
}

#[cfg(test)]
mod extract_tests {
    use super::push_text;

    #[test]
    fn push_text_does_not_prepend_space_at_start() {
        // Kills `&& with ||` on the space-insertion guard. Under `||`,
        // an empty `out` (`!out.is_empty() = false`) combined with a
        // non-whitespace tail (`!out.ends_with(ws) = true`) still
        // triggers the push, producing " hello" instead of "hello".
        let mut out = String::new();
        push_text(&mut out, "hello");
        assert_eq!(out, "hello");
    }

    #[test]
    fn push_text_does_not_double_space_after_existing_whitespace() {
        // Companion to the above. Under `||`, a non-empty `out` ending
        // in space (`!is_empty=true || ends_with_ws=true` short-circuits
        // to true regardless of the second clause) still pushes another
        // space, producing "abc  def" instead of "abc def".
        let mut out = String::from("abc ");
        push_text(&mut out, "def");
        assert_eq!(out, "abc def");
    }
}
