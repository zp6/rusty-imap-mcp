//! Sprint 4b proptest properties for the html and lookalike modules.
//!
//! Each property runs at 10,000 cases. Combined wall-clock ~6s on CI.
//!
//! All three properties exercise the public `parse_message` entry point
//! because `html::sanitize_html` and `lookalike::classify_domain` are
//! crate-private.

use proptest::prelude::*;
use rimap_content::parse_message;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// html::sanitize_html (reached via parse_message on a text/html part) must
    /// return either Ok or Err — never panic or hang — on arbitrary UTF-8
    /// input. The 8 KiB cap is well below the 1 MiB html size gate, so
    /// every case exercises the full sanitizer + audit pipeline; a larger
    /// cap only multiplies wall-clock without expanding coverage.
    #[test]
    fn parse_message_terminates_on_arbitrary_html(body in ".{0,8192}") {
        let mut raw = Vec::with_capacity(body.len() + 128);
        raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
        raw.extend_from_slice(body.as_bytes());
        let _ = parse_message(&raw);
    }

    /// The sanitized body_html must not contain <script>, <style>,
    /// javascript: or data:text/html schemes after a full parse.
    #[test]
    fn sanitized_body_html_has_no_script_style_or_dangerous_urls(
        body in "[a-zA-Z0-9 <>\"'/=.:-]{0,8192}"
    ) {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
        raw.extend_from_slice(b"<html><body>");
        raw.extend_from_slice(body.as_bytes());
        raw.extend_from_slice(b"</body></html>\r\n");
        if let Ok(content) = parse_message(&raw)
            && let Some(html) = content.untrusted.body_html.as_deref()
        {
            let lower = html.to_ascii_lowercase();
            prop_assert!(!lower.contains("<script"));
            prop_assert!(!lower.contains("<style"));
            prop_assert!(!lower.contains("javascript:"));
            prop_assert!(!lower.contains("data:text/html"));
        }
    }

    /// classify_domain (reached via lookalike::audit through parse_message)
    /// must not panic on arbitrary printable Unicode header-from strings.
    #[test]
    fn parse_message_terminates_on_arbitrary_from_header(dom in "\\PC{1,253}") {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"From: user@");
        raw.extend_from_slice(dom.as_bytes());
        raw.extend_from_slice(
            b"\r\nSubject: test\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        );
        let _ = parse_message(&raw);
    }
}
