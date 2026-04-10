//! Proptest property: arbitrary charset parameter strings passed to
//! `parse_message` always produce either a valid `Content` with UTF-8
//! `body_text` or a structured `ContentError` — never a panic.
//!
//! Runs at 10,000 cases.

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

    #[test]
    fn charset_parameter_produces_valid_utf8_or_error(
        charset in "[a-zA-Z0-9_:. -]{0,40}"
    ) {
        let eml = format!(
            "From: test@example.com\r\n\
             Subject: charset test\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=\"{charset}\"\r\n\
             \r\n\
             Hello world\r\n"
        );
        if let Ok(content) = parse_message(eml.as_bytes()) {
            // body_text must be valid UTF-8 (it's a String, so
            // this is guaranteed by construction, but we verify
            // the content is non-panicking and reasonable).
            let _ = content.untrusted.body_text.len();
        }
        // Structured error is also acceptable.
    }
}
