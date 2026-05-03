//! Regression test for issue #201: a fuzzer-discovered input that
//! panics inside `mail-parser-0.11.2` must not propagate out of
//! `rimap-content`. Each public entry point is exercised independently.
//!
//! The fixture bytes live in `tests/data/mail_parser_panic_201.eml`.
//! Their sha1 matches the libfuzzer-assigned filename
//! `crash-3dfef11827edd59b81f1ccc37ac16da62158472b` from workflow run
//! `25235117599` (artifact `crashes-content_mime`, expires 2026-07-30).

use rimap_content::{
    ContentError, extract_message_id, extract_threading_headers, parse_message,
    walk_attachment_parts,
};

const CRASH_INPUT: &[u8] = include_bytes!("data/mail_parser_panic_201.eml");

#[test]
fn parse_message_does_not_panic_on_issue_201_input() {
    // The point of this test is "we don't panic", not "the input is
    // always panic-bait". If upstream patches mail-parser later and we
    // pick up a fix, the input may parse cleanly or be rejected as
    // Malformed. Either is acceptable; only a panic fails the test.
    #[expect(
        clippy::panic,
        reason = "test failure: unexpected ContentError variant"
    )]
    match parse_message(CRASH_INPUT) {
        Ok(_)
        | Err(
            ContentError::ParserPanic
            | ContentError::Malformed { .. }
            | ContentError::LimitExceeded { .. },
        ) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn walk_attachment_parts_does_not_panic_on_issue_201_input() {
    #[expect(
        clippy::panic,
        reason = "test failure: unexpected ContentError variant"
    )]
    match walk_attachment_parts(CRASH_INPUT) {
        Ok(_)
        | Err(
            ContentError::ParserPanic
            | ContentError::Malformed { .. }
            | ContentError::LimitExceeded { .. },
        ) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn extract_threading_headers_does_not_panic_on_issue_201_input() {
    // Returns ThreadingHeaders by value; panic is the only failure mode.
    let _ = extract_threading_headers(CRASH_INPUT);
}

#[test]
fn extract_message_id_does_not_panic_on_issue_201_input() {
    // Returns Option<String>; panic is the only failure mode.
    let _ = extract_message_id(CRASH_INPUT);
}
