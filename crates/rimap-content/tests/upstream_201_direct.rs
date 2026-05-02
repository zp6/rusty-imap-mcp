//! Direct verification that mail-parser 0.11.3 no longer panics on the
//! issue #201 crash input. Unlike `parser_panic_safety.rs`, this test
//! deliberately bypasses our `safe_parse` `catch_unwind` shim and calls
//! the upstream API directly. If the upstream bug returns, this test
//! aborts the test runner with a panic — exactly what we want as a
//! regression signal.

const CRASH_INPUT: &[u8] = include_bytes!("data/mail_parser_panic_201.eml");

#[test]
fn upstream_mail_parser_does_not_panic_on_issue_201_input() {
    let _ = mail_parser::MessageParser::default().parse(CRASH_INPUT);
}
