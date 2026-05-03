//! Panic-safe wrapper around `mail_parser::MessageParser::parse`.
//!
//! Every `MessageParser::parse` call in `rimap-content` routes through
//! [`safe_parse`] so a panic in upstream parser code becomes a typed
//! [`ParserPanic`] sentinel instead of aborting the process. See
//! `docs/superpowers/specs/2026-05-01-issue-201-mail-parser-panic-design.md`
//! for the threat model and rationale (issue #201).

use std::panic::{AssertUnwindSafe, catch_unwind};

use mail_parser::{Message, MessageParser};
use sha2::{Digest, Sha256};

/// Sentinel returned when `mail-parser` panics on the input. Distinct
/// from `Option::None`, which means the parser cleanly rejected the
/// bytes. The two `Result`-returning callers map this to
/// `ContentError::ParserPanic`; the two infallible-shaped callers
/// collapse it into their existing default/None fallback.
#[derive(Debug)]
pub(crate) struct ParserPanic;

/// Run `MessageParser::default().parse(raw)` inside `catch_unwind`.
///
/// On a caught panic, emit a structured `tracing::error!` carrying the
/// input length and the first 16 hex chars of `sha256(raw)` (never the
/// raw bytes), then return `Err(ParserPanic)`. On normal return, pass
/// through the parser's own `Option<Message<'_>>` as `Ok(_)`.
///
/// `AssertUnwindSafe` is justified: on a caught panic the parser and
/// any partial `Message` are dropped immediately and never observed by
/// our code, so logical-invariant violations the parser may have left
/// behind cannot leak across the boundary.
pub(crate) fn safe_parse(raw: &[u8]) -> Result<Option<Message<'_>>, ParserPanic> {
    let outcome = catch_unwind(AssertUnwindSafe(|| MessageParser::default().parse(raw)));
    if let Ok(parsed) = outcome {
        Ok(parsed)
    } else {
        // Deliberately ignore the panic payload — we never want to
        // format attacker-controlled debug strings into logs.
        log_parser_panic(raw);
        Err(ParserPanic)
    }
}

/// Emit the structured panic record. Factored out so unit tests can
/// exercise the hash-and-log path independently of `mail_parser`.
fn log_parser_panic(raw: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(raw);
    let digest = hasher.finalize();
    // 16 hex chars = 8 bytes of sha256, enough for audit-log correlation
    // without giving an attacker a usable length-extension primitive.
    let hash_prefix = hex::encode(&digest[..8]);
    tracing::error!(
        target: "rimap_content::parser_panic",
        input_len = raw.len(),
        input_sha256_prefix = %hash_prefix,
        "mail-parser panicked on input"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test asserts Ok path; panic on Err is the desired failure mode"
    )]
    fn safe_parse_passes_through_clean_input() {
        // mail_parser accepts a minimal RFC 5322 message; safe_parse
        // must return Ok(Some(_)) on the happy path.
        let raw = b"From: a@example\r\nSubject: hi\r\n\r\nbody";
        let parsed = safe_parse(raw).expect("safe_parse must not Err on valid input");
        assert!(parsed.is_some(), "expected Some(Message) for valid input");
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "test exercises the catch_unwind error arm with a synthetic panic"
    )]
    fn catch_unwind_error_arm_produces_parser_panic() {
        // We cannot synthesize a panic from inside mail_parser without
        // hitting the actual upstream bug, so we exercise the error-arm
        // logic by mirroring what safe_parse does: catch_unwind on a
        // closure that explicitly panics, then thread the result through
        // the same match. This proves the outer match arms produce
        // ParserPanic and that log_parser_panic does not itself panic.
        let raw = b"any-bytes";
        let outcome: Result<Option<Message<'_>>, _> =
            catch_unwind(AssertUnwindSafe(|| -> Option<Message<'_>> {
                panic!("synthetic panic for test");
            }));
        let result: Result<Option<Message<'_>>, ParserPanic> = if let Ok(parsed) = outcome {
            Ok(parsed)
        } else {
            log_parser_panic(raw);
            Err(ParserPanic)
        };
        assert!(result.is_err(), "synthetic panic must collapse to Err");
    }

    #[test]
    fn log_parser_panic_handles_empty_input() {
        // Boundary: zero-byte input still produces a valid sha256 and
        // does not panic the logger. `Sha256::new()` + finalize on no
        // updates is a well-defined hash of the empty string.
        log_parser_panic(b"");
    }
}
