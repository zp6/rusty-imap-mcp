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

    /// Install a permissive `Registry` as the global default subscriber on
    /// the first call (#239). Without this, the *first* test thread to fire
    /// the `tracing::error!` macro at `log_parser_panic` registers the
    /// callsite against the still-default `NoSubscriber`, caching
    /// `Interest::never` for the lifetime of the test process. Any later
    /// test that installs a thread-local capture layer via `with_default`
    /// then sees the macro short-circuit before its layer is consulted.
    /// Calling this from every test that fires the macro guarantees the
    /// callsite is registered against a permissive subscriber the first
    /// time, regardless of test ordering.
    fn install_permissive_global_default() {
        use std::sync::OnceLock;
        use tracing_subscriber::registry::Registry;
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            let subscriber = Registry::default();
            let _ = tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber));
        });
    }

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
        install_permissive_global_default();
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
        install_permissive_global_default();
        // Boundary: zero-byte input still produces a valid sha256 and
        // does not panic the logger. `Sha256::new()` + finalize on no
        // updates is a well-defined hash of the empty string.
        log_parser_panic(b"");
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "Mutex::lock() poison-propagation in test-only event-capture layer"
    )]
    fn log_parser_panic_emits_structured_tracing_event() {
        use std::fmt::Write as _;
        use std::sync::{Arc, Mutex};
        use tracing::Subscriber;
        use tracing::field::{Field, Visit};
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::{Context, SubscriberExt};
        use tracing_subscriber::registry::Registry;

        // Kills `replace log_parser_panic with ()` mutation. The function
        // is pure side-effect: its only observable behavior is the
        // structured tracing event. Install a thread-local Layer that
        // records every event's target and field values, then assert the
        // expected target and required fields appear.
        struct Capture {
            events: Arc<Mutex<Vec<String>>>,
        }
        struct V<'a>(&'a mut String);
        impl Visit for V<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                write!(self.0, " {}={value:?}", field.name()).ok();
            }
            fn record_u64(&mut self, field: &Field, value: u64) {
                write!(self.0, " {}={value}", field.name()).ok();
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                write!(self.0, " {}={value}", field.name()).ok();
            }
        }
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let mut record = format!("target={}", event.metadata().target());
                event.record(&mut V(&mut record));
                self.events.lock().unwrap().push(record);
            }
        }

        install_permissive_global_default();
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let layer = Capture {
            events: Arc::clone(&events),
        };
        let subscriber = Registry::default().with(layer);
        let dispatch = tracing::Dispatch::new(subscriber);

        tracing::dispatcher::with_default(&dispatch, || {
            log_parser_panic(b"abc");
        });

        let captured = events.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "expected exactly one event, got {captured:?}"
        );
        let record = &captured[0];
        assert!(
            record.contains("target=rimap_content::parser_panic"),
            "expected target in event record, got: {record:?}",
        );
        assert!(
            record.contains("input_len=3"),
            "expected input_len=3 field, got: {record:?}",
        );
        assert!(
            record.contains("input_sha256_prefix="),
            "expected input_sha256_prefix field, got: {record:?}",
        );
    }
}
