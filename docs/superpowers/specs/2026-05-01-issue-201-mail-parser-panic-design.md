# Issue #201 — `mail-parser` panic isolation in `rimap-content` (design)

**Date:** 2026-05-01
**Branch:** `fix/issue-201-mail-parser-panic`
**Issue:** [#201](https://github.com/randomparity/rusty-imap-mcp/issues/201)
**Severity:** MEDIUM (process-abort on attacker-controlled MIME input; no
remote code execution, but a crafted message can take down the server)

## Goal

Make every `mail-parser` entry point in `rimap-content` panic-safe by catching
unwinds from third-party code at the API boundary, so a crafted RFC 5322 byte
stream produces a typed error or empty result instead of aborting the process.
Add a regression test pinned to the artifact-recovered crash input from PR
\#200's fuzz run, and file the bug upstream so we don't keep re-discovering it.

## Background

The `pr-smoke` Fuzz job (target `content_mime`) hit a panic inside
`mail-parser-0.11.2` while fuzzing PR #200:

```
thread '<unnamed>' (67) panicked at
/rust/registry/src/index.crates.io-1949cf8c6b5b557f/mail-parser-0.11.2/src/parsers/message.rs:449:67:
range start index 9 out of range for slice of length 4
```

The crash input is preserved as the `crashes-content_mime` artifact on
[run 25235117599](https://github.com/randomparity/rusty-imap-mcp/actions/runs/25235117599)
(expires 2026-07-30, so we mirror it into the repo before then).

### Why we can't fix this by upgrading

`mail-parser` 0.11.2 is the current crates.io release. Upstream `main`
(`stalwartlabs/mail-parser`) also reads `version = "0.11.2"`; the latest
*tagged* release on GitHub is v0.11.1, which is older than what we already
pin. There is no patched release to upgrade to. Acceptance-criteria
option (1) "upgrade" is therefore unavailable; the work collapses to (2)
defensive `catch_unwind` wrap and (3) upstream report.

A possibly-related upstream issue is open: stalwartlabs/mail-parser#120,
"The library will panic with messages containing corrupted eml attachments"
(filed Oct 2025, no comments). The minimised crash input recovered from our
artifact will determine whether they share a root cause.

### Why all four entry points matter

`rimap-content` invokes `MessageParser::parse` in four places, all of which
ingest attacker-controlled bytes (server-supplied RFC 5322 from IMAP):

1. `crates/rimap-content/src/parse/mod.rs:75` — `parse_message`
   *(what fuzz hit)*
2. `crates/rimap-content/src/raw_parts.rs:33` — `walk_attachment_parts`
3. `crates/rimap-content/src/threading.rs:33` — `extract_threading_headers`
4. `crates/rimap-content/src/lib.rs:39` — `extract_message_id`

Wrapping only the fuzzed entry point would leave the other three exposed to
the same upstream panic class. All four convert.

### Panic strategy

`Cargo.toml`'s `[profile.release]` does not set `panic = "abort"`, so the
default `unwind` strategy is in effect for release, debug, and test builds.
`std::panic::catch_unwind` works in every build. The clippy `panic = "deny"`
lint bans the `panic!()` *macro* in our code; it does not affect
`catch_unwind`.

## Approach

### Architecture

One internal helper, four call-site rewrites, one new error variant, one
fixture-backed regression test, one fuzz-corpus seed, one upstream report.

```
crates/rimap-content/
├── src/
│   ├── parse/
│   │   ├── mod.rs            (modified: ParserPanic from safe_parse)
│   │   └── safe_parser.rs    (NEW: catch_unwind wrapper + tracing)
│   ├── raw_parts.rs          (modified: ParserPanic from safe_parse)
│   ├── threading.rs          (modified: default on safe_parse panic)
│   ├── lib.rs                (modified: None on safe_parse panic)
│   └── error.rs              (modified: + ParserPanic variant)
├── tests/
│   ├── data/                 (NEW)
│   │   └── mail_parser_panic_201.eml   (NEW: artifact-recovered crash)
│   └── parser_panic_safety.rs          (NEW: regression test)
└── Cargo.toml                (modified: + sha2 workspace dep)

fuzz/
└── corpus/
    └── content_mime/
        └── mail_parser_panic_201      (NEW: same bytes as fixture)
```

### The wrapper

New module `crates/rimap-content/src/parse/safe_parser.rs`:

```rust
use std::panic::{AssertUnwindSafe, catch_unwind};
use mail_parser::{Message, MessageParser};
use sha2::{Digest, Sha256};

/// Sentinel returned when `mail-parser` panics on attacker-controlled input.
/// Distinct from `Option::None` (which means the parser cleanly rejected
/// the bytes), so callers can choose whether to surface the difference.
#[derive(Debug)]
pub(crate) struct ParserPanic;

/// Run `MessageParser::default().parse(raw)` inside `catch_unwind`. On a
/// caught panic, emit a `tracing::error!` line carrying the input length
/// and the first 16 hex chars of `sha256(raw)` (never the bytes), then
/// return `Err(ParserPanic)`. On normal return, propagate the parser's
/// `Option<Message<'_>>` as `Ok(_)`.
pub(crate) fn safe_parse(raw: &[u8]) -> Result<Option<Message<'_>>, ParserPanic> {
    let parser = MessageParser::default();
    let result = catch_unwind(AssertUnwindSafe(|| parser.parse(raw)));
    match result {
        Ok(parsed) => Ok(parsed),
        Err(_payload) => {
            let mut hasher = Sha256::new();
            hasher.update(raw);
            let digest = hasher.finalize();
            let hash_prefix = hex::encode(&digest[..8]);  // 16 hex chars
            tracing::error!(
                target: "rimap_content::parser_panic",
                input_len = raw.len(),
                input_sha256_prefix = %hash_prefix,
                "mail-parser panicked on input"
            );
            Err(ParserPanic)
        }
    }
}
```

`AssertUnwindSafe` is justified: on a caught panic we discard both `parser`
and any partial `Message` and return immediately, so any logical invariants
the parser left broken cannot be observed by our code. The panic payload is
deliberately unused — we never want to format attacker-controlled debug
strings into logs.

`hex` is already a workspace dependency. `sha2` is already a workspace
dependency for four sibling crates; this design adds it to
`rimap-content`'s dependency list.

### Call-site behaviour

Each of the four call sites collapses panic into the same sentinel that
matches its existing return shape, except `parse_message` and
`walk_attachment_parts` distinguish panic from clean-rejection via a new
`ContentError` variant:

| Call site                          | On clean rejection         | On caught panic                              |
|------------------------------------|----------------------------|----------------------------------------------|
| `parse_message`                    | `Err(Malformed { ... })`   | `Err(ParserPanic)` *(new variant)*           |
| `walk_attachment_parts`            | `Err(Malformed { ... })`   | `Err(ParserPanic)` *(new variant)*           |
| `extract_threading_headers`        | `ThreadingHeaders::default()` | `ThreadingHeaders::default()`             |
| `extract_message_id`               | `None`                     | `None`                                       |

Treating panic as a distinct error for the two `Result`-returning entry
points lets the audit pipeline alert on `ParserPanic` separately from the
high-volume `Malformed` channel: a `Malformed` is ordinary "bad bytes from
an IMAP server", a `ParserPanic` is "an attacker found a way to crash the
parser". Different signal class, different runbook.

`extract_threading_headers` and `extract_message_id` already collapse
parse-rejection to the same value as success-with-no-data (default /
None), so callers cannot distinguish them anyway; the panic path joins
that bucket. The `tracing::error!` line in `safe_parse` is the
observability hook for those two.

### New error variant

```rust
// crates/rimap-content/src/error.rs
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ContentError {
    #[error("malformed message: {reason}")]
    Malformed { reason: String },

    #[error("content limit exceeded: {kind} (limit={limit})")]
    LimitExceeded { kind: &'static str, limit: usize },

    /// Third-party MIME parser (`mail-parser`) panicked on the input.
    /// The panic was caught at the rimap-content boundary; the process
    /// is intact. Callers should treat this as a hard rejection of the
    /// message, equivalent to `Malformed` for control-flow purposes,
    /// but distinct for audit and alerting.
    #[error("third-party MIME parser panicked on input")]
    ParserPanic,
}
```

`#[non_exhaustive]` already on the enum, so adding the variant is
non-breaking for downstream `match` callers (they're forced to handle
`_`).

### Regression test

Recover the crash bytes from the GitHub Actions artifact (or the
`/tmp/.../crash-3dfef11827edd59b81f1ccc37ac16da62158472b` filename
recorded in the panic), commit them as
`crates/rimap-content/tests/data/mail_parser_panic_201.eml`, and assert
in a new test file `tests/parser_panic_safety.rs`:

```rust
#[test]
fn parse_message_does_not_panic_on_issue_201_input() {
    let raw = include_bytes!("data/mail_parser_panic_201.eml");
    let err = rimap_content::parse_message(raw).expect_err("must not succeed");
    assert!(
        matches!(err, ContentError::ParserPanic) || matches!(err, ContentError::Malformed { .. }),
        "expected ParserPanic or Malformed, got {err:?}"
    );
}
```

The `or Malformed` branch is deliberate: if upstream ships a fix in a
later 0.11.x bump and we pick it up, the input may parse cleanly or be
rejected as malformed instead of panicking. The test stays green either
way. The point of the test is "we don't panic", not "the input is always
panic-bait".

A second `#[test]` in the same file calls `walk_attachment_parts`,
`extract_threading_headers`, and `extract_message_id` on the same bytes
and asserts none of them panic.

### Fuzz-corpus seed

Copy the same bytes to `fuzz/corpus/content_mime/mail_parser_panic_201`.
This protects the regression even if upstream's persistent corpus-fetch
issue (the separate 401-fetch bug referenced in #201's "out of scope")
remains broken — the in-tree seed corpus covers it.

### Upstream report

File a fresh issue at https://github.com/stalwartlabs/mail-parser with:

- **Title:** "Panic on crafted input: range start index 9 out of range
  for slice of length 4 in `parsers/message.rs:449`"
- **Body:** the panic message, the exact panic location
  (`parsers/message.rs:449:67` on 0.11.2), confirmation it reproduces
  via `cargo fuzz` on a downstream crate, and a minimised reproducer:

```rust
// Cargo.toml: mail-parser = "0.11.2"
fn main() {
    let raw = include_bytes!("crash-3dfef11827edd59b81f1ccc37ac16da62158472b");
    let _ = mail_parser::MessageParser::default().parse(raw);
    // Panics:
    //   range start index 9 out of range for slice of length 4
    //   at mail-parser-0.11.2/src/parsers/message.rs:449:67
}
```

with the crash bytes attached as a base64 block or as a file attachment.
Cross-link to upstream #120 (asking whether they're the same root cause)
and to our #201 (so they can see we've added a defensive wrapper
downstream).

The implementation plan will produce the report text as a deliverable
file (e.g. `docs/superpowers/notes/upstream-mail-parser-201.md`) so it's
versioned and reviewable before posting.

## Testing

- **Regression test** (`tests/parser_panic_safety.rs`): the artifact
  bytes round-trip through all four entry points without panicking.
- **Unit test on `safe_parser`'s error arm**: synthetically panicking
  `mail_parser` from a test is impractical, so the unit test factors
  the panic-handling code into an inner helper that takes the
  `catch_unwind` result, then exercises that helper directly with a
  hand-rolled `Err(Box::new("synthetic"))` payload. This verifies the
  hash + tracing path independently of `mail_parser`'s behaviour.
- **Existing tests** in `crates/rimap-content/tests/` continue to pass.
- **Fuzz**: the seed corpus addition causes `cargo fuzz run content_mime`
  to immediately exercise the input. The job must complete without a
  libfuzzer crash report. Confirm locally before pushing.

## Out of scope

- The `pr-smoke` corpus / 401 fetch infrastructure issue. Tracked
  separately per #201's own out-of-scope note.
- Re-auditing the rest of the `mail-parser` API surface for other panic
  classes. The wrapper is generic over input — any future panic in any
  `parse()` call site is automatically caught.
- Migrating off `mail-parser`. The supply-chain note in `Cargo.toml:88`
  contemplates this only on a re-audit trigger; this issue is not that
  trigger.

## Acceptance criteria

- [ ] `crates/rimap-content/src/parse/safe_parser.rs` exists, exposes
  `safe_parse`, and is the only place `MessageParser::parse` is called.
- [ ] `ContentError::ParserPanic` is added to the public error enum.
- [ ] All four legacy `MessageParser::parse` call sites route through
  `safe_parse`.
- [ ] `tests/data/mail_parser_panic_201.eml` is the artifact-recovered
  crash input; its sha1 matches the libfuzzer-assigned filename
  `crash-3dfef11827edd59b81f1ccc37ac16da62158472b` (libfuzzer names crash
  files by sha1 of the input bytes).
- [ ] `tests/parser_panic_safety.rs` covers all four entry points and
  passes in CI.
- [ ] `fuzz/corpus/content_mime/mail_parser_panic_201` is the same bytes.
- [ ] Upstream issue text is drafted at
  `docs/superpowers/notes/upstream-mail-parser-201.md` with full
  reproducer (Cargo.toml dep, minimal `fn main`, attached/embedded crash
  bytes), linked to upstream #120 and our #201.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean.
- [ ] `cargo test -p rimap-content` clean.
- [ ] `cargo fuzz run content_mime -- -runs=1000` does not reproduce the
  panic locally.
