# Issue #201 — `mail-parser` Panic Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every `mail-parser` entry point in `rimap-content` panic-safe so attacker-controlled MIME input cannot abort the process; pin a regression test to the artifact-recovered crash bytes; draft an upstream report.

**Architecture:** Single internal `safe_parse` helper wrapping `MessageParser::default().parse(raw)` in `catch_unwind(AssertUnwindSafe(...))`. Caught panics emit a `tracing::error!` with input length + sha256 prefix (no payload bytes) and produce either a new `ContentError::ParserPanic` variant (for `Result`-returning entry points) or the existing default/None fallback (for the two infallible-shaped entry points). One repository fixture, one regression test file, one fuzz-corpus seed, one drafted upstream issue.

**Tech Stack:** Rust 2024, `mail-parser` 0.11.2 (pinned), `tracing` 0.1 (workspace), `sha2` 0.11 (workspace), `hex` 0.4 (workspace), `thiserror` (already in `rimap-content`), `cargo fuzz` for the seed verification.

**Spec:** [`docs/superpowers/specs/2026-05-01-issue-201-mail-parser-panic-design.md`](../specs/2026-05-01-issue-201-mail-parser-panic-design.md)

---

## File Map

**Create:**
- `crates/rimap-content/src/parse/safe_parser.rs` — wrapper module
- `crates/rimap-content/tests/data/mail_parser_panic_201.eml` — crash fixture
- `crates/rimap-content/tests/parser_panic_safety.rs` — regression test
- `fuzz/corpus/content_mime/mail_parser_panic_201` — fuzz-corpus seed (same bytes as fixture)
- `docs/superpowers/notes/upstream-mail-parser-201.md` — upstream issue draft

**Modify:**
- `crates/rimap-content/Cargo.toml` — add `sha2`, `hex`, `tracing` deps
- `crates/rimap-content/src/error.rs` — add `ParserPanic` variant + Display test
- `crates/rimap-content/src/parse/mod.rs` — declare `safe_parser` submodule, route `parse_message` through it, surface `ParserPanic`
- `crates/rimap-content/src/raw_parts.rs` — route `walk_attachment_parts` through `safe_parse`
- `crates/rimap-content/src/threading.rs` — route `extract_threading_headers` through `safe_parse`
- `crates/rimap-content/src/lib.rs` — route `extract_message_id` through `safe_parse`

---

## Task 0: Create the feature branch and recover the crash artifact

**Files:** none yet (working-tree setup)

- [ ] **Step 1: Create the feature branch from main**

```bash
git switch main
git pull --ff-only
git switch -c fix/issue-201-mail-parser-panic
```

Expected: branch `fix/issue-201-mail-parser-panic` created and checked out.

- [ ] **Step 2: Download the crash artifact from the workflow run**

The crash bytes are preserved as the `crashes-content_mime` artifact on workflow run `25235117599` (expires 2026-07-30).

```bash
mkdir -p /tmp/issue-201
gh run download 25235117599 --repo randomparity/rusty-imap-mcp --name crashes-content_mime --dir /tmp/issue-201/
ls /tmp/issue-201/
```

Expected: a file named `crash-3dfef11827edd59b81f1ccc37ac16da62158472b` in `/tmp/issue-201/`.

- [ ] **Step 3: Verify the file's sha1 matches the libfuzzer-assigned filename**

Libfuzzer names crash files `crash-<sha1(input)>`. Verify the bytes are intact:

```bash
shasum -a 1 /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b
```

Expected output:

```
3dfef11827edd59b81f1ccc37ac16da62158472b  /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b
```

If the sha1 does not match the filename, stop — the artifact is corrupt and a re-download is needed.

- [ ] **Step 4: Confirm the panic reproduces locally before fixing**

Build the fuzz target and feed it the crash file directly. This is a sanity check that the bug is real and reproducible from the artifact, before we add the wrapper.

```bash
cd /Users/dave/src/rusty-imap-mcp/fuzz
cargo +nightly fuzz run content_mime /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b -- -runs=1
```

Expected: libfuzzer prints a panic from `mail-parser-0.11.2/src/parsers/message.rs:449:67` with text like `range start index 9 out of range for slice of length 4`. Save the exact panic stderr to `/tmp/issue-201/panic.stderr` for use in the upstream issue draft (Task 11):

```bash
cargo +nightly fuzz run content_mime /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b -- -runs=1 2>/tmp/issue-201/panic.stderr || true
grep -A2 "panicked at" /tmp/issue-201/panic.stderr
```

Expected: the grep prints the `panicked at .../parsers/message.rs:449:67` line plus the slice-OOB message.

If the panic does **not** reproduce, stop — diagnosis is required before wrapping.

- [ ] **Step 5: Commit the branch start (no file changes yet, so use an empty marker commit only if your team requires it; otherwise skip)**

Skip the marker commit. Branch is ready for real work in Task 1.

---

## Task 1: Add workspace dependencies to `rimap-content`

**Files:** Modify `crates/rimap-content/Cargo.toml`

`safe_parser.rs` will need `tracing` for the structured log line, `sha2` for the input hash, and `hex` for hex-encoding the prefix. All three are already pinned at the workspace level (`Cargo.toml:61`, `:74`, `:75`). The crate must opt in.

- [ ] **Step 1: Add the three deps under `[dependencies]`**

Open `crates/rimap-content/Cargo.toml`. After line 24 (`mail-parser = { workspace = true }`), insert:

```toml
tracing = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
```

The final `[dependencies]` block, in source order, becomes:

```toml
[dependencies]
rimap-core = { path = "../rimap-core", version = "1.0.0" }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
time = { workspace = true }
mail-parser = { workspace = true }
tracing = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
encoding_rs = { workspace = true }
unicode-normalization = { workspace = true }
unicode-segmentation = { workspace = true }
unicode-script = { workspace = true }
scraper = { workspace = true }
ammonia = { workspace = true }
linkify = { workspace = true }
idna = { workspace = true }
addr = { workspace = true }
phf = { workspace = true }
```

- [ ] **Step 2: Verify the workspace build still succeeds with the new deps**

Run:

```bash
cargo check -p rimap-content
```

Expected: `Finished` with no warnings or errors. New deps are unused at this point but `cargo check` should not flag them — the actual unused-dep guard is `cargo machete`, which runs on commit-time hooks only when configured.

- [ ] **Step 3: Run the unused-dep linter to confirm we are not in violation yet**

Because nothing imports `tracing`/`sha2`/`hex` yet, `cargo machete` will flag them. We accept this transient state — Task 3 introduces all three usages. Skip the machete run until Task 3 is complete; if your local hook fires it, allow this commit through.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-content/Cargo.toml
git commit -m "$(cat <<'EOF'
deps(rimap-content): add tracing, sha2, hex for panic-isolation wrapper

Pulls workspace-pinned tracing 0.1, sha2 0.11, and hex 0.4 into
rimap-content. Consumed by the forthcoming safe_parser module
(issue #201) for structured panic logging and input-hash redaction.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: clean commit, working tree is clean afterward.

---

## Task 2: Add `ContentError::ParserPanic` variant (TDD)

**Files:** Modify `crates/rimap-content/src/error.rs`

The new variant is the public-facing signal that "third-party parser panicked on input". It joins the existing `Malformed` and `LimitExceeded` variants. The enum is already `#[non_exhaustive]`, so adding a variant is non-breaking for `match` callers.

- [ ] **Step 1: Write the failing Display test**

Open `crates/rimap-content/src/error.rs`. Inside the existing `#[cfg(test)] mod tests` block (after `malformed_display`), add:

```rust
    #[test]
    fn parser_panic_display() {
        let err = ContentError::ParserPanic;
        assert_eq!(
            err.to_string(),
            "third-party MIME parser panicked on input"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails to compile**

```bash
cargo test -p rimap-content --lib error::tests::parser_panic_display
```

Expected: compile error `no variant or associated item named ParserPanic found for enum ContentError`.

- [ ] **Step 3: Add the variant**

Replace the body of the `ContentError` enum (lines 11–31 of `error.rs`) with:

```rust
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ContentError {
    /// The message could not be parsed as RFC 5322. This is a hard
    /// failure — `mail-parser` rejected the byte stream entirely.
    #[error("malformed message: {reason}")]
    Malformed {
        /// Short description of what went wrong.
        reason: String,
    },

    /// A hard limit was exceeded. The caller should reject the message.
    /// `kind` names which limit tripped; `limit` is the compile-time
    /// constant value.
    #[error("content limit exceeded: {kind} (limit={limit})")]
    LimitExceeded {
        /// Which limit was exceeded (e.g. `"mime_depth"`, `"mime_parts"`,
        /// `"header_count"`).
        kind: &'static str,
        /// The compile-time limit value that was exceeded.
        limit: usize,
    },

    /// Third-party MIME parser (`mail-parser`) panicked on the input.
    /// The panic was caught at the `rimap-content` boundary; the
    /// process is intact. Callers should treat this as a hard rejection
    /// of the message, equivalent to `Malformed` for control-flow
    /// purposes, but distinct for audit and alerting (a panic means an
    /// attacker found a way to crash the parser, not just bad bytes).
    #[error("third-party MIME parser panicked on input")]
    ParserPanic,
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p rimap-content --lib error::tests
```

Expected: all three tests in `error::tests` pass (`limit_exceeded_display`, `malformed_display`, `parser_panic_display`).

- [ ] **Step 5: Run clippy on the crate**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean. (No new warnings — `#[non_exhaustive]` was already present.)

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-content/src/error.rs
git commit -m "$(cat <<'EOF'
feat(rimap-content): add ContentError::ParserPanic variant

New variant signals that mail-parser panicked on attacker-controlled
input; distinct from Malformed so audit/alerting can treat caught
panics as a higher-signal class than ordinary parse rejections. Enum
already #[non_exhaustive], so addition is non-breaking.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Build the `safe_parser` module (TDD)

**Files:**
- Create: `crates/rimap-content/src/parse/safe_parser.rs`
- Modify: `crates/rimap-content/src/parse/mod.rs` (declare the submodule)

The wrapper is the single chokepoint where every `mail_parser::MessageParser::parse` call in this crate happens, so we can audit panic safety in one place. Its only public-to-the-crate surface is `safe_parse(raw) -> Result<Option<Message<'_>>, ParserPanic>` and the sentinel `ParserPanic`.

- [ ] **Step 1: Declare the submodule in `parse/mod.rs`**

Open `crates/rimap-content/src/parse/mod.rs`. Below line 21 (`pub(crate) mod mime_scrub;`) insert:

```rust
mod safe_parser;
```

Keep the rest of the file untouched.

- [ ] **Step 2: Create the file with the helper and unit tests in one shot**

Create `crates/rimap-content/src/parse/safe_parser.rs` with the full content below. Steps 3–6 *verify* this content; we write the file once and then watch the tests go from "fails to compile" → "passes".

```rust
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
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        MessageParser::default().parse(raw)
    }));
    match outcome {
        Ok(parsed) => Ok(parsed),
        Err(_payload) => {
            // Deliberately ignore the panic payload — we never want to
            // format attacker-controlled debug strings into logs.
            log_parser_panic(raw);
            Err(ParserPanic)
        }
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
        let result = match outcome {
            Ok(parsed) => Ok(parsed),
            Err(_) => {
                log_parser_panic(raw);
                Err(ParserPanic)
            }
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
```

- [ ] **Step 3: Run the new tests**

```bash
cargo test -p rimap-content --lib parse::safe_parser::tests
```

Expected: three tests pass:
- `safe_parse_passes_through_clean_input`
- `catch_unwind_error_arm_produces_parser_panic`
- `log_parser_panic_handles_empty_input`

- [ ] **Step 4: Confirm the wider crate still builds**

```bash
cargo build -p rimap-content --all-targets
```

Expected: clean.

- [ ] **Step 5: Run clippy**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean. The `#[expect(clippy::panic, ...)]` attribute on the synthetic-panic test silences the panic-deny lint locally with a documented justification.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-content/src/parse/safe_parser.rs crates/rimap-content/src/parse/mod.rs
git commit -m "$(cat <<'EOF'
feat(rimap-content): add safe_parser::safe_parse panic-isolation wrapper

New internal helper wraps MessageParser::default().parse(raw) in
catch_unwind(AssertUnwindSafe(...)). Caught panics emit a structured
tracing::error! with input_len + sha256 prefix (never the bytes) and
return Err(ParserPanic). Unit tests cover the happy path and the
error-arm logic via a synthetic panic.

This commit only introduces the wrapper. The four existing call sites
to MessageParser::parse remain unwrapped — they convert in subsequent
commits.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Mirror the crash artifact into the repository

**Files:**
- Create: `crates/rimap-content/tests/data/mail_parser_panic_201.eml`
- Create: `fuzz/corpus/content_mime/mail_parser_panic_201`

The same bytes feed both the regression test and the fuzz corpus. Storing them once in the repo lets us assert behaviour deterministically and ensures `cargo fuzz` re-encounters the input on every run.

- [ ] **Step 1: Create the `tests/data/` directory and copy the artifact**

```bash
mkdir -p crates/rimap-content/tests/data
cp /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b \
   crates/rimap-content/tests/data/mail_parser_panic_201.eml
```

- [ ] **Step 2: Copy the same bytes to the fuzz corpus**

```bash
cp /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b \
   fuzz/corpus/content_mime/mail_parser_panic_201
```

- [ ] **Step 3: Verify both copies match the original sha1**

```bash
shasum -a 1 \
  /tmp/issue-201/crash-3dfef11827edd59b81f1ccc37ac16da62158472b \
  crates/rimap-content/tests/data/mail_parser_panic_201.eml \
  fuzz/corpus/content_mime/mail_parser_panic_201
```

Expected: all three lines start with `3dfef11827edd59b81f1ccc37ac16da62158472b`.

- [ ] **Step 4: Confirm git is willing to commit binary fixtures (no LFS, no hooks blocking)**

```bash
git add crates/rimap-content/tests/data/mail_parser_panic_201.eml fuzz/corpus/content_mime/mail_parser_panic_201
git status
```

Expected: both paths show as `new file:` under "Changes to be committed". If `.gitattributes` enforces LFS for `*.eml` (it currently does not in this repo), stop and confirm with the user.

- [ ] **Step 5: Commit the fixtures**

```bash
git commit -m "$(cat <<'EOF'
test(rimap-content): import issue #201 crash artifact as fixture

Same bytes land in two places:
- crates/rimap-content/tests/data/mail_parser_panic_201.eml
  drives the regression test in tests/parser_panic_safety.rs
  (added in a follow-up commit)
- fuzz/corpus/content_mime/mail_parser_panic_201
  ensures cargo fuzz re-exercises the input even when the
  persistent corpus fetch is unavailable

sha1 of the bytes matches the libfuzzer-assigned filename
crash-3dfef11827edd59b81f1ccc37ac16da62158472b from workflow
run 25235117599 (artifact crashes-content_mime, expires 2026-07-30).

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Write the regression test file (uncommitted)

**Files:** Create `crates/rimap-content/tests/parser_panic_safety.rs` — but **do not commit it yet**.

We write the integration test now and run it locally to watch each of the four `#[test]` functions panic. The file stays uncommitted in the working tree across Tasks 6–8, with each task turning one more test green when run locally. Task 9 commits the test file together with the final call-site fix, so every committed state on the branch has green tests and we never need `--no-verify`.

- [ ] **Step 1: Create the test file**

```rust
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

const CRASH_INPUT: &[u8] =
    include_bytes!("data/mail_parser_panic_201.eml");

#[test]
fn parse_message_does_not_panic_on_issue_201_input() {
    // The point of this test is "we don't panic", not "the input is
    // always panic-bait". If upstream patches mail-parser later and we
    // pick up a fix, the input may parse cleanly or be rejected as
    // Malformed. Either is acceptable; only a panic fails the test.
    match parse_message(CRASH_INPUT) {
        Ok(_) => {}
        Err(ContentError::ParserPanic) => {}
        Err(ContentError::Malformed { .. }) => {}
        Err(ContentError::LimitExceeded { .. }) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn walk_attachment_parts_does_not_panic_on_issue_201_input() {
    match walk_attachment_parts(CRASH_INPUT) {
        Ok(_) => {}
        Err(ContentError::ParserPanic) => {}
        Err(ContentError::Malformed { .. }) => {}
        Err(ContentError::LimitExceeded { .. }) => {}
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
```

- [ ] **Step 2: Run the test file and confirm all four currently panic**

```bash
cargo test -p rimap-content --test parser_panic_safety -- --nocapture
```

Expected: all four tests fail with a panic from `mail-parser-0.11.2/src/parsers/message.rs:449:67`:

```
test parse_message_does_not_panic_on_issue_201_input ... FAILED
test walk_attachment_parts_does_not_panic_on_issue_201_input ... FAILED
test extract_threading_headers_does_not_panic_on_issue_201_input ... FAILED
test extract_message_id_does_not_panic_on_issue_201_input ... FAILED
```

If any of the four already passes, stop — it means the call site is reaching mail-parser via a different code path than expected, and the conversion plan needs revisiting.

- [ ] **Step 3: Do not commit yet**

Confirm `git status` shows `crates/rimap-content/tests/parser_panic_safety.rs` as `Untracked`. Leave it that way. The file is committed in Task 9 alongside the final call-site fix.

```bash
git status -- crates/rimap-content/tests/parser_panic_safety.rs
```

Expected:

```
Untracked files:
  (use "git add <file>..." to include in what will be committed)
        crates/rimap-content/tests/parser_panic_safety.rs
```

---

## Task 6: Wire `parse_message` through `safe_parse`

**Files:** Modify `crates/rimap-content/src/parse/mod.rs`

This is the entry point the fuzzer hit. After this commit, `parse_message_does_not_panic_on_issue_201_input` flips green.

- [ ] **Step 1: Replace the `MessageParser::default().parse(...)` call with `safe_parse`**

Open `crates/rimap-content/src/parse/mod.rs`. The current body of `parse_message` (lines 63–108) calls `MessageParser::default().parse(&scrubbed)` directly. Replace lines 74–79:

```rust
    let message =
        MessageParser::default()
            .parse(&scrubbed)
            .ok_or_else(|| ContentError::Malformed {
                reason: "mail-parser rejected byte stream".to_string(),
            })?;
```

with:

```rust
    let message = safe_parser::safe_parse(&scrubbed)
        .map_err(|_| ContentError::ParserPanic)?
        .ok_or_else(|| ContentError::Malformed {
            reason: "mail-parser rejected byte stream".to_string(),
        })?;
```

Also remove the now-unused `use mail_parser::MessageParser;` import at the top of the file (line 9). The `MessageParser` symbol is no longer referenced from `parse/mod.rs` itself — it lives behind the `safe_parser` boundary now. No replacement `use` statement is needed: the new code references `safe_parser::safe_parse`, and `safe_parser` is already a direct submodule of `crate::parse` (declared in Task 3), reachable by bare name from inside `parse/mod.rs`.

Sanity check before deleting: confirm line 9's import is the only reference to `MessageParser` in `parse/mod.rs`.

```bash
grep -n MessageParser crates/rimap-content/src/parse/mod.rs
```

Expected after Task 6 step 1: zero matches. (Sister files like `parse/bodies.rs` may still reference `MessageParser` inside their own `#[cfg(test)] mod tests` blocks; those imports are independent and stay as they are.)

- [ ] **Step 2: Run the production-side test**

```bash
cargo test -p rimap-content --test parser_panic_safety \
  parse_message_does_not_panic_on_issue_201_input -- --nocapture
```

Expected: `test parse_message_does_not_panic_on_issue_201_input ... ok`. If the test logs a `tracing` line on stderr containing `rimap_content::parser_panic`, that is the expected observability signal — not a failure.

- [ ] **Step 3: Run the rest of the `parse_message` unit tests to confirm no regressions**

```bash
cargo test -p rimap-content --lib parse::tests
```

Expected: every existing test in `parse::tests` still passes. Specifically: `parse_extracts_from_to_subject`, `parse_oversized_body_emits_truncation_warning`, `parse_rejects_mime_depth_bomb`, etc.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Commit only the source-side change**

The uncommitted test file in `tests/parser_panic_safety.rs` is left in the working tree; it now passes one of its four tests locally. The remaining three still fail with a panic. We commit the test file in Task 9 once all four are green.

```bash
git add crates/rimap-content/src/parse/mod.rs
git commit -m "$(cat <<'EOF'
fix(rimap-content): route parse_message through safe_parse (#201)

parse_message now invokes mail_parser::MessageParser::parse via
safe_parser::safe_parse, so a panic in upstream parser code becomes
ContentError::ParserPanic instead of aborting the process. Cleanly
rejected input still produces ContentError::Malformed.

The repository-level regression test that pins this behaviour to the
issue #201 crash artifact lands in a follow-up commit once all four
mail-parser entry points are converted.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Confirm `git status` still shows the test file as untracked:

```bash
git status -- crates/rimap-content/tests/parser_panic_safety.rs
```

Expected: `Untracked`.

---

## Task 7: Wire `walk_attachment_parts` through `safe_parse`

**Files:** Modify `crates/rimap-content/src/raw_parts.rs`

`walk_attachment_parts` lives in a different module than `safe_parser`, so we must expose `safe_parse` to it. Two options:

A. Make `parse::safe_parser` `pub(crate)` so siblings can `use crate::parse::safe_parser`.
B. Re-export `safe_parse` and `ParserPanic` at the crate root under `pub(crate)`.

Pick **A** — `safe_parser` is already declared as a private submodule under `parse/mod.rs`; we change `mod safe_parser;` to `pub(crate) mod safe_parser;` and the symbol is reachable as `crate::parse::safe_parser::safe_parse`. No re-export shenanigans, the dependency direction stays parse → safe_parser.

- [ ] **Step 1: Promote `safe_parser` to `pub(crate)` in `parse/mod.rs`**

Edit `crates/rimap-content/src/parse/mod.rs`. Change the line added in Task 3 from:

```rust
mod safe_parser;
```

to:

```rust
pub(crate) mod safe_parser;
```

Run `cargo check -p rimap-content` to confirm no callers broke. Expected: clean.

- [ ] **Step 2: Replace the `MessageParser::new().parse(...)` call in `raw_parts.rs`**

Open `crates/rimap-content/src/raw_parts.rs`. Replace lines 33–37:

```rust
    let parsed = mail_parser::MessageParser::new()
        .parse(raw)
        .ok_or_else(|| ContentError::Malformed {
            reason: "failed to parse RFC 5322 message".into(),
        })?;
```

with:

```rust
    let parsed = crate::parse::safe_parser::safe_parse(raw)
        .map_err(|_| ContentError::ParserPanic)?
        .ok_or_else(|| ContentError::Malformed {
            reason: "failed to parse RFC 5322 message".into(),
        })?;
```

Note: the previous code used `MessageParser::new()`; `safe_parse` uses `MessageParser::default()`. Verify these are equivalent:

```bash
grep -A4 "pub fn new\|impl Default for MessageParser" \
  ~/.cargo/registry/src/index.crates.io-*/mail-parser-0.11.2/src/parsers/mod.rs \
  ~/.cargo/registry/src/index.crates.io-*/mail-parser-0.11.2/src/lib.rs 2>/dev/null | head -30
```

Both `new()` and `default()` construct a `MessageParser` with all built-in header parsers enabled — they are aliases. If the source shows otherwise (e.g. `default()` enabling some parser `new()` does not), stop and revisit `safe_parse` to use `MessageParser::new()` instead.

- [ ] **Step 3: Run the regression test**

```bash
cargo test -p rimap-content --test parser_panic_safety \
  walk_attachment_parts_does_not_panic_on_issue_201_input
```

Expected: pass.

- [ ] **Step 4: Run the existing `raw_parts` tests**

```bash
cargo test -p rimap-content --lib raw_parts::tests
```

Expected: all three tests still pass (`single_part_message_yields_one_raw_part`, `multipart_yields_leaf_parts_with_imap_ids`, `unparsable_is_malformed`).

- [ ] **Step 5: Run clippy**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit only the source-side change**

```bash
git add crates/rimap-content/src/parse/mod.rs crates/rimap-content/src/raw_parts.rs
git commit -m "$(cat <<'EOF'
fix(rimap-content): route walk_attachment_parts through safe_parse (#201)

Raises mail_parser::MessageParser::parse panics to
ContentError::ParserPanic at the raw_parts boundary. Promotes
parse::safe_parser to pub(crate) so siblings can reach the wrapper.

Two of four mail-parser entry points are now panic-safe; the
repository-level regression test still lives uncommitted in the
working tree until Task 9.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Wire `extract_threading_headers` through `safe_parse`

**Files:** Modify `crates/rimap-content/src/threading.rs`

`extract_threading_headers` returns `ThreadingHeaders` by value (no `Result`). Panic and clean-rejection both collapse to `ThreadingHeaders::default()`; the `tracing::error!` line in `safe_parse` is the only observable distinction.

- [ ] **Step 1: Replace the parse call**

Open `crates/rimap-content/src/threading.rs`. Replace line 33:

```rust
    let Some(parsed) = mail_parser::MessageParser::new().parse(raw) else {
        return ThreadingHeaders::default();
    };
```

with:

```rust
    let Ok(Some(parsed)) = crate::parse::safe_parser::safe_parse(raw) else {
        // Both Err(ParserPanic) and Ok(None) (clean rejection) collapse
        // to the same default; safe_parse's own tracing::error! line
        // distinguishes the two for audit consumers.
        return ThreadingHeaders::default();
    };
```

- [ ] **Step 2: Run the regression test**

```bash
cargo test -p rimap-content --test parser_panic_safety \
  extract_threading_headers_does_not_panic_on_issue_201_input
```

Expected: pass.

- [ ] **Step 3: Run the existing threading tests**

```bash
cargo test -p rimap-content --lib threading
```

Expected: all existing tests pass.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Commit only the source-side change**

```bash
git add crates/rimap-content/src/threading.rs
git commit -m "$(cat <<'EOF'
fix(rimap-content): route extract_threading_headers through safe_parse (#201)

Wraps the threading-header parse call so an upstream panic produces
ThreadingHeaders::default() (same shape as a clean parse rejection)
instead of aborting. The tracing::error! line in safe_parse is the
only observable signal that distinguishes panic from rejection here.

Three of four mail-parser entry points are now panic-safe; the
repository-level regression test lands in Task 9 alongside the
final entry-point conversion.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Wire `extract_message_id` through `safe_parse`

**Files:** Modify `crates/rimap-content/src/lib.rs`

`extract_message_id` returns `Option<String>`. Panic and clean-rejection both collapse to `None`.

- [ ] **Step 1: Replace the parse call**

Open `crates/rimap-content/src/lib.rs`. Replace lines 38–42:

```rust
pub fn extract_message_id(raw: &[u8]) -> Option<String> {
    mail_parser::MessageParser::new()
        .parse(raw)
        .and_then(|m| m.message_id().map(ToString::to_string))
}
```

with:

```rust
pub fn extract_message_id(raw: &[u8]) -> Option<String> {
    crate::parse::safe_parser::safe_parse(raw)
        .ok()
        .flatten()
        .and_then(|m| m.message_id().map(ToString::to_string))
}
```

- [ ] **Step 2: Run the regression test**

```bash
cargo test -p rimap-content --test parser_panic_safety \
  extract_message_id_does_not_panic_on_issue_201_input
```

Expected: pass.

- [ ] **Step 3: Run the existing extract_message_id test**

```bash
cargo test -p rimap-content --lib extract_message_id_tests
```

Expected: `extract_returns_message_id_when_header_present` passes.

- [ ] **Step 4: Run the full regression test file**

```bash
cargo test -p rimap-content --test parser_panic_safety
```

Expected: all four tests pass:

```
test extract_message_id_does_not_panic_on_issue_201_input ... ok
test extract_threading_headers_does_not_panic_on_issue_201_input ... ok
test parse_message_does_not_panic_on_issue_201_input ... ok
test walk_attachment_parts_does_not_panic_on_issue_201_input ... ok
```

- [ ] **Step 5: Run the full rimap-content test suite**

```bash
cargo test -p rimap-content
```

Expected: every test passes. No regressions in the existing parse/raw_parts/threading suites.

- [ ] **Step 6: Run clippy**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 7: Commit the final fix together with the regression test file**

This is the commit that lands the previously-uncommitted `tests/parser_panic_safety.rs` from Task 5. With every entry point now routed through `safe_parse`, all four tests pass on the first commit they appear in.

```bash
git add crates/rimap-content/src/lib.rs crates/rimap-content/tests/parser_panic_safety.rs
git commit -m "$(cat <<'EOF'
fix(rimap-content): route extract_message_id through safe_parse (#201)

Final mail_parser::MessageParser::parse call site converts. All four
public entry points to mail-parser now route through the panic-safe
wrapper.

Lands tests/parser_panic_safety.rs in the same commit so this is the
first revision in branch history at which a repository-level
regression test pinned to the issue #201 crash artifact exists, and
that revision has the test fully green. Earlier commits on this
branch already shipped the per-entry-point fixes; the test file was
deferred to keep every committed branch state at green.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Verify the fuzz corpus seed exercises the input cleanly

**Files:** none (the seed was committed in Task 4)

The fixture-and-corpus copy already happened in Task 4. This task verifies that with the wrapper in place, `cargo fuzz run content_mime` no longer crashes on the input.

- [ ] **Step 1: Run the fuzz target against the seed**

```bash
cd /Users/dave/src/rusty-imap-mcp/fuzz
cargo +nightly fuzz run content_mime corpus/content_mime/mail_parser_panic_201 -- -runs=1
```

Expected: libfuzzer exits cleanly (no `crashed!` line, no panic, no `abort`). The `tracing::error!` from `safe_parse` may print to stderr; that is the expected observability signal, not a failure.

If libfuzzer reports a crash, stop — the wrapper is not catching this panic. Re-examine `safe_parse`'s closure body and make sure the call site that the fuzzer drives (`parse_message` via `parse/mod.rs`) actually goes through `safe_parse`.

- [ ] **Step 2: Run a short randomised fuzz session to confirm the wrapper holds for nearby inputs**

```bash
cd /Users/dave/src/rusty-imap-mcp/fuzz
cargo +nightly fuzz run content_mime -- -runs=10000 -max_total_time=60
```

Expected: `Done 10000 runs` (or stops on time budget) with no crashes. If a *different* crash surfaces, file it as a separate issue and continue — it is not in scope for #201.

Return to the repo root:

```bash
cd /Users/dave/src/rusty-imap-mcp
```

- [ ] **Step 3: No commit — this task is verification only**

The corpus seed and tests are already committed. If anything in this task reveals a regression, the fix lands in a follow-up commit on the same branch.

---

## Task 11: Draft the upstream issue text

**Files:** Create `docs/superpowers/notes/upstream-mail-parser-201.md`

The deliverable is a Markdown file ready to paste into a fresh GitHub issue at `stalwartlabs/mail-parser`. Posting the issue is a manual step — we save the draft to git so the wording is reviewable and so we have a record of what we reported.

- [ ] **Step 1: Create the notes directory**

```bash
mkdir -p docs/superpowers/notes
```

- [ ] **Step 2: Recover the exact panic stderr captured in Task 0**

```bash
cat /tmp/issue-201/panic.stderr | grep -A3 "panicked at" | head
```

Note the panic message verbatim (it should match `range start index 9 out of range for slice of length 4` on `parsers/message.rs:449:67`). Use the exact text in the report — engineers searching for the panic will find the issue by string match.

- [ ] **Step 3: Compute the base64 of the crash bytes for embedding in the report**

```bash
base64 -i crates/rimap-content/tests/data/mail_parser_panic_201.eml | tr -d '\n' | fold -w 76 > /tmp/issue-201/crash.b64
wc -l /tmp/issue-201/crash.b64
```

Expected: a few lines of 76-char base64. Keep `/tmp/issue-201/crash.b64` for the next step.

- [ ] **Step 4: Write the upstream issue draft**

Create `docs/superpowers/notes/upstream-mail-parser-201.md` with this content. Replace the `<<INSERT BASE64 BLOCK HERE>>` marker with the contents of `/tmp/issue-201/crash.b64` before posting (we keep the marker in the committed file so a casual `git diff` does not get drowned in the base64 blob; reviewers can `cat /tmp/issue-201/crash.b64` to reconstitute it).

```markdown
# Upstream report: panic on crafted input in `parsers/message.rs:449`

**Target repo:** https://github.com/stalwartlabs/mail-parser
**Affected version:** `mail-parser 0.11.2` (current crates.io release; upstream `main` at the time of writing also reads `version = "0.11.2"`)
**Reporter context:** Discovered downstream in [randomparity/rusty-imap-mcp#201](https://github.com/randomparity/rusty-imap-mcp/issues/201) via `cargo fuzz`.

---

## Title

> Panic on crafted input: `range start index 9 out of range for slice of length 4` in `src/parsers/message.rs:449:67`

## Body

A coverage-guided fuzzer driving `MessageParser::default().parse(raw)` produced an input that panics inside `mail-parser-0.11.2`:

```
thread '<unnamed>' panicked at
mail-parser-0.11.2/src/parsers/message.rs:449:67:
range start index 9 out of range for slice of length 4
```

The panic is a slice-OOB on a small slice: it suggests a multi-byte unchecked read against a buffer that the parser previously narrowed to four bytes. The exact code path is on you to confirm; line 449 column 67 in the published 0.11.2 source on docs.rs is the indexing operation that triggers the panic.

### Possibly related

[stalwartlabs/mail-parser#120](https://github.com/stalwartlabs/mail-parser/issues/120) — "The library will panic with messages containing corrupted eml attachments". The stack-trace location is unconfirmed for that issue; it may or may not be the same root cause as the input below.

### Minimal reproducer

`Cargo.toml`:

```toml
[package]
name = "mail-parser-201-repro"
version = "0.0.0"
edition = "2021"

[dependencies]
mail-parser = "=0.11.2"
```

`src/main.rs`:

```rust
fn main() {
    // Crash bytes are committed to the rusty-imap-mcp repo at
    // crates/rimap-content/tests/data/mail_parser_panic_201.eml.
    // The base64 block below is the exact same bytes; sha1 of the
    // decoded bytes is 3dfef11827edd59b81f1ccc37ac16da62158472b
    // (libfuzzer-assigned crash filename).
    let raw = include_bytes!("../crash.bin");
    let _ = mail_parser::MessageParser::default().parse(raw);
    // Panics on 0.11.2:
    //   range start index 9 out of range for slice of length 4
    //   at mail-parser-0.11.2/src/parsers/message.rs:449:67
}
```

`crash.bin` (base64 of the raw crash bytes — decode with `base64 -d > crash.bin`):

```
<<INSERT BASE64 BLOCK HERE>>
```

### Reproduction steps

```bash
cargo new mail-parser-201-repro
cd mail-parser-201-repro
# replace Cargo.toml and src/main.rs with the snippets above
# create crash.bin from the base64 block above:
echo '<paste base64>' | base64 -d > crash.bin
cargo run
```

Expected: panic identical to the message at the top of this issue. Confirmed reproducing on `cargo 1.x stable` on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin` (both via `cargo fuzz` driving the same parse call).

### Downstream mitigation

We have wrapped the four `MessageParser::parse` call sites in our crate with `std::panic::catch_unwind(AssertUnwindSafe(...))` so a panic becomes a typed error rather than aborting the process. The fix is downstream-defensive — it does not patch the underlying bug, and any future `mail-parser` consumer that does not wrap will hit the same crash. We would much rather pull a fixed `mail-parser` than maintain the `catch_unwind` shim, so any patch you ship will let us drop ours.

### Environment

- `mail-parser`: 0.11.2 (crates.io)
- Discovered: 2026-04 via `cargo fuzz` against the public `MessageParser::default().parse` API
- Toolchain: stable 1.x, nightly for `cargo fuzz`

Happy to provide additional reproducers, a smaller minimised input if you need one, or to test patches on our fuzz corpus.
```

- [ ] **Step 5: Inline the base64 block before committing**

Replace the `<<INSERT BASE64 BLOCK HERE>>` marker in the file with the actual base64 from `/tmp/issue-201/crash.b64`:

```bash
# manually paste the contents of /tmp/issue-201/crash.b64 in place of the marker,
# OR run this in-place edit (preserves the surrounding fence and other content):
python3 - <<'PY'
import pathlib
notes = pathlib.Path("docs/superpowers/notes/upstream-mail-parser-201.md")
b64 = pathlib.Path("/tmp/issue-201/crash.b64").read_text().rstrip()
text = notes.read_text().replace("<<INSERT BASE64 BLOCK HERE>>", b64)
notes.write_text(text)
PY
```

Verify the base64 round-trips back to the original bytes:

```bash
sed -n '/^```$/,$p' docs/superpowers/notes/upstream-mail-parser-201.md \
  | sed -n '/^```$/,$p' \
  | head -200 \
  | base64 -d \
  | shasum -a 1
```

Expected: `3dfef11827edd59b81f1ccc37ac16da62158472b`. (The `sed`-based extract is fragile across editors — if it does not match, manually extract the base64 block to a file, decode, and verify.)

- [ ] **Step 6: Commit the upstream report draft**

```bash
git add docs/superpowers/notes/upstream-mail-parser-201.md
git commit -m "$(cat <<'EOF'
docs(notes): draft upstream report for stalwartlabs/mail-parser

Versioned draft of the issue text we will post against
stalwartlabs/mail-parser, documenting the parsers/message.rs:449:67
panic on crafted input. Includes minimal reproducer (Cargo.toml +
src/main.rs) and the crash bytes embedded as base64.

Posting the issue itself is a manual follow-up step.

Refs: #201

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Final verification and PR

**Files:** none (verification only)

- [ ] **Step 1: Run the full workspace test suite**

```bash
cargo test --workspace --all-features
```

Expected: all tests pass.

- [ ] **Step 2: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean across every crate.

- [ ] **Step 3: Run cargo deny**

```bash
cargo deny check
```

Expected: clean. The new `tracing`/`sha2`/`hex` deps in `rimap-content` are workspace-pinned and already vetted by sibling crates.

- [ ] **Step 4: Run cargo machete to confirm no unused deps slipped in**

```bash
cargo machete
```

Expected: no findings against `rimap-content`. (The Task 1 transient state is now resolved — `tracing`, `sha2`, and `hex` are all consumed by `safe_parser.rs`.)

- [ ] **Step 5: Run cargo audit**

```bash
cargo audit
```

Expected: no advisories against the crates this branch touches.

- [ ] **Step 6: Push the branch and open a PR**

```bash
git push -u origin fix/issue-201-mail-parser-panic
gh pr create --title "fix(rimap-content): isolate mail-parser panics behind catch_unwind (#201)" --body "$(cat <<'EOF'
## Summary

- Wrap every `mail_parser::MessageParser::parse` call site in `rimap-content` with `catch_unwind(AssertUnwindSafe(...))` via a new internal `safe_parser::safe_parse` helper.
- Add `ContentError::ParserPanic` variant so audit/alerting can distinguish "third-party parser panicked on input" from ordinary `Malformed` rejections.
- Pin the regression to the artifact-recovered crash bytes from PR #200's fuzz run; commit them as `crates/rimap-content/tests/data/mail_parser_panic_201.eml` and seed the fuzz corpus at `fuzz/corpus/content_mime/mail_parser_panic_201`.
- Draft the upstream report at `docs/superpowers/notes/upstream-mail-parser-201.md` with full minimal reproducer.

Closes #201.

## Why catch_unwind, not upgrade

`mail-parser` 0.11.2 is the current crates.io release and matches upstream `main`. There is no patched release to upgrade to. The `catch_unwind` shim is a defensive long-term posture regardless of an upstream fix — any future panic in upstream parser code is automatically caught at the `rimap-content` boundary.

## Test plan

- [x] `cargo test -p rimap-content` — all four entry points covered by `tests/parser_panic_safety.rs`
- [x] `cargo test --workspace --all-features` — no regressions
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [x] `cargo fuzz run content_mime corpus/content_mime/mail_parser_panic_201 -- -runs=1` — clean exit
- [x] `cargo fuzz run content_mime -- -runs=10000 -max_total_time=60` — no new crashes
- [ ] Post the upstream report from `docs/superpowers/notes/upstream-mail-parser-201.md` (manual follow-up after merge)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR URL printed; CI begins on the branch.

- [ ] **Step 7: Confirm CI is green**

```bash
gh pr checks --watch
```

Expected: every required check (build, test, fuzz smoke, clippy, deny, audit) goes green. If a check fails, address the failure on the same branch and re-push.

- [ ] **Step 8: Manual post-merge follow-up (not part of this branch)**

After the PR merges, file the upstream issue using the text in `docs/superpowers/notes/upstream-mail-parser-201.md`. Capture the upstream issue number in a comment on our #201 so the cross-link is durable.
