# Sprint B1: rimap-content Fuzz + Mutation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land four `cargo-fuzz` harnesses on the `rimap-content` trust boundary, refresh `cargo-mutants` against current `main`, kill every surviving mutant in non-binary code, and wire ClusterFuzzLite into CI for PR-smoke + nightly fuzzing.

**Architecture:** New top-level `fuzz/` directory (workspace-excluded) holds the `cargo-fuzz` crate with four targets. Two private functions inside `rimap-content` (`html::sanitize_html`, `parse::mime_scrub::scrub_header_smuggling`) get re-exported under the existing `test-util` feature so the fuzz crate can call them without duplicating the upper-layer machinery. Mutation cleanup proceeds module-by-module after a fresh baseline run; survivors that are equivalent mutants get inline annotations rather than fixes. CI gets a new `.github/workflows/fuzz.yml` driving ClusterFuzzLite for PR smoke (10 min) and nightly cron (60 min).

**Tech Stack:** `cargo-fuzz` (nightly-only), `libfuzzer-sys`, `cargo-mutants` 25.x, `ClusterFuzzLite` (Google), `actionlint`, `zizmor`, GitHub Actions on `ubuntu-24.04`.

**Spec reference:** [`docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`](../specs/2026-04-30-test-strategy-improvements-design.md), Sprint B1 — Section 4.

**Branch:** `feat/test-strategy-b1-rimap-content` (cut from current `main` after this plan's PR lands).

---

## Pre-flight

Confirm the working branch isn't `main`/`master`, the worktree is clean, and the local toolchain is ready.

- [ ] **Step 0: Verify branch, clean state, and tooling**

Run:
```bash
git branch --show-current
git status --short
which actionlint zizmor cargo-mutants
rustup toolchain list | grep -F nightly
cargo install --list 2>/dev/null | grep -E "cargo-fuzz|cargo-mutants"
```

Expected:
- `git branch --show-current` prints `feat/test-strategy-b1-rimap-content` (NOT `main`). If on `main`, stop and create the branch: `git checkout -b feat/test-strategy-b1-rimap-content`.
- `git status --short` is empty.
- `actionlint`, `zizmor`, `cargo-mutants` are on PATH. Install missing tools per the global `~/.claude/CLAUDE.md` "CLI tools" table or `just setup`.
- A `nightly-*` toolchain is listed. If not, run `rustup toolchain install nightly --component rust-src`.
- `cargo-fuzz` and `cargo-mutants` are listed. If not, run `cargo install --locked cargo-fuzz cargo-mutants`.

---

## Task 1: Scaffold the `fuzz/` workspace member

**Why:** `cargo-fuzz` needs a standalone Cargo crate with a known directory layout (`fuzz/Cargo.toml` + `fuzz/fuzz_targets/`). The repo workspace must explicitly exclude it because `libfuzzer-sys` is nightly-only and must not be pulled into stable workspace builds.

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/.gitignore`
- Create: `fuzz/fuzz_targets/.gitkeep` (placeholder, removed by Task 3)
- Modify: `Cargo.toml` (workspace root, add `exclude = ["fuzz"]`)
- Modify: `justfile` (add `fuzz`, `fuzz-list` recipes)

- [ ] **Step 1: Create the fuzz crate manifest**

Create `fuzz/Cargo.toml`:
```toml
[package]
name = "rusty-imap-mcp-fuzz"
version = "0.0.0"
publish = false
edition = "2024"
rust-version = "1.94.0"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[dependencies.rimap-content]
path = "../crates/rimap-content"
features = ["test-util"]

[dependencies.rimap-audit]
path = "../crates/rimap-audit"

[dependencies.rimap-server]
path = "../crates/rimap-server"

# Targets are added in later tasks. Until at least one fuzz target exists,
# `cargo +nightly fuzz list` returns an empty list, which is correct.

[workspace]
# Standalone — not part of the rusty-imap-mcp workspace because
# libfuzzer-sys is nightly-only and the workspace stable build must
# not pull it in.
```

`rimap-audit` and `rimap-server` deps are declared up front so the manifest does not churn each time a future sprint adds a target. They have zero cost when no target consumes them.

- [ ] **Step 2: Create the fuzz-crate gitignore**

Create `fuzz/.gitignore`:
```
target/
Cargo.lock
artifacts/
coverage/
```

`corpus/` is **not** gitignored — seed corpora are version-controlled.

- [ ] **Step 3: Create a placeholder so the directory tracks**

Create empty `fuzz/fuzz_targets/.gitkeep` (it's removed in Task 3 when the first real target lands).

- [ ] **Step 4: Exclude the fuzz crate from the workspace**

Edit `Cargo.toml` (workspace root). Find the `[workspace]` section and add the `exclude` key:

```toml
[workspace]
resolver = "2"
members = [
    "crates/rimap-core",
    "crates/rimap-config",
    "crates/rimap-imap",
    "crates/rimap-content",
    "crates/rimap-audit",
    "crates/rimap-authz",
    "crates/rimap-smtp",
    "crates/rimap-server",
]
exclude = ["fuzz"]
```

If `members = [...]` already exists, add only the `exclude = ["fuzz"]` line beneath it. Do not duplicate the `[workspace]` heading.

- [ ] **Step 5: Add `fuzz` recipes to the justfile**

Edit `justfile`. Find the `test-injection` recipe and insert immediately after it:

```make
# Run a single fuzz target for a fixed time budget. Requires nightly.
# Example: just fuzz content_mime
fuzz TARGET *ARGS:
    cd fuzz && cargo +nightly fuzz run {{TARGET}} -- -max_total_time=30 {{ARGS}}

# List the available fuzz targets.
fuzz-list:
    cd fuzz && cargo +nightly fuzz list
```

- [ ] **Step 6: Verify the workspace still builds**

Run:
```bash
cargo check --workspace --locked --all-targets
```

Expected: clean exit. The `fuzz/` directory must not be picked up by `--workspace` (verifies `exclude = ["fuzz"]` works). If `cargo check` errors on `libfuzzer-sys` or anything in `fuzz/`, the exclude is wrong — re-check Step 4.

- [ ] **Step 7: Verify the fuzz crate builds standalone on nightly**

Run:
```bash
cd fuzz && cargo +nightly check
```

Expected: clean exit. (The crate has no targets yet but the manifest must parse.)

Return to repo root: `cd ..`.

- [ ] **Step 8: Verify `just fuzz-list` runs (returns empty list)**

Run:
```bash
just fuzz-list
```

Expected: empty output (no targets yet) or a message like `<empty>`. The command must exit 0.

- [ ] **Step 9: Commit**

```bash
git add fuzz/Cargo.toml fuzz/.gitignore fuzz/fuzz_targets/.gitkeep Cargo.toml justfile
git commit -m "test(fuzz): scaffold cargo-fuzz workspace member

Add an excluded-from-workspace fuzz/ crate so future tasks can land
cargo-fuzz harnesses without contaminating the stable workspace
build with libfuzzer-sys (nightly-only).

Adds 'just fuzz <target>' and 'just fuzz-list' for local invocation.
Sprint B1 of the test-strategy-improvements plan.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 2: Expose `rimap-content` private entry points under `test-util`

**Why:** Two of the four fuzz targets need to call functions that are currently `pub(crate)` or `pub(super)` inside `rimap-content`. Re-exporting them under the existing `test-util` feature keeps the production API surface unchanged and matches the `epvme_runner`/dev-dep precedent already in `crates/rimap-content/Cargo.toml`.

**Files:**
- Modify: `crates/rimap-content/src/parse/mod.rs` (bump `mod mime_scrub` visibility to `pub(crate)`)
- Modify: `crates/rimap-content/src/parse/mime_scrub.rs` (bump `scrub_header_smuggling` from `pub(super)` to `pub(crate)`)
- Modify: `crates/rimap-content/src/testutil.rs` (re-export the two functions plus a small helper struct)
- Test: a single doc-tested use site in `testutil.rs` that proves the re-exports compile.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/rimap-content/src/testutil.rs` (existing file — preserve everything already there):

```rust
#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod test_util_reexports {
    use crate::output::SecurityWarning;

    #[test]
    fn fuzz_entries_are_callable_via_testutil() {
        // sanitize_html: minimal HTML body should round-trip without panic.
        let result = super::sanitize_html(b"<p>hi</p>", Some("utf-8"))
            .expect("sanitize_html on minimal HTML must succeed");
        assert!(!result.body_text.is_empty());

        // scrub_header_smuggling: a clean encoded-word produces no warnings.
        let mut warnings: Vec<SecurityWarning> = Vec::new();
        let raw = b"Subject: =?utf-8?B?aGVsbG8=?=\r\n\r\nbody";
        let scrubbed = super::scrub_header_smuggling(raw, &mut warnings);
        assert!(warnings.is_empty(), "clean encoded word should not warn");
        assert!(!scrubbed.is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails (compile error)**

Run:
```bash
cargo test --package rimap-content --features test-util test_util_reexports -- --nocapture
```

Expected: compile error with `cannot find function 'sanitize_html' in this scope` (or similar) — proves the re-exports don't exist yet.

- [ ] **Step 3: Bump module visibility for `mime_scrub`**

Edit `crates/rimap-content/src/parse/mod.rs`. Find this line:
```rust
mod mime_scrub;
```

Change to:
```rust
pub(crate) mod mime_scrub;
```

- [ ] **Step 4: Bump function visibility for `scrub_header_smuggling`**

Edit `crates/rimap-content/src/parse/mime_scrub.rs`. Find this line:
```rust
pub(super) fn scrub_header_smuggling(raw: &[u8], warnings: &mut Vec<SecurityWarning>) -> Vec<u8> {
```

Change to:
```rust
pub(crate) fn scrub_header_smuggling(raw: &[u8], warnings: &mut Vec<SecurityWarning>) -> Vec<u8> {
```

The other `pub(super)` function in the same file (`detect_smuggling_spans`) is intentionally left at its current visibility — only `scrub_header_smuggling` is needed by the fuzz target.

- [ ] **Step 5: Add the re-exports to `testutil.rs`**

Open `crates/rimap-content/src/testutil.rs`. At the top of the file (after the existing module-level doc comment and any existing `use` statements), add:

```rust
/// Re-export of [`crate::html::sanitize_html`] for fuzz harnesses and
/// out-of-tree integration tests. Production code must continue to
/// reach `sanitize_html` through the [`crate::parse::parse_message`]
/// pipeline.
pub use crate::html::sanitize_html;

/// Re-export of [`crate::parse::mime_scrub::scrub_header_smuggling`]
/// for fuzz harnesses. Production code reaches this function through
/// [`crate::parse::parse_message`].
pub use crate::parse::mime_scrub::scrub_header_smuggling;

/// Re-export of [`crate::html::HtmlResult`] so external callers of the
/// re-exported `sanitize_html` can name the return type.
pub use crate::html::HtmlResult;
```

- [ ] **Step 6: Make `HtmlResult` `pub(crate)`-visible**

Open `crates/rimap-content/src/html/mod.rs`. Find the `HtmlResult` struct declaration (around line 30):

```rust
#[derive(Debug, Clone)]
pub(crate) struct HtmlResult {
```

It's already `pub(crate)`, so no edit is needed — but verify by running:
```bash
grep -n "pub(crate) struct HtmlResult\|pub struct HtmlResult\|struct HtmlResult" crates/rimap-content/src/html/mod.rs
```

Expected: exactly one line, `pub(crate) struct HtmlResult {`. If the visibility is different, change it to `pub(crate)`.

- [ ] **Step 7: Run test to verify it passes**

Run:
```bash
cargo test --package rimap-content --features test-util test_util_reexports -- --nocapture
```

Expected: PASS. The test calls `super::sanitize_html` and `super::scrub_header_smuggling` and both compile + execute.

- [ ] **Step 8: Run the full rimap-content test suite to confirm no regressions**

Run:
```bash
cargo nextest run --package rimap-content --all-features --locked
```

Expected: every test passes (the change is visibility-only, no behavioral change).

- [ ] **Step 9: Run clippy on the workspace**

Run:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: clean exit. The visibility bump must not trip any pedantic lint.

- [ ] **Step 10: Commit**

```bash
git add crates/rimap-content/src/parse/mod.rs \
        crates/rimap-content/src/parse/mime_scrub.rs \
        crates/rimap-content/src/testutil.rs
git commit -m "test(rimap-content): expose sanitize_html and scrub_header_smuggling under test-util

The B1 fuzz harnesses for HTML and RFC 2047 header smuggling need
to call these two functions directly. Re-export them through the
existing test-util feature gate so production callers still reach
them only via parse_message().

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 3: `content_mime` fuzz harness

**Why:** Whole-message MIME parse is the highest-value entry point — the v1 spec calls it the #1 attacker surface. A coverage-guided fuzzer explores edge cases that proptest's structured-string generation will not find.

**Files:**
- Delete: `fuzz/fuzz_targets/.gitkeep`
- Create: `fuzz/fuzz_targets/content_mime.rs`
- Create: `fuzz/corpus/content_mime/` (seeded from existing corpora — see Step 4)
- Modify: `fuzz/Cargo.toml` (register the target)

- [ ] **Step 1: Register the target in `fuzz/Cargo.toml`**

Edit `fuzz/Cargo.toml`. Append (after the `[workspace]` block at the very end):

```toml

[[bin]]
name = "content_mime"
path = "fuzz_targets/content_mime.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Write the harness**

Create `fuzz/fuzz_targets/content_mime.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Drive the public entry point. parse_message must:
    //   - never panic
    //   - reject input over MAX_MESSAGE_BYTES with a clean LimitExceeded error
    //   - never allocate beyond the configured per-part / total caps
    //
    // Crashes/panics surface as libfuzzer findings. Resource caps are
    // verified by the existing unit tests in parse/mod.rs; the fuzzer's
    // job is to find the inputs that bypass those caps.
    let _ = rimap_content::parse_message(data);
});
```

The harness intentionally discards the `Result`. A successful parse, a `ContentError::LimitExceeded`, and a `ContentError::Malformed` are all valid outcomes; the harness asserts only that *some* outcome is reached without panic, OOM, or stack overflow.

- [ ] **Step 3: Remove the placeholder**

Run:
```bash
rm fuzz/fuzz_targets/.gitkeep
```

- [ ] **Step 4: Seed the corpus from the adversarial fixture set**

Run:
```bash
mkdir -p fuzz/corpus/content_mime
# 25 adversarial fixtures
for d in tests/injection-corpus/*/; do
    name=$(basename "$d")
    cp "$d/input.eml" "fuzz/corpus/content_mime/${name}.eml"
done
# 3 dovecot integration fixtures
cp crates/rimap-imap/tests/integration/dovecot/fixtures/plain.eml      fuzz/corpus/content_mime/dovecot-plain.eml
cp crates/rimap-imap/tests/integration/dovecot/fixtures/multipart.eml  fuzz/corpus/content_mime/dovecot-multipart.eml
cp crates/rimap-imap/tests/integration/dovecot/fixtures/attachment.eml fuzz/corpus/content_mime/dovecot-attachment.eml
ls fuzz/corpus/content_mime | wc -l
```

Expected: `28` (25 injection-corpus + 3 dovecot fixtures). If less, an entry in `tests/injection-corpus/` is missing its `input.eml` — investigate before moving on.

- [ ] **Step 5: Verify the harness builds on nightly**

Run:
```bash
cd fuzz && cargo +nightly fuzz build content_mime && cd ..
```

Expected: clean build. Errors typically come from a missing feature flag on `rimap-content` (the `test-util` feature must be enabled in `fuzz/Cargo.toml` — Task 1 Step 1 set this up).

- [ ] **Step 6: Run the harness for 60 seconds, no crash**

Run:
```bash
cd fuzz && cargo +nightly fuzz run content_mime -- -max_total_time=60 && cd ..
```

Expected: 60 seconds of fuzzing with no crash. libfuzzer prints stats every few seconds; on completion it logs `Done $time runs in $time second(s)`. Any crash, abort, or hang is an unexpected finding — stop and triage before proceeding (a panic in `parse_message` is a real bug).

- [ ] **Step 7: Verify the corpus was traversed**

Inspect the libfuzzer stats from Step 6's output. The line beginning `INITED` should report `corpus:` greater than or equal to 28 (the seeded count). If it reports `corpus: 0`, the seed corpus was not found — verify `fuzz/corpus/content_mime/` exists relative to the `cd fuzz` working directory.

- [ ] **Step 8: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets/content_mime.rs fuzz/corpus/content_mime/
git rm fuzz/fuzz_targets/.gitkeep
git commit -m "test(fuzz): add content_mime harness for parse_message

Drives rimap_content::parse_message on raw bytes. Seeded with the 25
adversarial fixtures from tests/injection-corpus and the 3 dovecot
integration fixtures (28 seeds total).

Asserts: no panic on any input; resource limits in parse::limits are
the only enforcement (the fuzzer's job is to find inputs that bypass
them). Resource-limit unit tests live in parse/mod.rs already.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 4: `content_html` fuzz harness

**Why:** The HTML sanitizer has its own attack surface (DOM-tree traversal, ammonia filtering, link extraction) distinct from the MIME parser. The existing proptest harness uses structured string generation; libfuzzer's coverage-guided exploration finds different bugs.

**Files:**
- Create: `fuzz/fuzz_targets/content_html.rs`
- Create: `fuzz/corpus/content_html/` (extract HTML bodies from fixtures)
- Modify: `fuzz/Cargo.toml` (register the target)

- [ ] **Step 1: Register the target**

Edit `fuzz/Cargo.toml`. After the `content_mime` `[[bin]]` block, append:

```toml

[[bin]]
name = "content_html"
path = "fuzz_targets/content_html.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Write the harness**

Create `fuzz/fuzz_targets/content_html.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // sanitize_html(raw: &[u8], charset: Option<&str>) -> Result<HtmlResult, ContentError>
    //
    // The fuzzer drives both arguments. The first byte (modulo a small
    // table) selects a charset label so the input space includes
    // realistic charset routing; the rest is the body.
    if data.is_empty() {
        return;
    }
    let charset = match data[0] % 5 {
        0 => None,
        1 => Some("utf-8"),
        2 => Some("iso-8859-1"),
        3 => Some("windows-1252"),
        _ => Some("us-ascii"),
    };
    let body = &data[1..];
    let _ = rimap_content::testutil::sanitize_html(body, charset);
});
```

The harness uses the `test-util` re-export (`rimap_content::testutil::sanitize_html`), which is the path Task 2 made public.

- [ ] **Step 3: Seed the corpus**

A small-scale extraction script. Run:

```bash
mkdir -p fuzz/corpus/content_html

# Extract HTML bodies from injection-corpus fixtures. Each .eml may have
# zero or more text/html parts; this naive extractor pulls anything
# between a "Content-Type: text/html" line and the next blank line +
# next part boundary. It's a seed-corpus seeder — fidelity is irrelevant,
# diversity matters.
python3 - <<'EOF'
import email
import os
import pathlib

src_dir = pathlib.Path("tests/injection-corpus")
out_dir = pathlib.Path("fuzz/corpus/content_html")

for case in sorted(src_dir.iterdir()):
    eml = case / "input.eml"
    if not eml.is_file():
        continue
    try:
        msg = email.message_from_bytes(eml.read_bytes())
    except Exception:
        continue
    idx = 0
    for part in msg.walk():
        if part.get_content_type() != "text/html":
            continue
        payload = part.get_payload(decode=True) or b""
        if not payload.strip():
            continue
        out = out_dir / f"{case.name}-{idx}.html"
        out.write_bytes(b"\x01" + payload)  # leading byte chooses charset
        idx += 1
EOF

ls fuzz/corpus/content_html | wc -l
```

Expected: at least 5 files. (Not every fixture has an HTML part; expect roughly 8–12.) If 0 files, the extractor failed silently — re-run interactively.

- [ ] **Step 4: Add a hand-crafted floor of edge cases**

Run:
```bash
cat > fuzz/corpus/content_html/empty.html <<'EOF'
EOF

printf '\x01<html></html>'                                 > fuzz/corpus/content_html/empty-doc.html
printf '\x01<script>x</script>'                            > fuzz/corpus/content_html/script-only.html
printf '\x01<style>.x{}</style>'                           > fuzz/corpus/content_html/style-only.html
printf '\x01<a href="http://e.com">x</a>'                  > fuzz/corpus/content_html/anchor.html
printf '\x01<a href="javascript:alert(1)">x</a>'           > fuzz/corpus/content_html/js-href.html
printf '\x01<img src="https://tracker.example/p.gif">'     > fuzz/corpus/content_html/remote-img.html
printf '\x01<div style="display:none">hidden</div>'        > fuzz/corpus/content_html/hidden.html
printf '\x01<p style="color:white;background:white">w</p>' > fuzz/corpus/content_html/white-on-white.html
printf '\x01<p>%s</p>' "$(printf 'A%.0s' {1..2000})"        > fuzz/corpus/content_html/long-text.html

ls fuzz/corpus/content_html | wc -l
```

Expected: at least 14 files (5 extracted + 9 hand-crafted edge cases). The leading `\x01` byte selects `Some("utf-8")` per the harness's charset-mux at Step 2.

- [ ] **Step 5: Build and run for 60 seconds**

Run:
```bash
cd fuzz && cargo +nightly fuzz build content_html && \
  cargo +nightly fuzz run content_html -- -max_total_time=60 && cd ..
```

Expected: clean build, 60 seconds of fuzzing, no crash.

- [ ] **Step 6: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets/content_html.rs fuzz/corpus/content_html/
git commit -m "test(fuzz): add content_html harness for sanitize_html

Drives the HTML→text sanitizer on raw bytes with a fuzzer-chosen
charset label (5-way mux off the first byte). Seed corpus extracts
HTML parts from tests/injection-corpus plus 9 hand-crafted edge
cases (empty, script-only, javascript: hrefs, remote images,
hidden/white-on-white, long bodies).

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 5: `content_rfc2047` fuzz harness

**Why:** The RFC 2047 encoded-word path is a known attack surface — `tests/injection-corpus/rfc2047-crlf-smuggling/` documents that a maliciously-encoded `=?...?=` token can carry CRLF bytes that splice unintended headers into the message. The smuggling-detection function `scrub_header_smuggling` is the load-bearing defense.

**Files:**
- Create: `fuzz/fuzz_targets/content_rfc2047.rs`
- Create: `fuzz/corpus/content_rfc2047/`
- Modify: `fuzz/Cargo.toml`

- [ ] **Step 1: Register the target**

Edit `fuzz/Cargo.toml`. Append:

```toml

[[bin]]
name = "content_rfc2047"
path = "fuzz_targets/content_rfc2047.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Write the harness**

Create `fuzz/fuzz_targets/content_rfc2047.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_content::output::SecurityWarning;

fuzz_target!(|data: &[u8]| {
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = rimap_content::testutil::scrub_header_smuggling(data, &mut warnings);

    // Invariant: the scrubbed output never contains a bare LF inside an
    // encoded-word run. (CRLF sequences are normal header continuation;
    // bare LF inside =?...?= is the smuggling signal that must have been
    // removed.) The function's contract is to either remove the smuggled
    // bytes or emit a SecurityWarning::HeaderSmuggling — the harness
    // asserts the *output* never carries the attack pattern when no
    // warning was raised.
    if warnings.is_empty() {
        let mut in_eword = false;
        let mut prev = 0u8;
        for &b in &scrubbed {
            if !in_eword && b == b'=' {
                // peek not available; track via state.
            }
            if b == b'?' && prev == b'=' {
                in_eword = true;
            }
            if in_eword && b == b'\n' && prev != b'\r' {
                panic!("bare LF inside encoded-word slipped through scrub_header_smuggling");
            }
            if b == b'=' && prev == b'?' {
                in_eword = false;
            }
            prev = b;
        }
    }
});
```

This is a stronger assertion than the other harnesses — `content_rfc2047` actively probes a known bug class. If a future change to the scrubber regresses, the harness panics and libfuzzer flags it as a finding.

- [ ] **Step 3: Seed the corpus from the existing CRLF-smuggling fixture**

Run:
```bash
mkdir -p fuzz/corpus/content_rfc2047

# The dedicated fixture for this attack class
cp tests/injection-corpus/rfc2047-crlf-smuggling/input.eml \
   fuzz/corpus/content_rfc2047/known-attack.eml

# A handful of clean RFC 2047 encoded-words
printf 'Subject: =?utf-8?B?aGVsbG8=?=\r\n\r\nbody'  > fuzz/corpus/content_rfc2047/clean-b64.eml
printf 'Subject: =?utf-8?Q?hello?=\r\n\r\nbody'     > fuzz/corpus/content_rfc2047/clean-q.eml
printf 'Subject: plain text\r\n\r\nbody'             > fuzz/corpus/content_rfc2047/no-eword.eml
printf 'Subject: =?utf-8?B?\r\nbody'                 > fuzz/corpus/content_rfc2047/truncated.eml
printf 'Subject: =?\r\n\r\nbody'                     > fuzz/corpus/content_rfc2047/dangling-open.eml
printf 'Subject: ?=\r\n\r\nbody'                     > fuzz/corpus/content_rfc2047/dangling-close.eml

ls fuzz/corpus/content_rfc2047 | wc -l
```

Expected: 7 files.

- [ ] **Step 4: Build and run for 60 seconds**

Run:
```bash
cd fuzz && cargo +nightly fuzz build content_rfc2047 && \
  cargo +nightly fuzz run content_rfc2047 -- -max_total_time=60 && cd ..
```

Expected: clean build, 60 seconds of fuzzing, no crash. **If the harness panics with the bare-LF assertion**, this is a real bug — stop and file an issue before proceeding.

- [ ] **Step 5: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets/content_rfc2047.rs fuzz/corpus/content_rfc2047/
git commit -m "test(fuzz): add content_rfc2047 harness for header smuggling scrubber

Drives scrub_header_smuggling on raw bytes; asserts that any output
emitted without an accompanying SecurityWarning never contains a
bare LF inside an encoded-word run (the CRLF-smuggling attack class
documented in tests/injection-corpus/rfc2047-crlf-smuggling).

Seed corpus: known-attack fixture + 6 hand-crafted edge cases.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 6: `content_charset` fuzz harness

**Why:** Charset label parsing has historically been a source of bugs in mail clients. `unicode::decode(bytes, charset_label)` is the entry point that turns server-controlled label strings into encoding decisions; a panic here is a remote DoS vector.

**Files:**
- Create: `fuzz/fuzz_targets/content_charset.rs`
- Create: `fuzz/corpus/content_charset/`
- Modify: `fuzz/Cargo.toml`

- [ ] **Step 1: Register the target**

Edit `fuzz/Cargo.toml`. Append:

```toml

[[bin]]
name = "content_charset"
path = "fuzz_targets/content_charset.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Write the harness**

Create `fuzz/fuzz_targets/content_charset.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Wire format: first byte = label length L (0..=63), next L bytes = label
    // (UTF-8 if valid, otherwise None), remainder = bytes to decode.
    if data.is_empty() {
        return;
    }
    let label_len = (data[0] & 0x3f) as usize;
    if 1 + label_len > data.len() {
        return;
    }
    let label_bytes = &data[1..1 + label_len];
    let body = &data[1 + label_len..];

    let label = std::str::from_utf8(label_bytes).ok();
    let _ = rimap_content::unicode::decode(body, label);
});
```

The wire-format split (length-prefixed label + body) gives libfuzzer a structured input space without needing a custom mutator.

- [ ] **Step 3: Seed the corpus with charset+bytes pairs**

Run (Python — bash heredocs cannot reliably emit a leading length byte):
```bash
mkdir -p fuzz/corpus/content_charset

python3 - <<'PY'
import pathlib

OUT = pathlib.Path("fuzz/corpus/content_charset")

def seed(name: str, label: str, body: bytes) -> None:
    label_bytes = label.encode("utf-8")
    assert len(label_bytes) <= 0x3f, f"label {label!r} exceeds 6-bit length cap"
    payload = bytes([len(label_bytes)]) + label_bytes + body
    (OUT / name).write_bytes(payload)

# encoding_rs's named set, sampled across script families. The fuzzer
# will explore from these seeds; the goal is breadth, not exhaustiveness.
SEEDS = [
    # ASCII-superset Latin
    ("utf8-ascii",        "utf-8",         b"hello world"),
    ("utf8-emoji",        "utf-8",         b"\xf0\x9f\x98\x80"),  # U+1F600
    ("utf8-bom",          "utf-8",         b"\xef\xbb\xbfhello"),
    ("utf8-overlong",     "utf-8",         b"\xc0\x80"),
    ("utf8-truncated",    "utf-8",         b"\xc3"),
    ("utf8-invalid",      "utf-8",         b"\xff\xfe\xfd"),
    ("ascii",             "us-ascii",      b"plain"),
    ("iso8859-1",         "iso-8859-1",    b"\xa3 sterling"),
    ("iso8859-2",         "iso-8859-2",    b"\xb1\xc4"),
    ("iso8859-15",        "iso-8859-15",   b"\xa4 euro"),
    ("windows-1250",      "windows-1250",  b"\xa1\xa3"),
    ("windows-1251",      "windows-1251",  b"\xc0\xc1\xc2"),
    ("windows-1252",      "windows-1252",  b"\x80 euro"),
    ("windows-1255",      "windows-1255",  b"\xe0\xe1"),
    ("macintosh",         "macintosh",     b"\xc7\xb1"),
    # CJK
    ("shift-jis",         "shift_jis",     b"\x82\xa0"),
    ("euc-jp",            "euc-jp",        b"\xa4\xa2"),
    ("iso-2022-jp",       "iso-2022-jp",   b"\x1b$B$\"\x1b(B"),
    ("euc-kr",            "euc-kr",        b"\xb0\xa1"),
    ("big5",              "big5",          b"\xa5\x40"),
    ("gb18030",           "gb18030",       b"\xa1\xa1"),
    ("gbk",               "gbk",           b"\xb0\xa1"),
    # Cyrillic
    ("koi8-r",            "koi8-r",        b"\xc1\xc2\xc3"),
    ("koi8-u",            "koi8-u",        b"\xa4\xa6"),
    # Empty
    ("utf8-empty",        "utf-8",         b""),
    ("empty-empty",       "",              b""),
    ("empty-body",        "us-ascii",      b""),
    # Garbage labels
    ("garbage-1",         "not-a-charset", b"anything"),
    ("garbage-2",         "x-mac-vendor",  b"data"),
    ("garbage-3",         "   ",           b"spaces"),
    ("garbage-4",         "UTF-8 ",        b"trailing space"),
    ("garbage-5",         "utf_8",         b"underscore"),
    # Mismatch (declared label, payload from a different encoding)
    ("mismatch-1",        "utf-8",         b"\xa3 sterling"),
    ("mismatch-2",        "iso-8859-1",    b"\xf0\x9f\x98\x80"),
]

for name, label, body in SEEDS:
    seed(name, label, body)

print(len(SEEDS))
PY

ls fuzz/corpus/content_charset | wc -l
```

Expected: `34` printed by Python, and `34` from `ls | wc -l`. If the count differs, the Python script aborted partway — re-run interactively.

- [ ] **Step 4: Build and run for 60 seconds**

Run:
```bash
cd fuzz && cargo +nightly fuzz build content_charset && \
  cargo +nightly fuzz run content_charset -- -max_total_time=60 && cd ..
```

Expected: clean build, 60 seconds of fuzzing, no crash.

- [ ] **Step 5: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets/content_charset.rs fuzz/corpus/content_charset/
git commit -m "test(fuzz): add content_charset harness for unicode::decode

Drives unicode::decode with length-prefixed (label, bytes) pairs.
Seed corpus covers common charsets (utf-8, iso-8859-1, windows-1252,
shift_jis, koi8-r, big5, gb18030), empty bodies, garbage labels, and
invalid byte sequences for utf-8 (lone surrogates, overlong forms).

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 7: Refresh `cargo-mutants` baseline on `rimap-content`

**Why:** The current `mutants.out/` snapshot is from 2026-04-08 and predates `desloppify`/BootError/rotation-clock-seam landings. The 67 reported survivors in non-`bin/` code are the starting list — but we must refresh first to filter false positives caused by code that has since changed.

**Files:**
- Create: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Run the targeted mutation suite**

Run:
```bash
cargo mutants --package rimap-content --no-shuffle 2>&1 | tee /tmp/mutants-rimap-content.log
```

Expected runtime: 30–90 minutes depending on host. The command prints a per-mutant outcome (`caught`, `missed`, `unviable`, `timeout`). Output is also written to `mutants.out/`.

- [ ] **Step 2: Snapshot the survivors**

Run:
```bash
mkdir -p docs/superpowers/specs/test-strategy
SURVIVORS=$(grep -E "^crates/rimap-content/src/[^b]" mutants.out/missed.txt | grep -v "^crates/rimap-content/src/bin/" | wc -l | tr -d ' ')
echo "Surviving mutants outside src/bin/: $SURVIVORS"
grep -E "^crates/rimap-content/src/" mutants.out/missed.txt | grep -v "^crates/rimap-content/src/bin/" > /tmp/rimap-content-survivors.txt
wc -l /tmp/rimap-content-survivors.txt
```

If the survivor count is **> 30**, stop and write a follow-up plan: B1's mutation cleanup is scoped to "manageable inline cleanup," and >30 is the cap that signals the work warrants its own plan. Document the count in the commit message and skip Tasks 8–9 in this PR; the fuzz harnesses + ClusterFuzzLite still ship in this sprint.

If the survivor count is ≤ 30, proceed.

- [ ] **Step 3: Write the baseline document**

Create `docs/superpowers/specs/test-strategy/mutation-baseline.md`:

````markdown
# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** YYYY-MM-DD (replace with today's date)
**Tool:** `cargo-mutants` (run via `just mutants-crate <name>`)
**Scope:** Five trust-boundary crates — `rimap-content`, `rimap-authz`,
`rimap-audit`, `rimap-server`, `rimap-imap`. Other workspace crates are
out of scope per spec
[`2026-04-30-test-strategy-improvements-design.md`](../2026-04-30-test-strategy-improvements-design.md).

A survivor is recorded here when it is *not* a true bug in the test suite —
either because the mutation is mathematically equivalent to the original
code, or because it falls in a code path the spec explicitly classifies as
"plumbing, best-effort." Survivors that *are* test-suite gaps are killed by
adding a test, not annotated.

---

## `rimap-content`

**Last refresh:** YYYY-MM-DD (replace).
**Surviving mutants in non-`bin/` code:** N (replace with Step 2 count).

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| _populated by Task 8/9_ |  |  |  |

The `bin/epvme_runner.rs` survivors are out of scope for B1 — that crate is
diagnostic tooling, not production. Re-evaluate post-B4.

## `rimap-authz`

_Populated in Sprint B2._

## `rimap-audit`

_Populated in Sprint B2._

## `rimap-server`

_Populated in Sprint B3._

## `rimap-imap`

_Populated in Sprint B3._
````

Replace the two `YYYY-MM-DD` placeholders with the current date and `N` with the count from Step 2.

- [ ] **Step 4: Commit the baseline doc and the survivor list**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "docs(test-strategy): create mutation-baseline scaffold for B1

Refreshed cargo-mutants on rimap-content; recorded the survivor count
as the starting point for Tasks 8-9. Per-survivor annotations land
inline in subsequent commits as each module gets cleaned up.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 8: Mutation cleanup — `parse/`, `html/`, `unicode.rs`, `lookalike.rs`

**Why:** These four modules implement the active sanitization pipeline. Per the spec, every survivor here must be killed (a test added that catches the mutation) — there is no "best-effort" branch in security-critical paths.

**Files:**
- Create or modify: tests under `crates/rimap-content/tests/` and `crates/rimap-content/src/{parse,html,unicode,lookalike}.rs` `#[cfg(test)]` modules.
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

This task is **iterative** — there is no upfront list of N steps because the survivor inventory is data-dependent. The task pattern is:

- [ ] **Step 1: Filter the survivor list to this task's modules**

Run:
```bash
grep -E "^crates/rimap-content/src/(parse/|html/|unicode\.rs|lookalike\.rs)" \
  /tmp/rimap-content-survivors.txt | tee /tmp/task8-survivors.txt
wc -l /tmp/task8-survivors.txt
```

Note the count — call it `K`. The next steps execute K times (one per surviving mutant), in the order they appear.

- [ ] **Step 2 (loop, K iterations): Kill one mutant**

For each line in `/tmp/task8-survivors.txt`:

  1. **Read the mutation.** The line is formatted `path:line:col: <mutation description>`. Open the named file at the named line. Read enough surrounding code to understand what the mutation changes.

  2. **Decide: real gap, or equivalent mutant?** Most mutations are real gaps — the mutant changes observable behavior and the test suite has a hole. A few are equivalent — the mutated code produces output indistinguishable from the original under the function's contract.

  3. **If real gap, write a failing test.** Pick the test file that already exercises this module (`crates/rimap-content/src/<module>.rs` `#[cfg(test)]`, or one of the `crates/rimap-content/tests/*.rs` integration tests). Add a test that asserts the precise behavior the mutation breaks. Run it under the original code and confirm it passes; run it under a temporary local hand-application of the mutation and confirm it fails.

     Run:
     ```bash
     cargo nextest run --package rimap-content --all-features -- <test_name>
     ```

     The test must pass under unmutated code. If it passes against the mutated code too, it's not actually catching the mutation — go back and tighten it.

  4. **If equivalent mutant, annotate.** Add a comment immediately above the line:
     ```rust
     // cargo-mutants: known-equivalent — <one-line rationale>
     ```
     Annotation rationales must explain *why* the mutation is observably indistinguishable, not just "it doesn't matter." Example:
     ```rust
     // cargo-mutants: known-equivalent — replaces `+= 1` with `+= 0` on a
     // counter only consumed for an internal `tracing::debug!`, never read
     // by tests or production code.
     ```

  5. **Update the baseline doc.** Add a row to the appropriate table in `docs/superpowers/specs/test-strategy/mutation-baseline.md` *only if* the mutant is annotated as equivalent (real fixes don't get rows — they don't survive any more).

  6. **Commit.** Group by module (one commit per `parse/`, one per `html/`, etc.) — commit all that module's fixes together once the module is empty of survivors.

     ```bash
     git add crates/rimap-content/src/<module>/ crates/rimap-content/tests/<related>.rs \
             docs/superpowers/specs/test-strategy/mutation-baseline.md
     git commit -m "test(rimap-content): close mutation gaps in <module>

     Adds N tests covering specific mutation survivors uncovered by
     cargo-mutants on the 2026-04-30 baseline refresh. M known-equivalent
     mutants annotated inline in mutation-baseline.md.

     Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
     ```

- [ ] **Step 3: Re-run mutation tests on the cleaned modules to verify**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/**' \
  --file 'crates/rimap-content/src/html/**' \
  --file 'crates/rimap-content/src/unicode.rs' \
  --file 'crates/rimap-content/src/lookalike.rs' \
  --no-shuffle
```

Expected: zero `MISSED` mutations. If any remain, return to Step 2 — they are either gaps the prior loop missed or equivalent mutants that need annotation.

- [ ] **Step 4: Verify the workspace still builds clean**

Run:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

---

## Task 9: Mutation cleanup — `output.rs`, `error.rs`, `raw_parts.rs`, `testutil.rs`

**Why:** Per the spec, these are "plumbing" — survivors that change observable output get killed; survivors equivalent under serialization round-trip get annotated. The bar is lower than Task 8.

**Files:** same pattern as Task 8 — adds tests under `#[cfg(test)]` modules in the four named files (or `crates/rimap-content/tests/*.rs` for integration coverage), plus annotations and `mutation-baseline.md` updates.

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/(output|error|raw_parts|testutil)\.rs" \
  /tmp/rimap-content-survivors.txt | tee /tmp/task9-survivors.txt
wc -l /tmp/task9-survivors.txt
```

Call this count `K2`.

- [ ] **Step 2 (loop, K2 iterations): Triage one mutant**

For each line, decide:

  - **Changes observable output / API contract** → kill with a test (Task 8 sub-procedure).
  - **Equivalent under a documented round-trip** → annotate inline + baseline-doc row.
  - **Pure cosmetic** (e.g., `tracing::debug!` formatting) → annotate inline + baseline-doc row.

The rationale lines for plumbing-code annotations get more leeway than Task 8 — "internal-only counter, never observed externally" is a complete justification here.

- [ ] **Step 3: Re-run on the cleaned files**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/output.rs' \
  --file 'crates/rimap-content/src/error.rs' \
  --file 'crates/rimap-content/src/raw_parts.rs' \
  --file 'crates/rimap-content/src/testutil.rs' \
  --no-shuffle
```

Expected: zero unannotated `MISSED` mutations.

- [ ] **Step 4: Final mutation-cleanup commit**

```bash
git add crates/rimap-content/ docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in plumbing modules

Closes the long tail of cargo-mutants survivors in output.rs, error.rs,
raw_parts.rs, testutil.rs. Real gaps killed with targeted tests;
equivalent mutants annotated inline with rationale.

After this commit: cargo mutants --package rimap-content (excluding
src/bin/epvme_runner.rs) reports zero unannotated survivors.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 10: ClusterFuzzLite workflow (PR smoke + nightly)

**Why:** Continuous fuzzing in CI is the runtime artifact that completes Sprint B1's done criteria. The PR-smoke job runs `content_mime` + `content_html` for 5 minutes each on every PR (the other two stay nightly-only per spec §4.4). The nightly job runs all four targets at 30 minutes each on `main`.

**Files:**
- Create: `.github/workflows/fuzz.yml`

ClusterFuzzLite documentation: <https://google.github.io/clusterfuzzlite/>. The `actions/build_fuzzers` and `actions/run_fuzzers` actions live at `github.com/google/clusterfuzzlite/actions/...`. SHAs must be looked up at execution time (zizmor enforces 40-char SHA pins per repo policy).

- [ ] **Step 1: Look up the current ClusterFuzzLite action SHAs**

Run:
```bash
gh api repos/google/clusterfuzzlite/branches/main --jq '.commit.sha'
```

Record the SHA — it's used in three `uses:` lines below. Also resolve the corresponding tag via:
```bash
gh api repos/google/clusterfuzzlite/git/refs/tags --jq '.[-1].ref'
```

If a stable tag like `v1` exists and is pinned to a recent SHA, prefer that. Document the (SHA, tag) pair as a comment on each `uses:` line.

- [ ] **Step 2: Create the workflow**

Create `.github/workflows/fuzz.yml`:

```yaml
name: Fuzz

on:
  pull_request:
    branches: [main]
    paths:
      - 'crates/rimap-content/**'
      - 'crates/rimap-audit/**'
      - 'crates/rimap-server/**'
      - 'fuzz/**'
      - '.github/workflows/fuzz.yml'
  schedule:
    # Nightly at 03:17 UTC. The odd minute spreads load on shared GHA
    # cron schedulers (top-of-the-hour cron jobs queue heavily).
    - cron: '17 3 * * *'

concurrency:
  # PR-smoke runs share a per-PR group so a force-push cancels the prior run.
  # Nightly runs share a single global group so two nightly cycles cannot
  # overlap if one runs long.
  group: fuzz-${{ github.event_name == 'schedule' && 'nightly' || github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

permissions:
  contents: read
  # 'security-events: write' would be needed to upload SARIF; not used here
  # because crash artifacts are sufficient for B1's scope.

env:
  CARGO_TERM_COLOR: always

jobs:
  pr-smoke:
    name: pr-smoke (${{ matrix.target }})
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        target: [content_mime, content_html]
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - name: Build fuzzers
        # Pin: replace <SHA> with the SHA captured in Step 1.
        uses: google/clusterfuzzlite/actions/build_fuzzers@<SHA>  # <tag/date>
        with:
          language: rust
          sanitizer: address
      - name: Run fuzzer (${{ matrix.target }})
        uses: google/clusterfuzzlite/actions/run_fuzzers@<SHA>  # <tag/date>
        with:
          language: rust
          fuzz-seconds: 300
          mode: code-change
          sanitizer: address
          # Restrict to a single target per matrix slot so a crash in one
          # does not mask a regression in the other.
          parallel-fuzzing: false

  nightly:
    name: nightly (${{ matrix.target }})
    if: github.event_name == 'schedule'
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        target: [content_mime, content_html, content_rfc2047, content_charset]
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - name: Build fuzzers
        uses: google/clusterfuzzlite/actions/build_fuzzers@<SHA>  # <tag/date>
        with:
          language: rust
          sanitizer: address
      - name: Run fuzzer (${{ matrix.target }})
        uses: google/clusterfuzzlite/actions/run_fuzzers@<SHA>  # <tag/date>
        with:
          language: rust
          fuzz-seconds: 1800  # 30 minutes per target
          mode: batch
          sanitizer: address
          parallel-fuzzing: false
```

Replace **all four** `<SHA>` placeholders with the SHA from Step 1 and the trailing `# <tag/date>` comments with the matching ref.

- [ ] **Step 3: actionlint must pass**

Run:
```bash
actionlint .github/workflows/fuzz.yml
```

Expected: no output. If actionlint flags `<SHA>`, the placeholder substitution from Step 2 was missed.

- [ ] **Step 4: zizmor must pass**

Run:
```bash
zizmor .github/workflows/fuzz.yml
```

Expected: zero new findings. If zizmor flags `superfluous-actions` on the ClusterFuzzLite calls, add a per-line `# zizmor: ignore[superfluous-actions]` trailer on each — the actions are not replaceable with shell commands here.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/fuzz.yml
git commit -m "ci(fuzz): add ClusterFuzzLite workflow for PR smoke + nightly

PR smoke runs content_mime + content_html for 5 min each on every
PR that touches the fuzzed crates or fuzz/. Nightly runs all four
B1 targets at 30 min each on main. Crash artifacts upload to GHA;
reproducer files persist 90 days per ClusterFuzzLite default.

Other content_* targets stay nightly-only per spec §4.4 — their
input space is largely subsumed by content_mime's deeper code paths.

Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 11: Smoke-test the workflow on a draft PR

**Why:** ClusterFuzzLite has many quiet failure modes (missing `language` keyword, wrong sanitizer, corpus path resolution). A draft PR is the cheapest way to verify the wiring on a real GHA runner before the work merges to `main`.

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin feat/test-strategy-b1-rimap-content
```

- [ ] **Step 2: Open a draft PR**

```bash
gh pr create --draft --title "test: B1 — rimap-content fuzz harnesses + mutation cleanup" \
  --body "$(cat <<'EOF'
## Summary

Sprint B1 of the test-strategy-improvements plan. Adds:

- Four cargo-fuzz harnesses (content_mime, content_html, content_rfc2047, content_charset) under a new workspace-excluded `fuzz/` crate.
- Seed corpora pulled from `tests/injection-corpus/` plus hand-crafted edge cases.
- Targeted mutation cleanup on `rimap-content` (refreshed baseline at the start of this PR; survivors killed module-by-module; equivalent mutants annotated inline).
- ClusterFuzzLite CI workflow for PR-smoke (10 min) and nightly cron (60 min).

## Test plan

- [ ] All seven existing `just ci` checks pass (rustfmt, clippy, check (macOS), test (stable), test (MSRV 1.88.0), cargo-deny, zizmor self-check).
- [ ] `just fuzz content_mime` runs ≥ 60 s locally without crash.
- [ ] `just fuzz content_html` runs ≥ 60 s locally without crash.
- [ ] `just fuzz content_rfc2047` runs ≥ 60 s locally without crash.
- [ ] `just fuzz content_charset` runs ≥ 60 s locally without crash.
- [ ] `cargo mutants --package rimap-content` reports zero unannotated survivors outside `src/bin/`.
- [ ] The `fuzz / pr-smoke` job appears in this PR's status checks and runs to completion green.
- [ ] `mutation-baseline.md` documents the new state for `rimap-content`.

EOF
)"
```

- [ ] **Step 3: Watch CI**

Run:
```bash
gh pr checks --watch
```

Expected: all eight existing checks plus two new `fuzz / pr-smoke (content_mime)` and `fuzz / pr-smoke (content_html)` checks pass. If a fuzz-smoke check fails:
- "build_fuzzers failed" → most likely a missing dep in `fuzz/Cargo.toml` (e.g., `rimap-content` feature not enabled). Fix locally, push, watch again.
- "run_fuzzers found a crash" → libfuzzer reproduced a real bug. Triage: this PR cannot merge until the crash is fixed *or* a known-issue branch documents the deferral.

- [ ] **Step 4: Mark the PR ready for review**

Once CI is green:
```bash
gh pr ready
```

---

## Wrap-up

- [ ] **Step 1: Tick off Sprint B1's spec done-criteria**

Per spec §4.5:

- [ ] `just fuzz content_mime` runs locally for ≥ 5 minutes without finding a new crash.
- [ ] Same for `content_html`, `content_rfc2047`, `content_charset`.
- [ ] `cargo mutants --package rimap-content` reports 0 surviving mutants in non-`bin/` code, or every survivor has a `known-equivalent` annotation.
- [ ] ClusterFuzzLite smoke job is green on the PR.
- [ ] `mutation-baseline.md` documents the new state.

- [ ] **Step 2: Run the long-form fuzz validation locally before requesting review**

5 minutes per target (the spec's actual done-criterion runtime, not Task 3–6's 60-second smoke):

```bash
just fuzz content_mime    -- -max_total_time=300
just fuzz content_html    -- -max_total_time=300
just fuzz content_rfc2047 -- -max_total_time=300
just fuzz content_charset -- -max_total_time=300
```

Expected: all four exit clean after 5 min. Any crash here is a bug, not a flake — file before requesting review.

- [ ] **Step 3: Request review**

```bash
gh pr comment --body "Ready for review — Sprint B1 done-criteria verified locally and in CI."
```

- [ ] **Step 4: After merge — open follow-up issues for deferred work**

Two issues if applicable:
1. **`bin/epvme_runner.rs` mutation survivors** — out of scope for B1 per spec; ~44 survivors as of 2026-04-08 baseline. Issue title: `test(epvme_runner): triage cargo-mutants survivors in diagnostic binary`. Body cites this plan and the relevant lines in the baseline doc.
2. **B1 over-cap split** (only if Task 7 hit the >30 cap) — issue title: `test(rimap-content): finish mutation cleanup deferred from Sprint B1`. Body cites this PR and explains the cap was hit.

---

## Self-review checklist (writer-side, do not skip)

- **Spec coverage:** every Sprint B1 sub-section in the spec maps to a task in this plan — fuzz harnesses (Tasks 3–6), mutation refresh (Task 7), mutation cleanup (Tasks 8–9), CFL wiring (Task 10), done-criteria validation (Wrap-up Step 1). The "no fuzz target for X" carve-outs are not in B1's scope.
- **No placeholders:** every code block contains literal text, not `<TBD>`. The two exceptions — ClusterFuzzLite SHAs in Task 10 — are explicit Step-1 lookups with a verification step that catches missed substitutions.
- **Type/name consistency:** `sanitize_html`, `scrub_header_smuggling`, `parse_message`, `unicode::decode` are referenced consistently across Tasks 2–6 and the harnesses use the exact paths Task 2 set up (`rimap_content::testutil::sanitize_html`, `rimap_content::parse_message`, `rimap_content::unicode::decode`).
- **TDD-shape:** Task 2 (the only behavioral change) is shaped as failing-test-first. Tasks 3–6 (fuzz harnesses) are shaped as build-then-run-then-verify because there is no obvious "failing test" framing for a fuzz harness — the test *is* the long-running fuzzer.
- **One commit per logical change:** each task ends in a single commit. Task 8/9's loops are explicit about grouping by module so the history reads as one commit per module's mutation cleanup.
- **Out-of-band actions are flagged:** the >30 survivor cap in Task 7 is called out in-place; the follow-up issues are called out in Wrap-up Step 4 (operator action, not silently expected).
- **Cost/value tradeoffs documented:** Task 4's hand-crafted edge cases, Task 5's panic-on-LF assertion, and Task 10's per-target matrix layout are all motivated inline.
