# Issue #224 — Re-extract Grapheme-Safe Truncation Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-apply on `main` the consolidation of UTF-8 boundary walks onto a single canonical `truncate_graphemes` helper (with allocation-free `truncate_graphemes_in_place` sibling), replacing the three remaining hand-rolled `is_char_boundary` walks across `rimap-content`, `rimap-server`, and `rimap-audit`.

**Architecture:** Fresh-application (not cherry-pick) because the archived commits' context lines diverge from current `main` — the archive parents had cargo-mutants annotations and a `scan_body_urls` boundary regression test that were never on `main`. Each task ports the same end state archived in PR #197 (commits `aa43c50`, `bc78143`, `5913b54`, `a0739da`, `758da92`) onto `main`'s actual surface, in TDD order with one logical commit per task. `rimap-content` gets `truncate_graphemes` + `truncate_graphemes_in_place` (sharing a private `grapheme_cut`); `rimap-server` and `rimap-content::lookalike` consume the helpers directly; `rimap-audit::writer::provenance` keeps a module-local copy backed by `unicode-segmentation` to avoid pulling `mail-parser`/`scraper`/`ammonia`/`idna` into the audit crate's compile graph.

**Tech Stack:** Rust 2024, MSRV 1.88.0, `unicode-segmentation = "1.13"` (already in workspace deps; already used by `rimap-content`).

**Source issue:** [#224](https://github.com/randomparity/rusty-imap-mcp/issues/224) (Phase-2 re-extract of #194)
**Original PR (archived):** [#197](https://github.com/randomparity/rusty-imap-mcp/pull/197) on `archive/daemon-experiment`, merged at `89bc3db`.
**Original plan (archived):** `docs/superpowers/plans/2026-05-01-issue-194-truncate-graphemes-consolidation.md` at archived SHA `0e548db`.
**Reference commits on archive:**
- `aa43c50 refactor(rimap-content): use truncate_graphemes in scan_body_urls`
- `bc78143 refactor(rimap-server): use truncate_graphemes in fetch_message`
- `5913b54 test(rimap-content): cover exactly-fits multi-byte cluster in truncate_graphemes`
- `a0739da refactor(rimap-audit): grapheme-safe truncation in provenance buffer`
- `758da92 refactor(rimap-content): add truncate_graphemes_in_place sibling, use it in fetch_message`

**Baseline test count (verified during plan write):** `cargo test --workspace --quiet` → **993 passed, 0 failed, 0 ignored**. After this plan: 993 − 6 (deleted `truncate_string` tests) + 2 (Task 1: exactly-fits + cross-check) + 1 (Task 2: scan_body_urls multi-byte) + 1 (Task 4: provenance multi-byte) = **991 passed**.

---

## File Map

**Modified — production code:**
- `crates/rimap-content/src/unicode.rs` — refactor `truncate_graphemes` to share a private `grapheme_cut`; add `truncate_graphemes_in_place` (allocation-free sibling).
- `crates/rimap-content/src/lookalike.rs` — replace `scan_body_urls` boundary walk with a direct call to `crate::unicode::truncate_graphemes`.
- `crates/rimap-server/src/tools/retrieval/fetch_message.rs` — replace both call sites with `truncate_graphemes_in_place`; delete `truncate_string` helper and its 6 unit tests.
- `crates/rimap-audit/Cargo.toml` — add `unicode-segmentation = { workspace = true }`.
- `crates/rimap-audit/src/writer/provenance.rs` — replace inline boundary walk with module-local `truncate_at_grapheme_boundary` helper backed by `unicode-segmentation`; documented as a copy of `truncate_graphemes_in_place`.

**Modified — tests:**
- `crates/rimap-content/src/unicode.rs` — add `truncate_keeps_full_multibyte_cluster_when_exactly_fits` and `truncate_in_place_matches_owned_variant` tests.
- `crates/rimap-content/src/lookalike.rs` — add `scan_body_urls_handles_multi_byte_char_at_scan_boundary` regression test.
- `crates/rimap-audit/src/writer/provenance.rs` — add `oversize_multibyte_message_id_truncates_at_grapheme_boundary` regression test.

Each task produces one self-contained commit.

---

## Task 0: Branch and pre-flight verification

**Files:** none modified.

- [ ] **Step 1: Confirm `main` is clean and up-to-date**

Run: `git status && git log --oneline -1`
Expected: working tree clean; HEAD at `1c394e6 Merge pull request #232 ...` or later. Stop if uncommitted changes exist.

- [ ] **Step 2: Create the working branch off `main`**

Run:
```bash
git checkout -b phase2/truncate-graphemes-rextract main
```
Expected: `Switched to a new branch 'phase2/truncate-graphemes-rextract'`. From this point forward, never commit directly to `main`.

- [ ] **Step 3: Snapshot current state — confirm exactly the four expected `is_char_boundary` hits**

Run: `rg -n 'is_char_boundary|floor_char_boundary' crates/ --type rust`
Expected:
```
crates/rimap-audit/src/writer/provenance.rs:74:            while !message_id.is_char_boundary(end) {
crates/rimap-content/src/lookalike.rs:183:    while end > 0 && !body_text.is_char_boundary(end) {
crates/rimap-server/src/tools/retrieval/fetch_message.rs:156:    while end > 0 && !s.is_char_boundary(end) {
crates/rimap-server/src/tools/retrieval/fetch_message.rs:195:        assert!(s.is_char_boundary(s.len()));
```
The first three are the targets; the fourth is inside the `truncate_string` test module (line 195) and disappears when Task 3 deletes that module. If the surface differs, investigate before continuing — do not adapt the plan silently.

- [ ] **Step 4: Confirm `unicode-segmentation` is already a workspace dep**

Run: `grep -n 'unicode-segmentation' Cargo.toml`
Expected: `Cargo.toml:106:unicode-segmentation = "1.13"`. If the version differs, update Task 4 Step 3 accordingly.

- [ ] **Step 5: Capture baseline test count**

Run: `cargo test --workspace --quiet 2>&1 | grep -E "^test result:" | awk '{p+=$4; f+=$6; i+=$8} END {print "passed=" p " failed=" f " ignored=" i}'`
Expected: `passed=993 failed=0 ignored=0`. Note the count for Task 5 verification.

- [ ] **Step 6: Capture baseline clippy state**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -5`
Expected: no warnings. Stop and fix any pre-existing warnings before proceeding — they would otherwise mask new ones introduced by this work.

---

## Task 1: `rimap-content::unicode` — share `grapheme_cut`, add `truncate_graphemes_in_place`, add coverage tests

**Files:**
- Modify: `crates/rimap-content/src/unicode.rs:153-172` (refactor `truncate_graphemes`, add private `grapheme_cut`, add `truncate_graphemes_in_place`)
- Test: `crates/rimap-content/src/unicode.rs` `mod tests` (add two regression tests)

**Design note:** The current `truncate_graphemes` allocates a new `String` even when the input fits (`input.to_string()`), which is fine. The refactor extracts the boundary-finding loop into a private `grapheme_cut(input, max_bytes) -> usize` so a new `truncate_graphemes_in_place(&mut String, usize)` can share the same algorithm without allocation. `truncate_graphemes_in_place` is needed because `fetch_message::handle` (Task 3) operates on `String` already and the `max_body_bytes` cap is operator-configurable up to multi-megabytes — allocating a fresh `String` of that size on every oversized body would be wasteful.

- [ ] **Step 1: Write the failing exactly-fits multi-byte test**

Open `crates/rimap-content/src/unicode.rs`. Inside `mod tests` (after the existing `truncate_zero_max_bytes_returns_empty` test at ~line 388), add:

```rust
    #[test]
    fn truncate_keeps_full_multibyte_cluster_when_exactly_fits() {
        // Regression: "中" is 3 bytes in UTF-8. "ab中cd" with max=5
        // must yield "ab中" — the trailing cluster ends exactly at
        // byte 5, a grapheme boundary that fits within the cap.
        // Guards against a `> vs >=` mutation on the cluster-fits
        // check inside `truncate_graphemes`.
        assert_eq!(truncate_graphemes("ab中cd", 5), "ab中");
    }
```

- [ ] **Step 2: Run the new test — verify it passes against the existing implementation**

Run: `cargo test -p rimap-content --lib unicode::tests::truncate_keeps_full_multibyte_cluster_when_exactly_fits -- --nocapture`
Expected: PASS. The current `truncate_graphemes` already handles this correctly; the test is a regression guard for the refactor.

- [ ] **Step 3: Refactor `truncate_graphemes` to share `grapheme_cut`, add `truncate_graphemes_in_place`**

In `crates/rimap-content/src/unicode.rs`, replace the entire block from line 153 through line 172 (the existing `truncate_graphemes` function and its doc comment) with:

```rust
/// Find the largest byte offset `cut <= max_bytes` such that
/// `input[..cut]` ends at a grapheme-cluster boundary. Returns
/// `input.len()` when `input` already fits.
fn grapheme_cut(input: &str, max_bytes: usize) -> usize {
    if input.len() <= max_bytes {
        return input.len();
    }
    let mut cut = 0;
    for (idx, cluster) in input.grapheme_indices(true) {
        if idx + cluster.len() > max_bytes {
            break;
        }
        cut = idx + cluster.len();
    }
    cut
}

/// Truncate `input` to at most `max_bytes` bytes, cutting at a
/// grapheme-cluster boundary. Returns an owned `String` that is
/// always a prefix of `input` (byte-wise).
///
/// If `input` is already ≤ `max_bytes`, returns a clone. If
/// `max_bytes == 0`, returns an empty string. Allocates; prefer
/// [`truncate_graphemes_in_place`] when you already own the string.
#[must_use]
pub fn truncate_graphemes(input: &str, max_bytes: usize) -> String {
    let cut = grapheme_cut(input, max_bytes);
    input[..cut].to_string()
}

/// Truncate `s` in-place to the largest prefix that ends at a
/// grapheme-cluster boundary and has byte length ≤ `max_bytes`.
/// No allocation: only `String::truncate` is called.
pub fn truncate_graphemes_in_place(s: &mut String, max_bytes: usize) {
    let cut = grapheme_cut(s, max_bytes);
    s.truncate(cut);
}
```

- [ ] **Step 4: Add the cross-check test**

Inside `mod tests`, immediately after the test added in Step 1, add:

```rust
    #[test]
    fn truncate_in_place_matches_owned_variant() {
        // Cross-check the in-place and owned helpers on inputs that
        // exercise each branch of `grapheme_cut`: under-limit, exact
        // limit, ASCII cut, mid-cluster drop, exact-fit interior cut,
        // and zero cap.
        let cases: &[(&str, usize)] = &[
            ("hello", 10),      // under-limit passthrough
            ("hello", 5),       // exact-limit whole string
            ("hello world", 5), // ASCII cut
            ("ae\u{0301}b", 2), // grapheme cluster dropped
            ("ab中cd", 5),      // multi-byte cluster fits exactly
            ("hello", 0),       // zero cap
        ];
        for (input, max) in cases {
            let mut owned = (*input).to_string();
            truncate_graphemes_in_place(&mut owned, *max);
            assert_eq!(
                owned,
                truncate_graphemes(input, *max),
                "in-place vs owned diverged on ({input:?}, {max})",
            );
        }
    }
```

- [ ] **Step 5: Run all `unicode` tests; confirm both new tests and the five existing ones pass**

Run: `cargo test -p rimap-content --lib unicode::tests`
Expected: all PASS, including the existing `truncate_under_limit_is_passthrough`, `truncate_exact_limit`, `truncate_ascii_cuts_cleanly`, `truncate_preserves_grapheme_cluster`, `truncate_zero_max_bytes_returns_empty`, plus the two added in this task.

- [ ] **Step 6: Confirm `truncate_graphemes` callers in the same module still work (`sanitize` uses it twice)**

Run: `cargo test -p rimap-content --lib`
Expected: all PASS. The internal `sanitize` callers (`unicode.rs:198` and `unicode.rs:202`) keep working unchanged because the public signature is preserved.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-content/src/unicode.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-content): add truncate_graphemes_in_place sibling, share grapheme_cut

Extracts the boundary-walk loop in unicode::truncate_graphemes into a
private grapheme_cut() helper so a new allocation-free sibling,
truncate_graphemes_in_place, can share the same algorithm. The owned
variant's signature is unchanged.

Adds two regression tests:
  - truncate_keeps_full_multibyte_cluster_when_exactly_fits guards
    the > vs >= boundary check on the cluster-fits comparison
    inside grapheme_cut.
  - truncate_in_place_matches_owned_variant pins the in-place output
    against the owned variant across every grapheme_cut branch.

Re-extract of archive commits 5913b54 and 758da92 (PR #197). Closes
part of #224.
EOF
)"
```

---

## Task 2: `rimap-content::lookalike` — replace `scan_body_urls` boundary walk

**Files:**
- Modify: `crates/rimap-content/src/lookalike.rs:179-196` (the `scan_body_urls` function)
- Test: `crates/rimap-content/src/lookalike.rs` `mod tests` (add multi-byte regression test)

**Design note:** `scan_body_urls(body_text: &str, ...)` walks `end` back to a UTF-8 char boundary so `&body_text[..end]` is a valid slice for `linkify`. The replacement allocates a new `String` of at most `MAX_LINKIFY_SCAN_BYTES = 64 KiB` per call; the cost is acceptable on this path (one bounded allocation per audited message). The owned variant is appropriate here because the input is `&str` (we don't own a `String`) and 64 KiB is small. The multi-byte regression test does not exist on `main` (it lived on the archived branch only) — Task 2 introduces it.

- [ ] **Step 1: Write the failing multi-byte regression test**

Open `crates/rimap-content/src/lookalike.rs`. Find the `mod tests` block and locate the existing `scan_body_urls`-touching test near `MAX_LINKIFY_SCAN_BYTES` references (approx. line 525). Add the following inside `mod tests`, before the existing tests' closing `}`:

```rust
    #[test]
    fn scan_body_urls_handles_multi_byte_char_at_scan_boundary() {
        // Regression: `scan_body_urls` truncates `body_text` at
        // MAX_LINKIFY_SCAN_BYTES via `unicode::truncate_graphemes`. A
        // body whose only grapheme boundary near the cap straddles the
        // cap byte must not panic when we slice and pass to linkify.
        //
        // Construction: 65535 ASCII bytes + a 2-byte non-ASCII char
        // straddling MAX_LINKIFY_SCAN_BYTES (=65536). `truncate_graphemes`
        // must drop the straddling cluster cleanly.
        let mut body = String::with_capacity(MAX_LINKIFY_SCAN_BYTES + 16);
        body.push_str(&"a".repeat(MAX_LINKIFY_SCAN_BYTES - 1));
        body.push('é');
        body.push_str("trailing");
        let mut warnings: Vec<SecurityWarning> = Vec::new();
        super::scan_body_urls(&body, &mut warnings);
        assert!(
            warnings.is_empty(),
            "no URLs in this body, got {warnings:?}"
        );
    }
```

- [ ] **Step 2: Run the test against the current `scan_body_urls` — verify it passes pre-refactor**

Run: `cargo test -p rimap-content --lib lookalike::tests::scan_body_urls_handles_multi_byte_char_at_scan_boundary -- --nocapture`
Expected: PASS. The current hand-rolled walk already handles the multi-byte boundary; the test is a regression guard for the refactor.

- [ ] **Step 3: Replace `scan_body_urls` with a call to `truncate_graphemes`**

In `crates/rimap-content/src/lookalike.rs`, replace lines 179–196 (the doc comment + function body) with:

```rust
/// Pass 3: linkify the first `MAX_LINKIFY_SCAN_BYTES` of `body_text`
/// (cut at a grapheme-cluster boundary) and classify each URL.
fn scan_body_urls(body_text: &str, out: &mut Vec<SecurityWarning>) {
    let scan_slice = crate::unicode::truncate_graphemes(body_text, MAX_LINKIFY_SCAN_BYTES);
    let finder = LinkFinder::new();
    for link in finder.links(&scan_slice) {
        if link.kind() != &LinkKind::Url {
            continue;
        }
        if let Some(domain) = extract_domain_from_url(link.as_str()) {
            emit_classification(&domain, "body:text", out);
        }
    }
}
```

- [ ] **Step 4: Run the regression test plus the wider lookalike suite**

Run: `cargo test -p rimap-content --lib lookalike::tests`
Expected: all PASS, including the new `scan_body_urls_handles_multi_byte_char_at_scan_boundary` and the existing `audit_respects_body_scan_cap` / `audit_scans_url_at_byte_offset_2000`.

- [ ] **Step 5: Confirm no `is_char_boundary` references remain in `lookalike.rs`**

Run: `rg -n 'is_char_boundary' crates/rimap-content/src/lookalike.rs`
Expected: empty (no matches).

- [ ] **Step 6: Run full `rimap-content` test suite**

Run: `cargo test -p rimap-content --quiet`
Expected: PASS.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-content/src/lookalike.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-content): use truncate_graphemes in scan_body_urls

Replaces the inline is_char_boundary backward walk with a call to the
canonical unicode::truncate_graphemes helper. Behaviour is unchanged:
the body is cut at a grapheme-cluster boundary <= MAX_LINKIFY_SCAN_BYTES
before being passed to linkify. The cost is one bounded (64 KiB)
allocation per audit pass, which is acceptable on this path.

Adds scan_body_urls_handles_multi_byte_char_at_scan_boundary as a
regression guard against future panics when MAX_LINKIFY_SCAN_BYTES
lands inside a multi-byte cluster.

Re-extract of archive commit aa43c50 (PR #197). Closes part of #224.
EOF
)"
```

---

## Task 3: `rimap-server::fetch_message` — delete `truncate_string`, use `truncate_graphemes_in_place`

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:1` (add `use rimap_content::unicode::truncate_graphemes_in_place;`)
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:114-125` (call sites in `handle`)
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:148-160` (delete `truncate_string`)
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:162-213` (delete the six `truncate_string` unit tests)

**Design note:** `rimap-server` already declares `rimap-content` as a path dep. The wrapper `truncate_string` exists only to host the boundary walk. Once both call sites switch to `truncate_graphemes_in_place`, the wrapper has no remaining responsibility — inline the calls and delete the wrapper plus its tests. The canonical `truncate_graphemes` in `rimap-content::unicode` already has equivalent or stronger tests covering the same six cases (`truncate_under_limit_is_passthrough`, `truncate_exact_limit`, `truncate_ascii_cuts_cleanly`, `truncate_preserves_grapheme_cluster`, `truncate_zero_max_bytes_returns_empty`, `truncate_keeps_full_multibyte_cluster_when_exactly_fits` from Task 1, plus the in-place cross-check). Using `truncate_graphemes_in_place` (not the owned variant) preserves the original `String::truncate` semantics — no allocation per call, important because `max_body_bytes` is operator-configurable.

- [ ] **Step 1: Add the `use` import**

In `crates/rimap-server/src/tools/retrieval/fetch_message.rs`, add a new line after the existing module-doc-comment line and before `use rimap_imap::types::Uid;` (line 3). The header should read:

```rust
//! `fetch_message` tool handler.

use rimap_content::unicode::truncate_graphemes_in_place;
use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
```

- [ ] **Step 2: Replace the call sites in `handle`**

In `crates/rimap-server/src/tools/retrieval/fetch_message.rs`, find the block at lines 114–125 reading:

```rust
    if let Some(max) = input.max_body_bytes {
        if body_text.len() > max {
            truncate_string(&mut body_text, max);
            truncated = true;
        }
        if let Some(html) = &mut body_html
            && html.len() > max
        {
            truncate_string(html, max);
            truncated = true;
        }
    }
```

Replace with:

```rust
    if let Some(max) = input.max_body_bytes {
        if body_text.len() > max {
            truncate_graphemes_in_place(&mut body_text, max);
            truncated = true;
        }
        if let Some(html) = &mut body_html
            && html.len() > max
        {
            truncate_graphemes_in_place(html, max);
            truncated = true;
        }
    }
```

- [ ] **Step 3: Delete the `truncate_string` helper**

Delete lines 148–160 of `crates/rimap-server/src/tools/retrieval/fetch_message.rs` — the entire helper:

```rust
/// Truncate a string to at most `max` bytes on a valid UTF-8
/// boundary.
fn truncate_string(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    // Find the last valid char boundary at or before `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}
```

- [ ] **Step 4: Delete the six redundant unit tests**

Delete the entire `#[cfg(test)] mod tests { ... }` block at lines 162–213 of `crates/rimap-server/src/tools/retrieval/fetch_message.rs`. The tests being removed:
- `truncate_below_max_is_noop`
- `truncate_at_exact_max_is_noop`
- `truncate_lops_off_trailing_bytes`
- `truncate_respects_utf8_char_boundary`
- `truncate_to_zero_yields_empty_string`
- `truncate_keeps_full_multibyte_char_when_possible`

Each is now redundantly covered by tests in `rimap-content::unicode::tests` (see the Design note above). Removing them avoids drift between two parallel test suites.

- [ ] **Step 5: Confirm no `is_char_boundary` or `truncate_string` references remain in `fetch_message.rs`**

Run: `rg -n 'is_char_boundary|truncate_string' crates/rimap-server/src/tools/retrieval/fetch_message.rs`
Expected: empty (no matches).

- [ ] **Step 6: Run `rimap-server` tests**

Run: `cargo test -p rimap-server --quiet 2>&1 | grep -E "^test result:" | tail -1`
Expected: PASS. The deleted unit tests reduce the per-crate test count by 6.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/fetch_message.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-server): use truncate_graphemes_in_place in fetch_message

Switches both body_text and body_html truncation sites in
fetch_message::handle to rimap_content::unicode::truncate_graphemes_in_place,
removing the local truncate_string wrapper and its six unit tests
(redundant with the canonical helper's coverage in
rimap-content::unicode::tests). The in-place sibling preserves the
original String::truncate semantics — no allocation per call, which
matters because max_body_bytes is operator-configurable up to
multi-megabytes.

Re-extract of archive commits bc78143 and 758da92 (PR #197). Closes
part of #224.
EOF
)"
```

---

## Task 4: `rimap-audit::provenance` — module-local grapheme helper, multi-byte regression test

**Files:**
- Modify: `crates/rimap-audit/Cargo.toml` (add `unicode-segmentation = { workspace = true }`)
- Modify: `crates/rimap-audit/src/writer/provenance.rs:18-21` (add module-level `use unicode_segmentation::UnicodeSegmentation;`)
- Modify: `crates/rimap-audit/src/writer/provenance.rs:67-89` (replace inline boundary walk with helper call)
- Modify: `crates/rimap-audit/src/writer/provenance.rs` (add `truncate_at_grapheme_boundary` helper before `mod tests`)
- Test: `crates/rimap-audit/src/writer/provenance.rs` `mod tests` (add `oversize_multibyte_message_id_truncates_at_grapheme_boundary`)

**Design note:** `rimap-audit` does NOT depend on `rimap-content`, and adding that dep would pull `mail-parser`, `scraper`, `ammonia`, `idna`, and the confusables table into the audit crate's compile graph for one helper. The original issue explicitly permits a module-local helper for this case. We add `unicode-segmentation` (already in workspace deps) and inline a 9-line helper that mirrors the algorithm of `rimap_content::unicode::truncate_graphemes_in_place`. The doc comment names the canonical helper as the source of truth, so future drift is visible at review time.

- [ ] **Step 1: Add the failing multi-byte regression test**

Open `crates/rimap-audit/src/writer/provenance.rs`. Inside the `#[cfg(test)] mod tests` block, after `oversize_message_id_is_truncated_with_suffix` (line 191–200), add:

```rust
    #[test]
    fn oversize_multibyte_message_id_truncates_at_grapheme_boundary() {
        // Regression: a Message-ID that exceeds MAX_MESSAGE_ID_LEN with
        // a multi-byte grapheme cluster straddling the cap byte must
        // not panic and must yield a valid UTF-8 prefix + the
        // "…[truncated]" suffix.
        //
        // Construction: 997 ASCII 'a' + 'é' (2 bytes) + 100 'b'.
        // MAX_MESSAGE_ID_LEN is 998, so the cap lands inside 'é'; the
        // cluster must be dropped entirely, leaving exactly 997 'a's
        // plus the suffix.
        let mut b = ProvenanceBuffer::new(60);
        let mut huge = "a".repeat(997);
        huge.push('é');
        huge.push_str(&"b".repeat(100));
        b.record_at(huge, at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        let stored = &snap[0];
        assert!(
            stored.ends_with("\u{2026}[truncated]"),
            "missing truncation suffix in {stored:?}"
        );
        let suffix = "\u{2026}[truncated]";
        let prefix_len = stored.len() - suffix.len();
        assert_eq!(prefix_len, 997, "expected 997-byte prefix in {stored:?}");
    }
```

- [ ] **Step 2: Run the new test against the current implementation — verify it passes pre-refactor**

Run: `cargo test -p rimap-audit --lib writer::provenance::tests::oversize_multibyte_message_id_truncates_at_grapheme_boundary -- --nocapture`
Expected: PASS. The current `is_char_boundary` walk is char-boundary-safe (and a single-codepoint cluster like `é` is also a grapheme cluster), so the assertion that the prefix is exactly 997 bytes already holds. The test is a regression guard for the refactor.

- [ ] **Step 3: Add `unicode-segmentation` as a dep on `rimap-audit`**

Open `crates/rimap-audit/Cargo.toml`. Add the following line to the `[dependencies]` block, immediately after the `tokio = { workspace = true }` line at line 30:

```toml
unicode-segmentation = { workspace = true }
```

The full `[dependencies]` block should now end with:

```toml
async-channel = { workspace = true }
tokio = { workspace = true }
unicode-segmentation = { workspace = true }
```

- [ ] **Step 4: Add the module-level `use` for `UnicodeSegmentation`**

In `crates/rimap-audit/src/writer/provenance.rs`, modify the `use` block at lines 18–20. The existing block reads:

```rust
use std::collections::VecDeque;

use time::OffsetDateTime;
```

Replace with:

```rust
use std::collections::VecDeque;

use time::OffsetDateTime;
use unicode_segmentation::UnicodeSegmentation;
```

- [ ] **Step 5: Replace the inline boundary walk in `record_at`**

In `crates/rimap-audit/src/writer/provenance.rs`, find the block at lines 70–79 inside `record_at`:

```rust
        let mut message_id = message_id.into();
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            // Truncate at a char boundary, not mid-codepoint.
            let mut end = MAX_MESSAGE_ID_LEN;
            while !message_id.is_char_boundary(end) {
                end -= 1;
            }
            message_id.truncate(end);
            message_id.push_str("\u{2026}[truncated]");
        }
```

Replace with:

```rust
        let mut message_id = message_id.into();
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            truncate_at_grapheme_boundary(&mut message_id, MAX_MESSAGE_ID_LEN);
            message_id.push_str("\u{2026}[truncated]");
        }
```

- [ ] **Step 6: Add the `truncate_at_grapheme_boundary` helper before `mod tests`**

In `crates/rimap-audit/src/writer/provenance.rs`, immediately after the closing `}` of the `impl ProvenanceBuffer` block (after the `evict_before` method at line 132) and before `#[cfg(test)] mod tests`, add:

```rust
/// Truncate `s` in-place to the largest prefix that ends at a grapheme
/// cluster boundary and has byte length <= `max_bytes`.
///
/// This is a module-local copy of `rimap_content::unicode::truncate_graphemes_in_place`
/// (the canonical reference). It is duplicated here to avoid pulling the
/// full `rimap-content` API surface (mail-parser, scraper, ammonia, idna)
/// into `rimap-audit` for one helper.
fn truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut cut = 0;
    for (idx, cluster) in s.grapheme_indices(true) {
        if idx + cluster.len() > max_bytes {
            break;
        }
        cut = idx + cluster.len();
    }
    s.truncate(cut);
}
```

- [ ] **Step 7: Confirm no `is_char_boundary` references remain in `provenance.rs`**

Run: `rg -n 'is_char_boundary' crates/rimap-audit/src/writer/provenance.rs`
Expected: empty (no matches).

- [ ] **Step 8: Run all `provenance` tests, including the new regression**

Run: `cargo test -p rimap-audit --lib writer::provenance::tests`
Expected: all PASS, including the new `oversize_multibyte_message_id_truncates_at_grapheme_boundary`.

- [ ] **Step 9: Run full `rimap-audit` test suite**

Run: `cargo test -p rimap-audit --quiet 2>&1 | grep -E "^test result:" | tail -1`
Expected: PASS.

- [ ] **Step 10: Lint**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 11: Commit**

```bash
git add crates/rimap-audit/Cargo.toml crates/rimap-audit/src/writer/provenance.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-audit): grapheme-safe truncation in provenance buffer

Replaces the inline is_char_boundary backward walk in
ProvenanceBuffer::record_at with a module-local
truncate_at_grapheme_boundary helper backed by unicode-segmentation.
The helper mirrors rimap_content::unicode::truncate_graphemes_in_place
(cited in the doc comment); it lives locally to avoid pulling
mail-parser, scraper, ammonia, and idna into rimap-audit's compile
graph.

Adds oversize_multibyte_message_id_truncates_at_grapheme_boundary as
a regression guard against future panics and prefix-length drift.

Re-extract of archive commit a0739da (PR #197). Closes part of #224.
EOF
)"
```

---

## Task 5: Workspace verification and PR

**Files:** none modified.

- [ ] **Step 1: Confirm done criteria — no hand-rolled boundary walks anywhere in `crates/`**

Run: `rg -n 'is_char_boundary|floor_char_boundary' crates/ --type rust`
Expected: empty (no matches). The four pre-existing hits are all gone:
- `rimap-audit/src/writer/provenance.rs:74` — replaced in Task 4
- `rimap-content/src/lookalike.rs:183` — replaced in Task 2
- `rimap-server/src/tools/retrieval/fetch_message.rs:156` — function deleted in Task 3
- `rimap-server/src/tools/retrieval/fetch_message.rs:195` — assertion in deleted test module from Task 3

- [ ] **Step 2: Confirm `truncate_graphemes` and `truncate_graphemes_in_place` are the only such helpers**

Run: `rg -n 'fn truncate_graphemes' crates/ --type rust`
Expected: exactly two definitions, both in `crates/rimap-content/src/unicode.rs`:
```
crates/rimap-content/src/unicode.rs:???:pub fn truncate_graphemes(input: &str, max_bytes: usize) -> String {
crates/rimap-content/src/unicode.rs:???:pub fn truncate_graphemes_in_place(s: &mut String, max_bytes: usize) {
```
The line numbers will reflect Task 1's new placement; the count must be 2.

- [ ] **Step 3: Confirm the `rimap-audit` module-local helper is named distinctly**

Run: `rg -n 'fn truncate_at_grapheme_boundary' crates/ --type rust`
Expected:
```
crates/rimap-audit/src/writer/provenance.rs:???:fn truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize) {
```
(One match.)

- [ ] **Step 4: Run the full workspace test suite and capture totals**

Run: `cargo test --workspace --quiet 2>&1 | grep -E "^test result:" | awk '{p+=$4; f+=$6; i+=$8} END {print "passed=" p " failed=" f " ignored=" i}'`
Expected: `passed=991 failed=0 ignored=0` (baseline 993 − 6 deleted `truncate_string` tests + 4 new tests).

- [ ] **Step 5: Run workspace clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Run cargo deny**

Run: `cargo deny check`
Expected: PASS. (`unicode-segmentation` was already in the workspace deps and used by `rimap-content`; the only graph change is `rimap-audit → unicode-segmentation`. No new licenses or advisories enter the graph.)

- [ ] **Step 7: Run `cargo fmt --check`**

Run: `cargo fmt --all -- --check`
Expected: clean. If it complains, run `cargo fmt --all` and amend each affected commit.

- [ ] **Step 8: Optional — run mutation tests on the changed sites**

Run (each on a separate command — `cargo-mutants` should always be invoked with `--jobs 2` per host memory constraints):
```bash
cargo mutants --jobs 2 --in-place -p rimap-content -f crates/rimap-content/src/unicode.rs
cargo mutants --jobs 2 --in-place -p rimap-content -f crates/rimap-content/src/lookalike.rs --line-filter 179-196
cargo mutants --jobs 2 --in-place -p rimap-server -f crates/rimap-server/src/tools/retrieval/fetch_message.rs
cargo mutants --jobs 2 --in-place -p rimap-audit -f crates/rimap-audit/src/writer/provenance.rs
```
Expected: any survivors should be either trivially equivalent (annotated) or covered by an additional test before opening the PR. If running mutation tests is too slow for this PR, defer to a follow-up — note in the PR body.

- [ ] **Step 9: Push the branch**

Run:
```bash
git push -u origin phase2/truncate-graphemes-rextract
```
Expected: branch pushed; PR creation hint printed.

- [ ] **Step 10: Open the PR**

Run:
```bash
gh pr create --title "refactor(workspace): consolidate UTF-8 boundary walks onto truncate_graphemes (#224)" --body "$(cat <<'EOF'
## Summary
- Re-applies on `main` the consolidation of UTF-8 boundary walks onto a single canonical `truncate_graphemes` helper, with allocation-free `truncate_graphemes_in_place` sibling.
- Replaces the three remaining hand-rolled `is_char_boundary` backward walks in `rimap-content`, `rimap-server`, and `rimap-audit`.
- Closes #224.

## Sites changed
- `rimap-content/src/unicode.rs` — refactor `truncate_graphemes` to share a private `grapheme_cut`; add `truncate_graphemes_in_place` sibling and two regression tests (exactly-fits multi-byte cluster, in-place vs owned cross-check).
- `rimap-content/src/lookalike.rs::scan_body_urls` — direct call to `crate::unicode::truncate_graphemes`; new multi-byte boundary regression test.
- `rimap-server/src/tools/retrieval/fetch_message.rs` — switched both call sites to `truncate_graphemes_in_place`; removed the now-empty `truncate_string` wrapper and its six unit tests (redundant with `unicode::truncate_graphemes` coverage).
- `rimap-audit/src/writer/provenance.rs` — module-local `truncate_at_grapheme_boundary` backed by `unicode-segmentation`, documented as a copy of the canonical helper. Avoids pulling `mail-parser`/`scraper`/`ammonia`/`idna` into `rimap-audit`.

## Re-extract context
- Original work: PR #197 (merged into archive at `89bc3db`).
- Original issue: #194.
- Archive commits replayed (as fresh applications, not cherry-picks): `aa43c50`, `bc78143`, `5913b54`, `a0739da`, `758da92`. Direct cherry-picks were rejected because the archive parents had cargo-mutants annotations and a boundary regression test that were never on `main`; this PR re-derives the same end state.

## Test plan
- [ ] `cargo test --workspace` PASS (991 tests, 4 added, 6 removed)
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo deny check` PASS
- [ ] `cargo fmt --all -- --check` clean
- [ ] `rg -n 'is_char_boundary|floor_char_boundary' crates/` returns no hand-rolled boundary walks
- [ ] CI green on all 8 required checks

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
Expected: PR URL printed.

---

## Self-review checklist (run before saving this plan)

- **Spec coverage:** Issue #224's four acceptance criteria are all addressed:
  - `truncate_graphemes` + `truncate_graphemes_in_place` helpers in `rimap-content` → Task 1.
  - All call sites in `rimap-content`, `rimap-server`, `rimap-audit` use the helpers → Tasks 2, 3, 4.
  - Multi-byte cluster regression test present → three new tests (Task 1, Task 2, Task 4) cover the `unicode`, `lookalike`, and `provenance` sites respectively.
  - CI green on all 8 required checks → Task 5 Steps 4–7.
- **Placeholder scan:** No TBDs, no "implement later", no "similar to Task N", no unresolved error-handling stubs. Every code-step has the exact code; every command-step has the exact command.
- **Type consistency:**
  - `truncate_graphemes(input: &str, max_bytes: usize) -> String` — used in Task 2.
  - `truncate_graphemes_in_place(s: &mut String, max_bytes: usize)` — used in Task 3.
  - `truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize)` — module-local in Task 4 (deliberately distinct name to make it visible at grep time).
  - `grapheme_cut(input: &str, max_bytes: usize) -> usize` — private, defined in Task 1, consumed by both public helpers in the same file.
- **Dep accounting:** `unicode-segmentation = "1.13"` is already at workspace `Cargo.toml:106` and consumed by `rimap-content`; Task 4 adds it to `rimap-audit/Cargo.toml` as `{ workspace = true }`. `cargo deny check` should pass with no graph changes beyond `rimap-audit → unicode-segmentation`.
- **Cycle check:** `rimap-audit → unicode-segmentation` (no cycle); we deliberately do NOT add `rimap-audit → rimap-content` to keep the audit crate's compile graph small.
- **Test count math:** baseline 993 − 6 (deleted `truncate_string` tests in Task 3) + 2 (Task 1: exactly-fits, cross-check) + 1 (Task 2: scan_body_urls multi-byte) + 1 (Task 4: provenance multi-byte) = 991. Verified in Task 5 Step 4.
- **Pre-test gating:** Tasks 1, 2, and 4 add their regression tests *before* the refactor and confirm they pass against the existing implementation (the helpers are already char-boundary-safe). Task 3 has no new test — its scenarios are already covered by the new tests in Task 1's `unicode::tests`.
