# Issue #194 — Consolidate UTF-8 Boundary Walks onto `truncate_graphemes`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three remaining hand-rolled `is_char_boundary` walks in the workspace with the canonical `rimap_content::unicode::truncate_graphemes` helper (or a delegating module-local helper where a cross-crate dependency would be too heavy).

**Architecture:** Two of the three sites (`lookalike.rs` and `fetch_message.rs`) are in crates that already have `rimap-content` available — they call the canonical helper directly. The third site (`provenance.rs` in `rimap-audit`) keeps a small module-local helper backed by `unicode-segmentation` to avoid pulling the full `rimap-content` API surface (mail-parser, scraper, ammonia, idna) into `rimap-audit`. The local helper is documented as a copy of `truncate_graphemes`'s algorithm, so the canonical implementation remains the single point of reference.

**Tech Stack:** Rust 2024, MSRV 1.88.0, `unicode-segmentation = "1.13"` (already in workspace deps).

**Source issue:** https://github.com/randomparity/rusty-imap-mcp/issues/194 — "refactor(workspace): replace remaining UTF-8 boundary-walk copies with truncate_graphemes"

**Reference commit:** `c96b3c1` "refactor(rimap-content): consolidate utf-8 truncation and header-boundary detection."

---

## Pre-flight

- [ ] **Step 0a: Confirm working from a feature branch (NOT `main`)**

```bash
git status
git branch --show-current
```

If on `main`, create a feature branch:

```bash
git checkout -b refactor/issue-194-truncate-graphemes
```

- [ ] **Step 0b: Snapshot current state — confirm exactly three hand-rolled sites**

```bash
rg -n 'is_char_boundary|floor_char_boundary' crates/ --type rust
```

Expected (4 hits across 3 files; the 4th is an unrelated assertion in a test):
```
crates/rimap-audit/src/writer/provenance.rs:74:    while !message_id.is_char_boundary(end) {
crates/rimap-content/src/lookalike.rs:195:    while end > 0 && !body_text.is_char_boundary(end) {
crates/rimap-server/src/tools/retrieval/fetch_message.rs:157:    while end > 0 && !s.is_char_boundary(end) {
crates/rimap-server/src/tools/retrieval/fetch_message.rs:196:    assert!(s.is_char_boundary(s.len()));   ← test assertion, unchanged
```

If the surface differs, investigate before continuing — do not adapt the plan silently.

- [ ] **Step 0c: Capture baseline test pass**

```bash
cargo test --workspace --quiet
```
Expected: PASS. Note the count for later comparison.

---

## File structure

| Crate | File | Change |
|---|---|---|
| `rimap-content` | `src/lookalike.rs` | Replace `scan_body_urls` boundary walk with direct call to `crate::unicode::truncate_graphemes` |
| `rimap-server` | `src/tools/retrieval/fetch_message.rs` | Delete `truncate_string` helper; inline two calls to `rimap_content::unicode::truncate_graphemes` at the existing call sites |
| `rimap-server` | `src/tools/retrieval/fetch_message.rs` (tests) | Delete the six `truncate_string` unit tests (now redundant with `unicode::truncate_graphemes` tests) |
| `rimap-audit` | `Cargo.toml` | Add `unicode-segmentation = { workspace = true }` |
| `rimap-audit` | `src/writer/provenance.rs` | Replace inline boundary walk with module-local `truncate_at_grapheme_boundary` helper using `unicode-segmentation`; document it as a copy of `rimap_content::unicode::truncate_graphemes` |
| `rimap-audit` | `src/writer/provenance.rs` (tests) | Add multi-byte regression test |

Each task produces one self-contained commit.

---

## Task 1: `rimap-content` — replace `scan_body_urls` boundary walk

**Files:**
- Modify: `crates/rimap-content/src/lookalike.rs:188-217` (the `scan_body_urls` function)
- Test: `crates/rimap-content/src/lookalike.rs:597-620` (existing `scan_body_urls_handles_multi_byte_char_at_scan_boundary` already covers the multi-byte boundary case)

**Design note:** `scan_body_urls` currently borrows `body_text: &str` and walks `end` back to a UTF-8 char boundary so `&body_text[..end]` is a valid slice for `linkify`. The replacement allocates a new `String` (bounded by `MAX_LINKIFY_SCAN_BYTES = 64 KiB`) via `truncate_graphemes`. The allocation cost is acceptable: this path runs at most once per audited message, and 64 KiB is small. The old code's "back up at most 3 bytes to a char boundary" is replaced by "iterate graphemes from byte 0 forward until adding the next would exceed 64 KiB."

- [ ] **Step 1: Verify the existing multi-byte regression test currently passes**

```bash
cargo test -p rimap-content --lib lookalike::tests::scan_body_urls_handles_multi_byte_char_at_scan_boundary -- --nocapture
```
Expected: PASS (this test was added to kill mutations on the boundary walk; it must continue to pass after the refactor).

- [ ] **Step 2: Replace the body of `scan_body_urls` with a `truncate_graphemes` call**

Open `crates/rimap-content/src/lookalike.rs`. Replace lines 186–217 (the entire `scan_body_urls` function and its preceding doc comment) with:

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

- [ ] **Step 3: Update the multi-byte regression test's "what this kills" comment**

The existing test at line 597 has a comment block describing which mutations it kills on the now-removed boundary loop. Update the comment so it describes what the test now guards: that `truncate_graphemes` does not panic when `body_text.len()` exceeds `MAX_LINKIFY_SCAN_BYTES` and the cut point lands inside a multi-byte cluster.

Replace the existing comment block (lines ~597-609 inside the test) with:

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

- [ ] **Step 4: Run lookalike tests; verify the boundary test still passes and `audit_respects_body_scan_cap` / `audit_scans_url_at_byte_offset_2000` are unaffected**

```bash
cargo test -p rimap-content --lib lookalike::tests
```
Expected: all tests PASS.

- [ ] **Step 5: Confirm no `is_char_boundary` references remain in `lookalike.rs`**

```bash
rg -n 'is_char_boundary' crates/rimap-content/src/lookalike.rs
```
Expected: empty (no matches).

- [ ] **Step 6: Run full `rimap-content` test suite**

```bash
cargo test -p rimap-content --quiet
```
Expected: PASS.

- [ ] **Step 7: Lint**

```bash
cargo clippy -p rimap-content --all-targets --all-features -- -D warnings
```
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-content/src/lookalike.rs
git commit -m "refactor(rimap-content): use truncate_graphemes in scan_body_urls

Replaces the inline is_char_boundary backward walk with a call to the
canonical unicode::truncate_graphemes helper. Behaviour is unchanged:
the body is cut at a grapheme-cluster boundary <= MAX_LINKIFY_SCAN_BYTES
before being passed to linkify. The cost is one bounded (64 KiB)
allocation per audit pass, which is acceptable on this path.

Closes part of #194."
```

---

## Task 2: `rimap-server` — delete `truncate_string`, inline `truncate_graphemes`

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:115-126` (call sites in `handle`)
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:149-161` (delete `truncate_string`)
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:163-214` (delete the six `truncate_string` unit tests)

**Design note:** `rimap-server` already declares `rimap-content` as a path dep (see `Cargo.toml:35`). The wrapper `truncate_string` exists only to host the boundary walk. Once the walk is replaced with `truncate_graphemes`, the wrapper has no remaining responsibility — inline the calls and delete the wrapper plus its tests. The canonical `truncate_graphemes` already has stronger tests in `rimap-content::unicode` covering each of the same cases (`truncate_under_limit_is_passthrough`, `truncate_exact_limit`, `truncate_ascii_cuts_cleanly`, `truncate_preserves_grapheme_cluster`, `truncate_zero_max_bytes_returns_empty`).

- [ ] **Step 1: Read the current `handle` function around the truncation calls**

Confirm lines 115–126 currently read:

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

- [ ] **Step 2: Replace both call sites with direct `truncate_graphemes` calls**

In `crates/rimap-server/src/tools/retrieval/fetch_message.rs`, replace the block above with:

```rust
    if let Some(max) = input.max_body_bytes {
        if body_text.len() > max {
            body_text = rimap_content::unicode::truncate_graphemes(&body_text, max);
            truncated = true;
        }
        if let Some(html) = &mut body_html
            && html.len() > max
        {
            *html = rimap_content::unicode::truncate_graphemes(html, max);
            truncated = true;
        }
    }
```

- [ ] **Step 3: Delete the `truncate_string` helper**

Delete lines 149–161 of `crates/rimap-server/src/tools/retrieval/fetch_message.rs`:

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

Delete the entire `#[cfg(test)] mod tests` block at lines 163–214 of `crates/rimap-server/src/tools/retrieval/fetch_message.rs`. The tests being removed:
- `truncate_below_max_is_noop`
- `truncate_at_exact_max_is_noop`
- `truncate_lops_off_trailing_bytes`
- `truncate_respects_utf8_char_boundary`
- `truncate_to_zero_yields_empty_string`
- `truncate_keeps_full_multibyte_char_when_possible`

Each is now redundantly covered by tests in `rimap-content/src/unicode.rs` (`truncate_under_limit_is_passthrough`, `truncate_exact_limit`, `truncate_ascii_cuts_cleanly`, `truncate_preserves_grapheme_cluster`, `truncate_zero_max_bytes_returns_empty`).

- [ ] **Step 5: Confirm no `is_char_boundary` references remain in `fetch_message.rs`**

```bash
rg -n 'is_char_boundary|truncate_string' crates/rimap-server/src/tools/retrieval/fetch_message.rs
```
Expected: empty (no matches).

- [ ] **Step 6: Run `rimap-server` tests**

```bash
cargo test -p rimap-server --quiet
```
Expected: PASS. The deleted unit tests reduce the test count by 6; verify only those are missing.

- [ ] **Step 7: Lint**

```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/fetch_message.rs
git commit -m "refactor(rimap-server): use truncate_graphemes in fetch_message

Inlines two calls to the canonical rimap_content::unicode::truncate_graphemes
at the body_text and body_html truncation sites in fetch_message::handle,
and removes the now-empty truncate_string wrapper plus its unit tests
(redundant with unicode::truncate_graphemes's own coverage).

Closes part of #194."
```

---

## Task 3: `rimap-audit` — module-local grapheme helper for provenance

**Files:**
- Modify: `crates/rimap-audit/Cargo.toml` (add `unicode-segmentation` dep)
- Modify: `crates/rimap-audit/src/writer/provenance.rs:71-79` (replace inline boundary walk)
- Test: `crates/rimap-audit/src/writer/provenance.rs` tests module (add multi-byte regression)

**Design note:** `rimap-audit` does NOT currently depend on `rimap-content`, and adding that dep would pull mail-parser, scraper, ammonia, idna, and the confusables table into the audit crate's compile graph. The issue explicitly permits a module-local helper for this case ("If a module-local helper is preferred (to avoid the dep), copy the implementation but reference `unicode::truncate_graphemes` as the canonical reference"). We add `unicode-segmentation` (a tiny, no-deps pure-Rust crate already in workspace deps) and inline a 6-line helper that mirrors `truncate_graphemes`'s algorithm. The doc comment names the canonical helper as the source of truth.

- [ ] **Step 1: Add a failing multi-byte regression test**

Open `crates/rimap-audit/src/writer/provenance.rs`. Inside the `#[cfg(test)] mod tests` block (after `oversize_message_id_is_truncated_with_suffix` at ~line 200), add:

```rust
    #[test]
    fn oversize_multibyte_message_id_truncates_at_grapheme_boundary() {
        // Regression: a Message-ID that exceeds MAX_MESSAGE_ID_LEN with
        // a multi-byte grapheme cluster straddling the cap byte must
        // not panic and must yield a valid UTF-8 prefix + the
        // "…[truncated]" suffix.
        let mut b = ProvenanceBuffer::new(60);
        // 997 ASCII bytes ('a' x 997) + a 2-byte char ('é') + filler.
        // MAX_MESSAGE_ID_LEN is 998, so the cap lands inside 'é'.
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
        // The body must be a valid UTF-8 string ending at a grapheme
        // boundary <= MAX_MESSAGE_ID_LEN. Since 'é' (2 bytes) starts
        // at byte 997 and would push past 998, it must be dropped
        // entirely — leaving exactly 997 'a's plus the suffix.
        let suffix = "\u{2026}[truncated]";
        let prefix_len = stored.len() - suffix.len();
        assert_eq!(prefix_len, 997, "expected 997-byte prefix in {stored:?}");
    }
```

- [ ] **Step 2: Run the new test to verify it fails**

```bash
cargo test -p rimap-audit --lib writer::provenance::tests::oversize_multibyte_message_id_truncates_at_grapheme_boundary
```
Expected: PASS already (the existing `is_char_boundary` walk is char-safe), OR FAIL on the prefix-length assertion if the existing walk lands at byte 998 (mid-codepoint would panic; backward walk to 997 means the helper currently truncates to 997 ASCII bytes — which is what we expect). Either way, this test will guard the refactor.

If it passes pre-refactor, that's expected — the existing implementation is already char-boundary-safe. The test is a regression guard for the refactor.

- [ ] **Step 3: Add `unicode-segmentation` as a dep on `rimap-audit`**

Open `crates/rimap-audit/Cargo.toml`. In the `[dependencies]` block, add (alphabetically — between `tracing` and `async-channel` won't sort cleanly; place it near the other workspace deps; the file already mixes ordering):

```toml
unicode-segmentation = { workspace = true }
```

Recommended placement: after the `tracing = { workspace = true }` line.

- [ ] **Step 4: Replace the inline boundary walk with a module-local helper**

In `crates/rimap-audit/src/writer/provenance.rs`, find the block at lines 70–79:

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

Then add the helper function at the end of the file's top-level (immediately before the `#[cfg(test)] mod tests` block):

```rust
/// Truncate `s` in-place to the largest prefix that ends at a grapheme
/// cluster boundary and has byte length <= `max_bytes`.
///
/// This is a module-local copy of the algorithm in
/// `rimap_content::unicode::truncate_graphemes` (the canonical
/// reference). It is duplicated here to avoid pulling the full
/// `rimap-content` API surface (mail-parser, scraper, ammonia, idna)
/// into `rimap-audit` for one helper.
fn truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize) {
    use unicode_segmentation::UnicodeSegmentation;
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

- [ ] **Step 5: Run the regression test plus all existing provenance tests**

```bash
cargo test -p rimap-audit --lib writer::provenance::tests
```
Expected: all tests PASS, including the new `oversize_multibyte_message_id_truncates_at_grapheme_boundary`.

- [ ] **Step 6: Confirm no `is_char_boundary` references remain in `provenance.rs`**

```bash
rg -n 'is_char_boundary' crates/rimap-audit/src/writer/provenance.rs
```
Expected: empty (no matches).

- [ ] **Step 7: Run full `rimap-audit` test suite**

```bash
cargo test -p rimap-audit --quiet
```
Expected: PASS.

- [ ] **Step 8: Lint**

```bash
cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings
```
Expected: no warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-audit/Cargo.toml crates/rimap-audit/src/writer/provenance.rs
git commit -m "refactor(rimap-audit): grapheme-safe truncation in provenance buffer

Replaces the inline is_char_boundary backward walk in ProvenanceBuffer::record_at
with a module-local truncate_at_grapheme_boundary helper backed by
unicode-segmentation. The helper mirrors the algorithm of the canonical
rimap_content::unicode::truncate_graphemes (cited in the doc comment); it
lives locally to avoid pulling mail-parser, scraper, ammonia, and idna
into rimap-audit's compile graph.

Adds a regression test that constructs a Message-ID with a multi-byte
grapheme straddling MAX_MESSAGE_ID_LEN.

Closes part of #194."
```

---

## Task 4: Workspace verification & wrap-up

- [ ] **Step 1: Confirm done criteria — no hand-rolled boundary walks anywhere in `crates/`**

```bash
rg -n 'is_char_boundary|floor_char_boundary' crates/ --type rust
```
Expected output (only the canonical helper's location and the one harmless test assertion if it's still there):

```
crates/rimap-server/src/tools/retrieval/fetch_message.rs:???:    assert!(s.is_char_boundary(s.len()));   ← if test wasn't deleted
```

Wait — re-check: the assertion at `fetch_message.rs:196` was inside the `truncate_string` test module. After Task 2 deletes that module, this match disappears too. Expected final output: **empty**.

- [ ] **Step 2: Confirm the canonical helper's signature is still the only `truncate_graphemes` definition**

```bash
rg -n 'fn truncate_graphemes' crates/ --type rust
```
Expected:
```
crates/rimap-content/src/unicode.rs:160:pub fn truncate_graphemes(input: &str, max_bytes: usize) -> String {
```
(Only one match.)

- [ ] **Step 3: Run the full workspace test suite**

```bash
cargo test --workspace --quiet
```
Expected: PASS. Test count should be: baseline − 6 (deleted `truncate_string` tests) + 1 (new provenance multi-byte test) = baseline − 5.

- [ ] **Step 4: Run workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: no warnings.

- [ ] **Step 5: Run cargo deny**

```bash
cargo deny check
```
Expected: PASS. (`unicode-segmentation` was already in the workspace deps and used by `rimap-content`, so no new licenses or advisories enter the graph.)

- [ ] **Step 6: Optional — run mutation tests on the changed sites**

The lookalike.rs change site has prior cargo-mutants annotations; the boundary loop those annotations described is gone, but we should confirm the new code surface doesn't introduce surviving mutants in the immediate area.

```bash
cargo mutants --in-place -p rimap-content -f crates/rimap-content/src/lookalike.rs --line-filter 186-200
cargo mutants --in-place -p rimap-audit -f crates/rimap-audit/src/writer/provenance.rs
cargo mutants --in-place -p rimap-server -f crates/rimap-server/src/tools/retrieval/fetch_message.rs
```
Expected: any survivors should be either trivially equivalent (annotated) or covered by an additional test before opening the PR. If running mutation tests is too slow for this PR, defer to a follow-up — note in the PR body.

- [ ] **Step 7: Open PR**

```bash
git push -u origin refactor/issue-194-truncate-graphemes
gh pr create --title "refactor(workspace): consolidate UTF-8 boundary walks onto truncate_graphemes (#194)" --body "$(cat <<'EOF'
## Summary
- Replace the three remaining hand-rolled `is_char_boundary` backward walks with the canonical `rimap_content::unicode::truncate_graphemes` helper (or a documented module-local copy where a cross-crate dep would be too heavy).
- Closes #194.

## Sites changed
- `rimap-content/src/lookalike.rs::scan_body_urls` — direct call to `crate::unicode::truncate_graphemes`.
- `rimap-server/src/tools/retrieval/fetch_message.rs` — inlined two `truncate_graphemes` calls; removed the now-empty `truncate_string` wrapper and its six unit tests (redundant with `unicode::truncate_graphemes` coverage).
- `rimap-audit/src/writer/provenance.rs` — module-local `truncate_at_grapheme_boundary` backed by `unicode-segmentation`, documented as a copy of the canonical helper. Avoids pulling `mail-parser`/`scraper`/`ammonia`/`idna` into `rimap-audit`.

## Test plan
- [ ] `cargo test --workspace` PASS
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo deny check` PASS
- [ ] `rg -n 'is_char_boundary|floor_char_boundary' crates/` returns no hand-rolled boundary walks
- [ ] New regression test `oversize_multibyte_message_id_truncates_at_grapheme_boundary` covers the audit site

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review checklist (already run before saving this plan)

- **Spec coverage:** All three sites listed in the issue are addressed. The done-criteria grep is verified in Task 4 Step 1. Each site has a multi-byte test (lookalike's was pre-existing; fetch_message's were redundant and removed; provenance's is added in Task 3 Step 1).
- **Placeholder scan:** No TBDs, no "implement later", no "similar to Task N", no unresolved error-handling stubs.
- **Type consistency:** `truncate_graphemes(input: &str, max_bytes: usize) -> String` is referenced consistently in Tasks 1 and 2. The local helper `truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize)` in Task 3 has a different signature (in-place) by design.
- **Dep accounting:** `unicode-segmentation = "1.13"` is already in workspace deps (Cargo.toml:108), so Task 3's `rimap-audit/Cargo.toml` change is a one-line workspace-true entry.
- **Cycle check:** `rimap-audit → unicode-segmentation` (no cycle); we deliberately do NOT add `rimap-audit → rimap-content` to keep the audit crate's compile graph small.
