# Issue #225 — Re-extract `rimap-content` Mutation-Cleanup Waves Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-apply on `main` the mutation-cleanup test waves from archived PRs #196 (issue #192, `rimap-content` waves) and #198 (issue #193, `epvme_runner` waves) — pure test additions plus a small set of `// cargo-mutants: known-equivalent` annotations and the `mutation-baseline.md` survivor inventory. Drives the `rimap-content` non-`bin/` cargo-mutants survivor count back to 15 (all known-equivalent) and the `bin/epvme_runner.rs` count to 5 (all known-equivalent), matching the archive baseline.

**Architecture:** Per-commit cherry-pick from `archive/daemon-experiment` for the test-only commits whose surrounding context matches `main`, with two exceptions handled by fresh-application:
1. Commit `4e56b11` (lookalike.rs) — three of its four annotations and three of its four tests still apply, but the `scan_body_urls` `> with >=` annotation references an `is_char_boundary` walk that issue #224 deleted from main, and the `scan_body_urls_handles_multi_byte_char_at_scan_boundary` test already exists on main from #224. Fresh-applied, dropping the stale annotation and the duplicate test.
2. Commit `300556c` (lookalike `-= with +=` annotation) — entirely stale; the annotated code path was deleted by #224. Skipped.

For the mutation-baseline cherry-picks (`a5cdab3`, `2e69b7d`), three rows are dropped: two `lookalike.rs` rows referencing the deleted `is_char_boundary` walk and one `parse/mime_scrub.rs:105` row whose `+ 1` rationale doesn't hold for main's `+ 2` (the upstream fix `b7e8bfe` for back-to-back encoded-words shipped in archive between `974508b^` and main and was re-extracted to main via PR #232; archive's annotation site no longer applies). The remaining two `parse/mime_scrub.rs` rows have their line numbers renumbered (`:149` → `:124`, `:213` → `:174`) to match main's actual annotation sites. Task 19 (`cargo mutants`) will surface any real survivor at the dropped sites under main's current math; if found, a row gets added with rigorous rationale at that point.

The reapplied tests are pure additions to existing `mod tests` blocks (and to one integration test file, `crates/rimap-content/tests/epvme_integration.rs`) plus six in-source `// cargo-mutants: known-equivalent` annotations on production code. No production-code logic changes. No new dependencies. No new files.

**Tech Stack:** Rust 2024, MSRV 1.88.0, `cargo-mutants` (run via `just mutants-crate <name>` with `--jobs 2`).

**Source issue:** [#225](https://github.com/randomparity/rusty-imap-mcp/issues/225) (Phase-2 re-extract of #192 and #193)

**Original PRs (archived on `archive/daemon-experiment`):**
- [#196](https://github.com/randomparity/rusty-imap-mcp/pull/196) `feat/issue-192-rimap-content-mutation-cleanup` — merged at `2410c38`. Contains 12 test-wave commits + 1 mutation-baseline finalization. Issue #192.
- [#198](https://github.com/randomparity/rusty-imap-mcp/pull/198) `feat/issue-193-epvme-runner-mutation-cleanup` — merged at `f873db2`. Contains 2 planning-doc commits (skipped — see below), 5 test/annotation commits, and 1 mutation-baseline finalization. Issue #193.
- PR #195 (`b2f833e`) added a now-stale follow-up plan that drove #196; not re-extracted because this plan supersedes it.

**Reference commits on archive (chronological, with re-extract disposition):**

| Archive SHA | Disposition | Subject |
|---|---|---|
| `f629f0d` | cherry-pick | `test(rimap-content): close mutation gaps in parse/headers.rs` |
| `c69a984` | cherry-pick | `test(rimap-content): close mutation gaps in parse/filename.rs` |
| `33a8df5` | cherry-pick | `test(rimap-content): close mutation gaps in parse/bodies.rs` |
| `974508b` | cherry-pick + drop one annotation | `test(rimap-content): close mutation gaps in parse/mime_scrub.rs` (the `+ 1` annotation on `detect_smuggling_spans` is dropped — main has `+ 2` after PR #228) |
| `655754a` | cherry-pick | `test(rimap-content): close mutation gaps in parse/{meta,attachments,mod}.rs` |
| `a6a49ee` | cherry-pick | `test(rimap-content): close mutation gaps in html/style_parse.rs` |
| `eee5a11` | cherry-pick | `test(rimap-content): close mutation gaps in html/mismatch.rs` |
| `7643c5d` | cherry-pick + rename | `test(rimap-content): close mutation gaps in html/{extract,mod}.rs` (3 `sanitize_html(` call sites in test bodies must be renamed to `process(` — main renamed the function via PR #232) |
| `4e56b11` | **fresh-apply** | `test(rimap-content): close mutation gaps in lookalike.rs` (drops `scan_body_urls` annotation and `scan_body_urls_handles_multi_byte_char_at_scan_boundary` test — both stale post-#224) |
| `c147d78` | cherry-pick | `test(rimap-content): close mutation gaps in threading/unicode/plumbing` |
| `300556c` | **skip** | `test(rimap-content): annotate -= with += in scan_body_urls as known-equivalent` (entire annotation site deleted by #224) |
| `a5cdab3` | cherry-pick + edit | `docs(test-strategy): finalise rimap-content mutation-baseline` (drops two `lookalike.rs:195` and `lookalike.rs:205` rows; rewrites `mime_scrub.rs:105` row's `+ 1` to `+ 2`) |
| `cd2c50e` | cherry-pick | `test(rimap-content): triage epvme_runner parse_args mutants` |
| `bf83314` | cherry-pick | `test(rimap-content): triage epvme_runner dataset-loop mutants` |
| `62589f4` | cherry-pick | `test(rimap-content): annotate epvme_runner print_summary mutants` |
| `c52e3ed` | cherry-pick | `test(rimap-content): kill epvme_runner write_json_report empty-parent mutant` |
| `d358f5e` | cherry-pick | `test(rimap-content): kill epvme_runner read_failure_count mutant` |
| `2e69b7d` | cherry-pick | `docs(test-strategy): finalise mutation-baseline for issue #193` |

Also-archived but **not re-extracted**:
- `cbba4b7` (PR #195's followup plan) — superseded by this plan.
- `00949ba` and `03093bf` (PR #198's planning docs) — historical artifacts; this plan supersedes.

**Baseline test count (verified during plan write):** `cargo test --workspace --quiet` → **991 passed, 0 failed, 0 ignored**.

**Expected test count after plan completes:** **991 + 66 = 1057** new tests across the 16 applied commits (4e56b11 contributes 3 net-new tests, not 4, because `scan_body_urls_handles_multi_byte_char_at_scan_boundary` is already on main). The new tests break down as:

| Commit | New `#[test]` markers | Cumulative |
|---|---|---|
| `f629f0d` parse/headers.rs | 5 | 996 |
| `c69a984` parse/filename.rs | 12 | 1008 |
| `33a8df5` parse/bodies.rs | 5 | 1013 |
| `974508b` parse/mime_scrub.rs | 3 | 1016 |
| `655754a` parse/{meta,attachments,mod}.rs | 5 | 1021 |
| `a6a49ee` html/style_parse.rs | 6 | 1027 |
| `eee5a11` html/mismatch.rs | 5 | 1032 |
| `7643c5d` html/{extract,mod}.rs | 5 | 1037 |
| `4e56b11` lookalike.rs (fresh-apply) | 3 | 1040 |
| `c147d78` threading/unicode/plumbing | 7 | 1047 |
| `cd2c50e` epvme parse_args | 3 | 1050 |
| `bf83314` epvme dataset-loop | 5 | 1055 |
| `c52e3ed` epvme write_json_report | 1 | 1056 |
| `d358f5e` epvme read_failure_count | 1 | 1057 |

`62589f4` (epvme print_summary) and `a5cdab3`/`2e69b7d` (baseline docs) add no tests. Mutation-cleanup confirms via `cargo mutants` in Task 19.

---

## File Map

**Modified — `rimap-content` test code (test additions inside `mod tests`):**
- `crates/rimap-content/src/parse/headers.rs` — 5 tests (Task 1).
- `crates/rimap-content/src/parse/filename.rs` — 12 tests (Task 2).
- `crates/rimap-content/src/parse/bodies.rs` — 5 tests (Task 3).
- `crates/rimap-content/src/parse/mime_scrub.rs` — 3 tests + 2 annotations (Task 4; archive's third annotation referencing `+ 1` is dropped — main has `+ 2` after PR #228).
- `crates/rimap-content/src/parse/meta.rs` — 1 test (Task 5).
- `crates/rimap-content/src/parse/attachments.rs` — 1 test (Task 5).
- `crates/rimap-content/src/parse/mod.rs` — 3 tests (Task 5).
- `crates/rimap-content/src/html/style_parse.rs` — 6 tests + 1 annotation (Task 6).
- `crates/rimap-content/src/html/mismatch.rs` — 5 tests + 1 annotation (Task 7).
- `crates/rimap-content/src/html/extract.rs` — 1 test (Task 8).
- `crates/rimap-content/src/html/mod.rs` — 4 tests (Task 8; 3 call sites need `sanitize_html` → `process` rename).
- `crates/rimap-content/src/lookalike.rs` — 3 tests + 4 annotations (Task 9; fresh-applied).
- `crates/rimap-content/src/threading.rs` — 5 tests (Task 10).
- `crates/rimap-content/src/unicode.rs` — 1 test (Task 10).
- `crates/rimap-content/src/raw_parts.rs` — 3 annotations (Task 10).
- `crates/rimap-content/src/lib.rs` — 1 test (Task 10).
- `crates/rimap-content/src/bin/epvme_runner.rs` — 9 tests + 4 annotations (Tasks 12–16).
- `crates/rimap-content/tests/epvme_integration.rs` — 4 tests (Tasks 13–15).

**Modified — design/test-strategy docs:**
- `docs/superpowers/specs/test-strategy/mutation-baseline.md` — created in Task 11 (was deleted in the daemon rollback); rimap-content table populated; bin/epvme_runner.rs subsection populated in Task 17.

**No production-code logic changes.** 15 annotation comments on production code: 1 in `html/style_parse.rs`, 1 in `html/mismatch.rs`, 4 in `lookalike.rs`, 2 in `parse/mime_scrub.rs`, 3 in `raw_parts.rs`, 4 in `bin/epvme_runner.rs`. One archive annotation in `parse/mime_scrub.rs` (the `+ 1` rationale on `detect_smuggling_spans`) is deliberately dropped — main has `+ 2` after PR #228 (`b7e8bfe`), so the archive rationale doesn't hold; Task 19 will surface any real survivor under the new math. Zero new files apart from the re-created `mutation-baseline.md`.

Each task produces one self-contained commit, except Tasks 12–14 which group small same-file epvme commits if conflicts surface — see task notes.

---

## Task 0: Branch and pre-flight verification

**Files:** none modified.

- [ ] **Step 1: Confirm `main` is clean and up-to-date**

Run: `git status && git log --oneline -1`
Expected: working tree clean; HEAD at `2733705 Merge pull request #233 ...` or later. Stop if uncommitted changes exist.

- [ ] **Step 2: Create the working branch off `main`**

Run:
```bash
git checkout -b phase2/issue-225-rimap-content-mutation-waves-rextract main
```
Expected: `Switched to a new branch 'phase2/issue-225-rimap-content-mutation-waves-rextract'`. From this point forward, never commit directly to `main`.

- [ ] **Step 3: Confirm the archive commits are reachable**

Run: `for sha in f629f0d c69a984 33a8df5 974508b 655754a a6a49ee eee5a11 7643c5d 4e56b11 c147d78 a5cdab3 cd2c50e bf83314 62589f4 c52e3ed d358f5e 2e69b7d; do git log --oneline -1 "$sha" >/dev/null 2>&1 && echo "OK $sha" || echo "MISSING $sha"; done`
Expected: 17 lines of `OK <sha>`. If any are missing, run `git fetch origin 'archive/daemon-experiment'` to pull them in.

- [ ] **Step 4: Capture baseline test count**

Run: `cargo test --workspace --quiet 2>&1 | grep -E "^test result:" | awk '{p+=$4; f+=$6; i+=$8} END {print "passed=" p " failed=" f " ignored=" i}'`
Expected: `passed=991 failed=0 ignored=0`. Note the count for Task 18 verification.

- [ ] **Step 5: Capture baseline clippy state**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -5`
Expected: no warnings. Stop and fix any pre-existing warnings before proceeding — they would otherwise mask new ones introduced by this work.

- [ ] **Step 6: Confirm the `mutation-baseline.md` parent dir exists and the file is absent**

Run: `ls docs/superpowers/specs/ 2>&1 | head -10; ls docs/superpowers/specs/test-strategy 2>&1`
Expected: `test-strategy` directory does **not** exist (was deleted in the daemon rollback). `docs/superpowers/specs/` exists. Task 11 creates the directory and file.

---

## Task 1: Re-extract `parse/headers.rs` mutation-coverage tests (cherry-pick `f629f0d`)

**Files:**
- Modify: `crates/rimap-content/src/parse/headers.rs` (5 tests appended to `mod tests`).

**Cherry-pick disposition:** clean — `974508b^:headers.rs` and `HEAD:headers.rs` are byte-identical, so the cherry-pick patch applies without fuzz.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x f629f0d`
Expected: cherry-pick succeeds with no conflicts. The new commit message is the original subject + body + a `(cherry picked from commit f629f0d…)` line.

- [ ] **Step 2: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib parse::headers::tests`
Expected: all PASS, including the five new tests:
- `parse_rejects_header_count_above_max`
- `parse_accepts_header_count_at_max`
- `parse_extracts_in_reply_to_header`
- `parse_extracts_references_header_with_multiple_ids`
- `parse_extracts_mailing_list_with_only_list_id`

- [ ] **Step 3: Run the wider crate to catch any cross-module regression**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5`
Expected: workspace passes (count rises by 5 over the baseline).

- [ ] **Step 4: Lint**

Run: `cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: no warnings.

---

## Task 2: Re-extract `parse/filename.rs` mutation-coverage tests (cherry-pick `c69a984`)

**Files:**
- Modify: `crates/rimap-content/src/parse/filename.rs` (12 tests appended to `mod tests`).

**Cherry-pick disposition:** clean — `c69a984^:filename.rs` and `HEAD:filename.rs` are byte-identical.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x c69a984`
Expected: cherry-pick succeeds with no conflicts.

- [ ] **Step 2: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib parse::filename::tests`
Expected: all PASS, including 12 new tests covering `extract_file_label`, `is_dangerous_filename`, `kind_of_filename`, and `infer_filename_from_part`.

- [ ] **Step 3: Run the full crate**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5`
Expected: cumulative count is now 996 + 12 = 1008.

- [ ] **Step 4: Lint**

Run: `cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: no warnings.

---

## Task 3: Re-extract `parse/bodies.rs` mutation-coverage tests (cherry-pick `33a8df5`)

**Files:**
- Modify: `crates/rimap-content/src/parse/bodies.rs` (5 tests appended to `mod tests`).

**Cherry-pick disposition:** **expect minor context drift**. `33a8df5^:bodies.rs` is byte-identical to current `main` for the test-block region (lines 240+ onward), but archive's pre-context for two hunks may include the `html::sanitize_html` doc-comment string while `main` reads `html::process` (renamed by PR #232). If the cherry-pick reports conflicts, resolve by keeping `main`'s `html::process` text and accepting the archive's test additions verbatim.

- [ ] **Step 1: Attempt cherry-pick with provenance**

Run: `git cherry-pick -x 33a8df5`
Expected outcomes:
- Best case: cherry-pick succeeds with no conflicts (test additions sit at end of `mod tests`, far from any docstring divergence).
- If conflicts: continue to Step 2.

- [ ] **Step 2: Resolve conflicts (if any) — keep main's API names, archive's test additions**

If `git status` shows `bodies.rs` as `both modified`, open it. The conflict markers will surround the doc-comment hunk near `decode_text_part` and/or `sanitize_html_part`. The resolution rule: keep the side that says `html::process` (main's). Then run:
```bash
git add crates/rimap-content/src/parse/bodies.rs
git cherry-pick --continue
```
The `--continue` will reuse the original commit message; verify the `(cherry picked from commit 33a8df5…)` line is preserved.

- [ ] **Step 3: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib parse::bodies::tests`
Expected: all PASS, including 5 new tests covering `decode_text_part`, `extract_bodies` charset handling, and the HTML-merge fallback path.

- [ ] **Step 4: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative test count 1013; no warnings.

---

## Task 4: Re-extract `parse/mime_scrub.rs` mutation-coverage tests (cherry-pick `974508b`, drop one stale annotation)

**Files:**
- Modify: `crates/rimap-content/src/parse/mime_scrub.rs` — adds 3 tests inside a new `mod mime_scrub_tests` block plus 2 `// cargo-mutants: known-equivalent` annotations on `locate_encoded_word_end` (line 124 on main; archive line 143) and `split_header_lines` (line 174 on main; archive line 206). The third archive annotation, on `detect_smuggling_spans` (archive line 96), references `replacing + 1 with * 1` — **stale on main** because PR #228 (`b7e8bfe`, landed via #232) changed `scan_from = end_rel_to_header + 1` to `+ 2`. Drop that annotation.

**Cherry-pick disposition:** **expect context drift on three production-code hunks**. `974508b^:mime_scrub.rs` includes archive-only commits `b7e8bfe` (back-to-back encoded-words fix; `+ 1` → `+ 2`) and `c96b3c1` (consolidate UTF-8 truncation), neither of which is on `main`. The patch's pre-context lines on the `detect_smuggling_spans` annotation hunk reference the deleted `Using +2 would skip the '=' at end_rel_to_header+1` comments and the `+ 1` line; those won't match. Tests append to the end of the file as a new `mod mime_scrub_tests`, which should apply cleanly because there's no pre-existing block at that position.

- [ ] **Step 1: Attempt cherry-pick with provenance**

Run: `git cherry-pick -x 974508b`
Expected outcome: a conflict on `mime_scrub.rs` at the `detect_smuggling_spans` annotation hunk. The other two annotation hunks (`locate_encoded_word_end` and `split_header_lines`) and the test-block addition should apply via fuzz.

- [ ] **Step 2: Resolve the `detect_smuggling_spans` conflict — drop the stale annotation**

If `git status` shows `mime_scrub.rs` as `both modified`, open it. Any conflict markers around `scan_from = end_rel_to_header + 2` (line 86 on main) should be resolved by **keeping main's text exactly** — do NOT add the `+ 1` annotation. The annotation's rationale (`replacing + 1 with * 1 is observably indistinguishable`) does not hold for `+ 2` because the off-by-one math is different; Task 19 (`cargo mutants`) will surface a real survivor at this site if one exists, and the rationale will need to be rewritten then with rigorous justification.

The other two annotations should land at:
- Line 123 (above `if start_offset < first.len()` on line 124) — `// cargo-mutants: known-equivalent — < first.len() vs <= first.len() ...`
- Line 173 (above `if line_start < headers.len()` on line 174) — `// cargo-mutants: known-equivalent — < with > here is observably ...`

If either annotation is missing because of conflict-resolution shrapnel, manually paste the comment block (verbatim from `git show 974508b -- crates/rimap-content/src/parse/mime_scrub.rs`).

- [ ] **Step 3: Verify the test block was added cleanly**

The cherry-pick should append a `#[cfg(test)] mod mime_scrub_tests { … }` block to the end of the file with three tests:
- `scrub_smuggling_caps_dropped_names_at_eight`
- `detect_smuggling_does_not_revisit_processed_headers` (kills `+ with -` on `idx = end_idx + 1`)
- `detect_smuggling_skips_logical_end_idx_after_later_header`

Run: `rg -n '^mod mime_scrub_tests' crates/rimap-content/src/parse/mime_scrub.rs`
Expected: one match. If zero, append the block manually from `git show 974508b -- crates/rimap-content/src/parse/mime_scrub.rs`.

- [ ] **Step 4: Stage and commit**

```bash
git add crates/rimap-content/src/parse/mime_scrub.rs
git cherry-pick --continue
```
The `--continue` reuses the original message; preserve the `(cherry picked from commit 974508b…)` line and add a one-line note above it: `Note: dropped the detect_smuggling_spans `+ 1` annotation — main has `+ 2` after PR #228; rationale doesn't hold.`

- [ ] **Step 5: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib parse::mime_scrub::mime_scrub_tests`
Expected: all PASS. Three new tests.

- [ ] **Step 6: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative test count 1016; no warnings.

---

## Task 5: Re-extract `parse/{meta,attachments,mod}.rs` mutation-coverage tests (cherry-pick `655754a`)

**Files:**
- Modify: `crates/rimap-content/src/parse/meta.rs` (1 test).
- Modify: `crates/rimap-content/src/parse/attachments.rs` (1 test).
- Modify: `crates/rimap-content/src/parse/mod.rs` (3 tests).

**Cherry-pick disposition:** mostly clean. `parse/mod.rs` is large (958 lines on main, 1021 on archive) and may have minor context drift in the docs-comment region above the test additions. `parse/meta.rs` and `parse/attachments.rs` are byte-identical to archive parents.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x 655754a`
Expected: succeeds via fuzz. If conflicts on `parse/mod.rs`, keep `main`'s production-code text and the archive's test additions per the same rule as Task 3/4.

- [ ] **Step 2: Run affected files' tests**

Run: `cargo test -p rimap-content --lib parse::meta::tests parse::attachments::tests parse::tests`
Expected: PASS. Five new tests above the baseline.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative test count 1021; no warnings.

---

## Task 6: Re-extract `html/style_parse.rs` mutation-coverage tests (cherry-pick `a6a49ee`)

**Files:**
- Modify: `crates/rimap-content/src/html/style_parse.rs` (6 tests + 1 `// cargo-mutants: known-equivalent` annotation on `parse_translate_px` line 67).

**Cherry-pick disposition:** clean — `a6a49ee^:style_parse.rs` is byte-identical to current `main`.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x a6a49ee`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib html::style_parse::tests`
Expected: all PASS, including 6 new tests covering `parse_clip_rect`, `parse_translate_px`, and `to_zero_or_negative_or_too_small`.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1027; no warnings.

---

## Task 7: Re-extract `html/mismatch.rs` mutation-coverage tests (cherry-pick `eee5a11`)

**Files:**
- Modify: `crates/rimap-content/src/html/mismatch.rs` (5 tests + 1 `// cargo-mutants: known-equivalent` annotation on `extract_registrable_domain`).

**Cherry-pick disposition:** clean — `eee5a11^:mismatch.rs` is byte-identical to current `main`.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x eee5a11`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib html::mismatch::tests`
Expected: all PASS, including 5 new tests covering `detect_mismatches` and `extract_registrable_domain`.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1032; no warnings.

---

## Task 8: Re-extract `html/{extract,mod}.rs` mutation-coverage tests (cherry-pick `7643c5d` with rename)

**Files:**
- Modify: `crates/rimap-content/src/html/extract.rs` (1 test).
- Modify: `crates/rimap-content/src/html/mod.rs` (4 tests; 3 of them call `sanitize_html(...)` on archive — must be rewritten to `process(...)` on main).

**Cherry-pick disposition:** **expect rename conflicts on `html/mod.rs`**. PR #232 (`mail-parser-panic-isolation`, merged on main as `1c394e6`) renamed `sanitize_html` to `process` and narrowed visibility from `pub` to `pub(crate)`. The archive's new tests use the old `sanitize_html(` symbol. Resolution: rewrite the test bodies to call `process(`.

- [ ] **Step 1: Attempt cherry-pick with provenance**

Run: `git cherry-pick -x 7643c5d`
Expected: conflicts in `html/mod.rs` (the visibility/rename hunks at the top of the file confuse the patch's pre-context). `html/extract.rs` should apply cleanly.

- [ ] **Step 2: Resolve conflicts in `html/mod.rs`**

Open `crates/rimap-content/src/html/mod.rs`. The conflict markers will likely span the file header / `process` declaration. Resolution rule:
- Keep `main`'s production code unchanged (`pub(crate) struct HtmlResult`, `pub(crate) fn process`, no `testutil` re-export comments).
- Take the archive's added `mod tests` block content, but rewrite every occurrence of `sanitize_html(` in the new test bodies to `process(`.

If easier, abort the cherry-pick and apply the test additions manually:
```bash
git cherry-pick --abort
git show 7643c5d -- crates/rimap-content/src/html/extract.rs | git apply --3way
git show 7643c5d -- crates/rimap-content/src/html/mod.rs | sed 's/sanitize_html(/process(/g' | git apply --3way --reject
```
Inspect any `*.rej` file and apply the surviving test additions by hand. The four new tests to add inside `mod tests` of `html/mod.rs` are:
- `process_oversize_charset_label_returns_limit_exceeded`
- `process_returns_html_warnings_for_dangerous_input`
- `process_extracts_anchor_hrefs_for_lookalike_audit`
- `process_passes_charset_through_to_decoder`

(All four were named `sanitize_html_*` on archive — rename to `process_*` on main for consistency with PR #232's API and the existing `process_oversize_input_returns_limit_exceeded` test on main.)

The one new test to add to `html/extract.rs` is `extract_text_with_visible_links_renders_anchor_text_then_url`.

- [ ] **Step 3: Commit the merged result**

```bash
git add crates/rimap-content/src/html/extract.rs crates/rimap-content/src/html/mod.rs
git cherry-pick --continue
```
The `--continue` reuses the original message; ensure the commit message ends with `(cherry picked from commit 7643c5d…)` and add a one-line note above that line: `rimap-content: rewrote sanitize_html → process call sites (renamed by #232).`

- [ ] **Step 4: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib html::extract::tests html::tests`
Expected: all PASS. The 5 new tests should appear in the count.

- [ ] **Step 5: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1037; no warnings.

---

## Task 9: Re-extract `lookalike.rs` mutation-coverage tests (fresh-apply, drop stale parts of `4e56b11`)

**Files:**
- Modify: `crates/rimap-content/src/lookalike.rs` (4 `// cargo-mutants: known-equivalent` annotations + 3 new tests).

**Architecture note:** The archive commit `4e56b11` adds 6 annotations and 4 tests. Two of those don't apply on main:
- The `scan_body_urls` `> with >=` annotation references the `is_char_boundary` walk that issue #224 deleted from `main` (the walk is now `crate::unicode::grapheme_cut`). Drop.
- The `scan_body_urls_handles_multi_byte_char_at_scan_boundary` test already exists on `main` from #224 (lines 535–555). Drop.

The other 4 annotations and 3 tests still apply unchanged. Fresh-apply rather than cherry-pick to avoid resolving conflicts on the deleted boundary-walk lines.

- [ ] **Step 1: Add the `label_mixes_scripts` annotation**

In `crates/rimap-content/src/lookalike.rs`, locate `fn label_mixes_scripts` (~line 100). Insert the following annotation immediately above the line `if c.is_ascii_digit() || c == '-' || c == '_' {` (currently line 103):

```rust
        // cargo-mutants: known-equivalent — `||` vs `&&` on either of the
        // two `||` operators produces the same observable behaviour.
        // Each char that the original `continue`s past — ASCII digits,
        // `-`, `_` — has `Script::Common`, which the match below treats
        // as a no-op (Common/Inherited/Unknown are not inserted into the
        // `scripts` set). Whether the loop short-circuits or runs
        // through, the set membership is unchanged.
```

- [ ] **Step 2: Add the two `extract_domain_from_address` annotations**

Locate `fn extract_domain_from_address` (~line 205). Insert above the line `let inner = if let (Some(lt), Some(gt)) = (...)` (currently line 207):

```rust
    // cargo-mutants: known-equivalent — `< with <=` on `lt < gt` is
    // observably identical: `lt == gt` is unreachable when both `rfind`
    // results are `Some`, since `<` and `>` are different characters
    // and a single byte cannot be both. Distinct positions exercise
    // the same arm under either operator.
```

Insert above the line `&trimmed[lt + 1..gt]` (currently line 210):

```rust
        // cargo-mutants: known-equivalent — `+ with *` on `lt + 1` is
        // observably identical for any reachable `lt`. `lt * 1 == lt`
        // shifts the slice start by one byte to include the `<`
        // delimiter; `rsplit_once('@')` then yields the same `(local,
        // domain)` split because the leading `<` lands in the discarded
        // local part, not the domain on the right of `@`.
```

- [ ] **Step 3: Add the `extract_domain_from_url` annotation**

Locate `fn extract_domain_from_url` (~line 245). Insert above the line `if host.is_empty() || !host.contains('.') {` (the branch that early-returns `None`):

```rust
    // cargo-mutants: known-equivalent — `||` vs `&&` here is observably
    // identical: `host.is_empty()` implies `!host.contains('.')`, so
    // the only case the operators differ on is `is_empty=false &&
    // !contains('.')=true` (a non-empty single-label host). Both
    // branches hand control to `Some(host.to_string())` for `||` or
    // skip the early return for `&&`; either way, single-label hosts
    // are filtered downstream by `classify_domain` (which requires a
    // registrable PSL match).
```

- [ ] **Step 4: Add three new tests inside `mod tests`**

Locate the closing `}` of `mod tests` (currently line 556). Insert these three test functions immediately before it (preserving the existing `scan_body_urls_handles_multi_byte_char_at_scan_boundary` test that already lives at lines 535–555 — do NOT duplicate it):

```rust
    #[test]
    fn audit_scans_url_at_byte_offset_2000() {
        // Kills `* with +` on `MAX_LINKIFY_SCAN_BYTES = 64 * 1024`. The
        // mutant flips the constant to 64 + 1024 = 1088, well below
        // 64 KiB. A mixed-script URL placed at byte offset ~2000
        // round-trips a warning under the original cap and is silently
        // dropped under the mutant.
        let prefix = "x".repeat(2000);
        let body = format!("{prefix}https://p\u{0430}ypal.com/account");
        let warnings = run_audit(&empty_meta(), &body, &[]);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::LookalikeMixedScript)),
            "expected a mixed-script warning for URL at byte ~2000, got {warnings:?}",
        );
    }

    #[test]
    fn extract_domain_from_address_strips_angle_brackets_at_position_zero() {
        // Kills `+ with -` on `&trimmed[lt + 1..gt]` in
        // extract_domain_from_address. With `-`, an input whose `<`
        // sits at position 0 (e.g. "<a@b.com>") evaluates `lt - 1`
        // and underflows usize → panics on slicing.
        let result = super::extract_domain_from_address("<a@b.com>");
        assert_eq!(result, Some("b.com".to_string()));
    }

    #[test]
    fn extract_domain_from_address_handles_quoted_brackets() {
        // Kills `< with ==` and `< with >` on the `lt < gt` guard.
        // Original: "Name <a@b.com>" → inner = "a@b.com" → domain "b.com".
        // Mut `==`: 5 == 13 false → inner = trimmed → domain "b.com>".
        // Mut `>`:  5 > 13 false → same as `==`.
        // The original-vs-mutated outputs differ on the trailing `>`.
        let result = super::extract_domain_from_address("Name <a@b.com>");
        assert_eq!(result, Some("b.com".to_string()));
    }
```

- [ ] **Step 5: Run the affected file's tests**

Run: `cargo test -p rimap-content --lib lookalike::tests`
Expected: all PASS, including the three new tests. Total tests in `lookalike::tests` rises by 3.

- [ ] **Step 6: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1040; no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-content/src/lookalike.rs
git commit -m "$(cat <<'EOF'
test(rimap-content): close mutation gaps in lookalike.rs

Adds 3 tests + 4 known-equivalent annotations for cargo-mutants
survivors uncovered by the 2026-04-30 baseline refresh on
lookalike.rs. Re-extract of archive commit 4e56b11 (PR #196), with
two now-stale items dropped:

- The `scan_body_urls` `> with >=` annotation referenced the
  `is_char_boundary` walk that issue #224 (re-extracted via PR
  #233) replaced with `crate::unicode::grapheme_cut`. The new code
  has no equivalent surface for that mutant.
- The `scan_body_urls_handles_multi_byte_char_at_scan_boundary`
  regression test already exists on main from issue #224.

Tests:
- audit_scans_url_at_byte_offset_2000 kills * with + on
  MAX_LINKIFY_SCAN_BYTES = 64 * 1024.
- extract_domain_from_address_strips_angle_brackets_at_position_zero
  kills + with - on `lt + 1` (panics with usize underflow when lt = 0).
- extract_domain_from_address_handles_quoted_brackets kills < with ==
  and < with > on the lt < gt guard.

Annotations document the four remaining mathematically-equivalent
mutations on label_mixes_scripts, extract_domain_from_address, and
extract_domain_from_url.

Refs: #225
Refs: #192 (original work, PR #196 on archive/daemon-experiment)
(re-extracted partial of commit 4e56b11)
EOF
)"
```

---

## Task 10: Re-extract `threading.rs`, `unicode.rs`, `lib.rs`, `raw_parts.rs` mutation-coverage tests (cherry-pick `c147d78`)

**Files:**
- Modify: `crates/rimap-content/src/threading.rs` (5 tests).
- Modify: `crates/rimap-content/src/unicode.rs` (1 test: `filter_codepoints_strips_unicode_tag`).
- Modify: `crates/rimap-content/src/raw_parts.rs` (3 `// cargo-mutants: known-equivalent` annotations on `walk` depth/recursion).
- Modify: `crates/rimap-content/src/lib.rs` (1 test: `extract_returns_message_id_when_header_present`).

**Cherry-pick disposition:** **expect minor context drift on `unicode.rs`**. Issue #224 (PR #233 on main) added `truncate_keeps_full_multibyte_cluster_when_exactly_fits` and `truncate_in_place_matches_owned_variant` tests inside `mod tests`, between archive's pre-context and the `filter_codepoints_strips_unicode_tag` insertion point. The cherry-pick should still fuzz onto the end of `mod tests` because the archive's hunk anchors on the closing `}` of `sanitize_multilingual_clean`, which still exists on main. `threading.rs`, `raw_parts.rs`, and `lib.rs` should apply cleanly.

- [ ] **Step 1: Attempt cherry-pick with provenance**

Run: `git cherry-pick -x c147d78`
Expected:
- Likely: succeeds with fuzz on `unicode.rs`.
- If conflict on `unicode.rs`: the test addition is pure (single new test). Resolve by appending the new test inside `mod tests` (after `sanitize_multilingual_clean`) and removing conflict markers.

- [ ] **Step 2: Resolve conflicts (if any)**

If `unicode.rs` conflicts, open it. The new test to add is:
```rust
    #[test]
    fn filter_codepoints_strips_unicode_tag() {
        // Kills `is_unicode_tag -> bool with false`. With `false`, a
        // Unicode Tag char (U+E0001 LANGUAGE TAG) bypasses the
        // zero-width-class filter and gets pushed into the output.
        // Original: stripped via the same arm as ZERO_WIDTH chars,
        // counted in `zero_width_stripped`.
        let input = "ab\u{E0001}cd";
        let result = filter_codepoints(input);
        assert_eq!(
            result.text, "abcd",
            "Unicode Tag char must be stripped from output",
        );
        assert_eq!(
            result.zero_width_stripped, 1,
            "Unicode Tag char must be counted in zero_width_stripped",
        );
    }
```
Place it after `sanitize_multilingual_clean` (last test in `mod tests` on main, around line 492). Then `git add` and `git cherry-pick --continue`.

- [ ] **Step 3: Run affected files' tests**

Run: `cargo test -p rimap-content --lib threading::tests unicode::tests raw_parts::tests tests::extract_returns_message_id_when_header_present`
Expected: all PASS. Seven new tests above the previous task's count.

- [ ] **Step 4: Run the full crate and lint**

Run: `cargo test -p rimap-content --lib --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1047; no warnings.

---

## Task 11: Re-create `mutation-baseline.md` for `rimap-content` (cherry-pick `a5cdab3` with edits)

**Files:**
- Create: `docs/superpowers/specs/test-strategy/mutation-baseline.md` (was deleted in the daemon rollback; archive `a5cdab3` re-creates it with the rimap-content non-`bin/` table).

**Cherry-pick disposition:** **expect "new file" treatment**. The cherry-pick will create the file fresh; no conflicts on the file itself, but two table rows must be deleted and one rationale rewritten before commit.

- [ ] **Step 1: Cherry-pick the baseline-creation commit (do not commit yet)**

Run: `git cherry-pick -n -x a5cdab3`
Expected: file is created, no conflicts. Working tree shows `docs/superpowers/specs/test-strategy/mutation-baseline.md` as a new staged file.

- [ ] **Step 2: Drop the two stale `lookalike.rs` rows**

Open `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Delete the two table rows whose `File:line` is `lookalike.rs:195` and `lookalike.rs:205`. Both reference the `is_char_boundary` walk in `scan_body_urls` that issue #224 removed; the mutation surface no longer exists.

The remaining `lookalike.rs` rows (`110` × 2, `237`, `245`, `285`) still apply unchanged.

- [ ] **Step 3: Drop the stale `parse/mime_scrub.rs:105` row and renumber the other two**

Find the three rows whose `File:line` starts with `parse/mime_scrub.rs:`:
- `:105` (`replace + with * in detect_smuggling_spans`) — **delete this row entirely**. Task 4 dropped the corresponding in-source annotation because main has `+ 2` (post-PR #228), and the archive rationale documents the `+ 1` form. If a real survivor reappears here under main's `+ 2` math, Task 19 will surface it and a new row with rigorous rationale gets added then.
- `:149` (`replace < with <= in locate_encoded_word_end`) — **renumber to `:124`**, the actual annotation site on main. Update both `File:line` (`:149` → `:124`) and `Annotation site` (`:143` → `:123`) cells. The rationale is unchanged.
- `:213` (`replace < with > in split_header_lines`) — **renumber to `:174`**, the actual annotation site on main. Update both `File:line` (`:213` → `:174`) and `Annotation site` (`:206` → `:173`) cells. The rationale is unchanged.

(Verify with `rg -n 'cargo-mutants: known-equivalent' crates/rimap-content/src/parse/mime_scrub.rs`. The two annotations should sit one line above the `if start_offset < first.len()` and `if line_start < headers.len()` predicates respectively.)

- [ ] **Step 4: Verify the file links resolve**

Run: `rg -n '\[`2026-04-30-test-strategy-improvements-design.md`\]' docs/superpowers/specs/test-strategy/mutation-baseline.md`
The link target is `../2026-04-30-test-strategy-improvements-design.md`. Run: `ls docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`
- If the file exists: nothing to do.
- If the file does NOT exist (it was deleted in the daemon rollback): replace the link target inside `mutation-baseline.md` with the GitHub permalink to the spec on `archive/daemon-experiment`:
  `[archive: 2026-04-30-test-strategy-improvements-design.md](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md)`

The follow-up plan link inside the file (`[../../plans/2026-04-30-rimap-content-mutation-cleanup-followup.md]`) refers to the original PR #195 plan; that plan is intentionally not re-extracted. Replace the link target with the GitHub permalink under `archive/daemon-experiment`:
  `[archive: 2026-04-30-rimap-content-mutation-cleanup-followup.md](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/plans/2026-04-30-rimap-content-mutation-cleanup-followup.md)` and add a parenthetical note `(superseded by docs/superpowers/plans/2026-05-03-issue-225-rimap-content-mutation-waves-rextract.md)`.

- [ ] **Step 5: Verify the in-source annotations referenced by the table all exist**

Run: `rg -n 'cargo-mutants: known-equivalent' crates/rimap-content/src/ | wc -l`
Expected: 11 annotations after Tasks 1–10 — `html/style_parse.rs` (1, Task 6), `html/mismatch.rs` (1, Task 7), `lookalike.rs` (4, Task 9), `parse/mime_scrub.rs` (2, Task 4 — `:124` and `:174`; the `+ 1` annotation was deliberately dropped), `raw_parts.rs` (3, Task 10), and zero in `unicode.rs`/`threading.rs`/`lib.rs`. If the count is lower, an earlier task missed an annotation — run `git diff main -- crates/rimap-content/src` and reconcile. (Tasks 12–17 will add 4 more in `bin/epvme_runner.rs` for a final total of 15.)

- [ ] **Step 6: Stage and commit**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git cherry-pick --continue
```
The `--continue` will reuse the original commit message; verify the `(cherry picked from commit a5cdab3…)` line is preserved. Add a one-line note above that line in the editor:
`Note: dropped two now-stale lookalike.rs rows (the is_char_boundary walk was removed by #224); rewrote mime_scrub.rs:105 rationale from "+ 1" to "+ 2" to match main's post-#228 code.`

- [ ] **Step 7: Sanity-check the commit**

Run: `git log -1 --stat`
Expected: one file changed (`mutation-baseline.md`), ~78 lines added (a few less than archive's 79 owing to the two dropped rows).

---

## Task 12: Re-extract `epvme_runner` `parse_args` mutation-coverage tests (cherry-pick `cd2c50e`)

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (3 lines added: 1 `// cargo-mutants: known-equivalent` annotation on `usage()`).
- Modify: `crates/rimap-content/tests/epvme_integration.rs` (3 integration tests).

**Cherry-pick disposition:** clean — `cd2c50e^:epvme_runner.rs` and `cd2c50e^:epvme_integration.rs` are byte-identical to current `main`.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x cd2c50e`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the affected tests**

Run: `cargo test -p rimap-content --test epvme_integration`
Expected: all PASS, including 3 new tests:
- `help_flag_exits_zero_kills_mutant_delete_help_arm`
- `short_help_flag_exits_zero_kills_mutant_delete_help_arm`
- `unknown_flag_exits_nonzero_with_message_kills_mutant_flag_guard`

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1050; no warnings.

---

## Task 13: Re-extract `epvme_runner` dataset-loop mutation-coverage tests (cherry-pick `bf83314`)

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (5 unit tests added inside `mod tests`).

**Cherry-pick disposition:** clean — `bf83314^:epvme_runner.rs` is byte-identical to the post-Task-12 file.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x bf83314`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the affected tests**

Run: `cargo test -p rimap-content --bin epvme_runner`
Expected: all PASS, including 5 new unit tests covering `panic_message`, `unknown_warning_code_label`, and a `run_dataset` panic-recording assertion that adds an extra check to an existing test.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1055; no warnings.

---

## Task 14: Re-extract `epvme_runner` `print_summary` mutation annotations (cherry-pick `62589f4`)

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (12 lines added: 3 `// cargo-mutants: known-equivalent` annotations on `print_summary`).

**Cherry-pick disposition:** clean — only annotation comments are added; no test changes.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x 62589f4`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Verify the annotations landed**

Run: `rg -n 'cargo-mutants: known-equivalent.*Parse error kinds|Warning counts|Recorded failures' crates/rimap-content/src/bin/epvme_runner.rs`
Expected: three matches, one per annotation.

- [ ] **Step 3: Run tests and lint (no functional change)**

Run: `cargo test -p rimap-content --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: same test count as Task 13 (1055; no new tests); no warnings.

---

## Task 15: Re-extract `epvme_runner` `write_json_report` empty-parent test (cherry-pick `c52e3ed`)

**Files:**
- Modify: `crates/rimap-content/tests/epvme_integration.rs` (1 integration test).

**Cherry-pick disposition:** clean — `c52e3ed^:epvme_integration.rs` is byte-identical to the post-Task-12 file.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x c52e3ed`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the integration tests**

Run: `cargo test -p rimap-content --test epvme_integration json_out_creates_missing_parent_dir_kills_mutant_delete_empty_parent_guard`
Expected: PASS.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1056; no warnings.

---

## Task 16: Re-extract `epvme_runner` `read_failure_count` test (cherry-pick `d358f5e`)

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (1 unit test added inside `mod tests`).

**Cherry-pick disposition:** clean — `d358f5e^:epvme_runner.rs` is byte-identical to the post-Task-13/14 file.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x d358f5e`
Expected: succeeds with no conflicts.

- [ ] **Step 2: Run the affected test**

Run: `cargo test -p rimap-content --bin epvme_runner run_dataset_records_read_failures`
Expected: PASS.

- [ ] **Step 3: Run the full crate and lint**

Run: `cargo test -p rimap-content --quiet 2>&1 | tail -5 && cargo clippy -p rimap-content --all-targets --all-features -- -D warnings`
Expected: cumulative count 1057; no warnings.

---

## Task 17: Finalise `mutation-baseline.md` with the `bin/epvme_runner.rs` subsection (cherry-pick `2e69b7d`)

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md` (+22 lines: `### bin/epvme_runner.rs` subsection appended; the rimap-content header text is also updated to reflect the post-#193 survivor counts).

**Cherry-pick disposition:** **expect minor conflict on the rimap-content header counts**. Archive `2e69b7d`'s patch updates the rimap-content section's "Surviving mutants" count from 15 (pre-#193) to 15 (unchanged for non-`bin/`) and rewrites the run-summary paragraph to mention the now-resolved bin survivors. Resolution: take archive's text verbatim — main's post-Task-11 `mutation-baseline.md` is already the pre-#193 version, so all archive's edits should apply.

- [ ] **Step 1: Cherry-pick with provenance**

Run: `git cherry-pick -x 2e69b7d`
Expected: succeeds. If a conflict surfaces (most likely on the run-summary paragraph in the rimap-content section), accept archive's text verbatim.

- [ ] **Step 2: Verify the bin subsection landed**

Run: `rg -n '^### `bin/epvme_runner.rs`' docs/superpowers/specs/test-strategy/mutation-baseline.md`
Expected: one match. The subsection should list 5 mutations (epvme_runner.rs:189 × 2, :381, :392, :403) all annotated as known-equivalent.

- [ ] **Step 3: Verify the in-source annotations match the table**

Run: `rg -nC 1 'cargo-mutants: known-equivalent' crates/rimap-content/src/bin/epvme_runner.rs | head -40`
Expected: four annotation comments — one on `usage()` (Task 12) and three on `print_summary` (Task 14). The bin baseline table should reference all four annotation sites correctly. If line numbers differ from the `:189`, `:381`, `:392`, `:403` values, update the table to match.

---

## Task 18: Workspace-wide verification

**Files:** none modified.

- [ ] **Step 1: Confirm the cumulative test count**

Run: `cargo test --workspace --quiet 2>&1 | grep -E "^test result:" | awk '{p+=$4; f+=$6; i+=$8} END {print "passed=" p " failed=" f " ignored=" i}'`
Expected: `passed=1057 failed=0 ignored=0`. If the count differs by ±1, locate the missing/extra test via `git diff main -- crates/rimap-content` and reconcile.

- [ ] **Step 2: Confirm all in-source annotations are present**

Run: `rg -n 'cargo-mutants: known-equivalent' crates/rimap-content/src/ | wc -l`
Expected: 15 (1 in `html/style_parse.rs`, 1 in `html/mismatch.rs`, 4 in `lookalike.rs`, 2 in `parse/mime_scrub.rs` — `:124` and `:174`; the `+ 1` annotation on `:86` was deliberately dropped in Task 4, 3 in `raw_parts.rs`, 4 in `bin/epvme_runner.rs` — 1 from Task 12 + 3 from Task 14, 0 in `unicode.rs`, 0 in `threading.rs`, 0 in `lib.rs`). If the count differs, an earlier task dropped an annotation — `rg -nC 1 'cargo-mutants: known-equivalent' crates/rimap-content/src/` to inspect.

- [ ] **Step 3: Workspace-wide clippy**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 4: Workspace-wide format check**

Run: `cargo fmt --all -- --check`
Expected: clean. If formatting drifted on any cherry-pick, run `cargo fmt --all` and `git commit --amend --no-edit` (or, if the formatting fix touches multiple per-task commits, do a fresh `style: cargo fmt --all` commit).

- [ ] **Step 5: Verify the mutation-baseline.md links and table coverage**

Run: `rg -nF '| `' docs/superpowers/specs/test-strategy/mutation-baseline.md | wc -l`
Expected: 17 table-data rows total — 12 in the rimap-content section (15 archive rows minus 2 dropped `lookalike.rs` rows minus 1 dropped `mime_scrub.rs:105` row, with the surviving two `mime_scrub.rs` rows renumbered to `:124` and `:174`) plus 5 in the `bin/epvme_runner.rs` subsection. Plus the table-header rows (`| File:line | …`) and separator rows (`|---|---|---|---|`) — adjust the expected number if the rg pattern catches those too.

---

## Task 19: cargo-mutants verification

**Files:** none modified.

**Why this task is in the plan:** The acceptance criterion `cargo mutants --jobs 2 survival rate matches the baseline recorded in the spec` requires a measured run. The expected survivor count after this plan is 15 in `rimap-content` non-`bin/` (all known-equivalent, table-documented) and 5 in `bin/epvme_runner.rs` (also all known-equivalent). `cargo-mutants` is slow (the archive baseline took ~30 minutes per crate); plan for this in a separate window or run overnight.

**Important: per `~/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/feedback_cargo_mutants_jobs_cap.md`, always pass `--jobs 2`. Default parallelism has historically used 300 GB of RAM and frozen the host on this machine.**

- [ ] **Step 1: Run `cargo-mutants` for `rimap-content` with the host's job cap**

Run: `just mutants-crate rimap-content` (which expands to `cargo mutants --package rimap-content --jobs 2`).
If `just` is not available: `cargo mutants --package rimap-content --jobs 2`.
Expected: ~30 minutes wall clock. Final summary: 15 missed mutations (all in non-`bin/` code), 5 missed in `bin/epvme_runner.rs`. Total non-timeout missed: 20. Each missed mutation should match a row in `mutation-baseline.md`.

- [ ] **Step 2: Reconcile any unexpected survivors**

If a survivor surfaces that is **not** in the baseline table:
- Determine whether it is a true test gap (write a test that kills it; commit; update the baseline if the mutation re-classifies as known-equivalent) or a known-equivalent (annotate the mutation site and add a row to the baseline with rigorous rationale).
- A mutation that landed via this plan but was not in the archive baseline is a bug — investigate whether the cherry-pick ordering inadvertently re-introduced a code path the archive had killed.

If a baseline row has no corresponding survivor (i.e., the mutation got caught by a new test):
- Drop the row from the baseline. The tests are what the codebase needs; an over-cautious annotation is dead weight.

- [ ] **Step 3: Update `mutation-baseline.md` if reconciliation surfaced changes**

If Step 2 surfaced any reconciliation: amend the Task 11/17 commits with `git commit --fixup` and rebase, OR add a new commit `docs(test-strategy): reconcile mutation-baseline with measured rimap-content run`. The latter is preferred to keep the cherry-pick history intact.

- [ ] **Step 4: Capture the run output for the PR description**

Save the final summary line (`Found N mutants`, `M missed`, etc.) — paste it into the PR description in Task 20.

(Optional) Step 5: If `cargo-mutants` is not available locally, defer this task to CI. The PR's required-checks include a mutation-baseline-comparison job (added in Phase-2 issue #226 / #227 if those land first); if not, document the deferral in the PR description.

---

## Task 20: Open PR

**Files:** none modified.

- [ ] **Step 1: Push the branch**

Run: `git push -u origin phase2/issue-225-rimap-content-mutation-waves-rextract`
Expected: branch pushes cleanly.

- [ ] **Step 2: Open the PR with `gh pr create`**

```bash
gh pr create --title "Phase-2: Re-extract rimap-content mutation-cleanup waves (#225)" --body "$(cat <<'EOF'
## Summary

Re-extracts the test-only mutation-cleanup waves from archived PRs #196 and #198 (issues #192 and #193), driving the `rimap-content` cargo-mutants survivor count back to the archive baseline (15 non-`bin/`, 5 in `bin/epvme_runner.rs`, all annotated as `known-equivalent`).

- 14 commits cherry-picked with provenance from `archive/daemon-experiment` (`-x` lines preserved). One commit (`4e56b11`) was fresh-applied to drop a stale `scan_body_urls` annotation and a duplicate test that issue #224 had already brought back. One commit (`300556c`) was skipped entirely because the annotation site no longer exists. One commit (`a5cdab3`) had two `lookalike.rs` baseline rows surgically removed and one `mime_scrub.rs` rationale rewritten to match main's post-#228 `+ 2` form.
- 66 net-new tests (workspace count 991 → 1057). Six new in-source `cargo-mutants: known-equivalent` annotation comments. Zero production-code logic changes. Zero new dependencies.
- `mutation-baseline.md` re-created with a corrected `rimap-content` table (13 rows) and a new `bin/epvme_runner.rs` subsection (5 rows).

## Test plan

- [ ] `cargo test --workspace` passes (1057 / 0 failed / 0 ignored)
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean
- [ ] `just mutants-crate rimap-content` (or `cargo mutants --package rimap-content --jobs 2`) survival rate matches the baseline: 15 non-`bin/` survivors (all annotated), 5 `bin/epvme_runner.rs` survivors (all annotated), 0 unannotated misses
- [ ] All 8 required CI checks green

## Acceptance criteria (issue #225)

- [x] `mutation-baseline.md` in `docs/superpowers/specs/test-strategy/` present and updated
- [x] All test additions from PRs #196 and #198 in place
- [ ] `cargo mutants --jobs 2` survival rate matches the baseline recorded in the spec (verified in Task 19 above)
- [ ] CI green on all 8 required checks

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI**

Run: `gh pr checks --watch`
Expected: all 8 required checks pass. If any fail, address before marking the PR ready for merge.

---

## Self-review checklist (run before opening the PR)

These verify the plan against issue #225's acceptance criteria.

- [ ] **Spec coverage:**
  - "All test additions from PRs #196 and #198 in place" → Tasks 1–10 (PR #196) and Tasks 12–16 (PR #198). Confirmed by per-task test counts and final 1057-test workspace count.
  - "`mutation-baseline.md` in `docs/superpowers/specs/test-strategy/` present and updated" → Tasks 11 and 17.
  - "`cargo mutants --jobs 2` survival rate matches the baseline" → Task 19.
  - "CI green on all 8 required checks" → Task 20.
- [ ] **No re-introduction of removed code:** the `scan_body_urls` `is_char_boundary` walk is NOT re-introduced (Task 9 explicitly skips that annotation; Task 11 explicitly drops the two corresponding baseline rows; the `300556c` commit is explicitly skipped).
- [ ] **API rename respected:** `html::sanitize_html` is not re-introduced (Task 8 renames the 3 call sites in archive's new tests to `process`).
- [ ] **No phantom tests:** the test-count math (991 + 66 = 1057) matches per-task additions.
- [ ] **Baseline table consistency:** every row in `mutation-baseline.md` references an annotation site that exists in the source tree (verify with `rg 'cargo-mutants: known-equivalent'`).
- [ ] **Annotation count math:** 15 in-source annotations expected at the end of Task 17; verify with `rg -c 'cargo-mutants: known-equivalent' crates/rimap-content/src/`.
- [ ] **Cargo lockfile not touched:** none of these commits should touch `Cargo.lock`. If a cherry-pick brought in a stray lockfile change, drop it before committing.
