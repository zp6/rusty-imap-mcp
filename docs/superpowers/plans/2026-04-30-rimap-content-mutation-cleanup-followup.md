# `rimap-content` Mutation Cleanup Follow-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the `rimap-content` mutation cleanup that Sprint B1 deferred (issue #192). Drive `cargo mutants --package rimap-content` to zero unannotated surviving mutants outside `src/bin/`, with every `known-equivalent` annotation justified inline and recorded in `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

**Architecture:** This is a test-suite-and-docs-only change. No production code under `crates/rimap-content/src/` changes behaviorally; survivors are killed by adding tests (in existing `#[cfg(test)]` modules or `crates/rimap-content/tests/*.rs`) or annotated as `known-equivalent` with an inline rationale comment plus a row in `mutation-baseline.md`. Work is committed module-by-module so `git log --oneline` reads as one cleanup commit per module group. The B1 plan's Tasks 8–9 prose defines the triage rule; this plan turns that into per-file tasks sized to the 2026-04-30 survivor distribution from issue #192.

**Tech Stack:** `cargo-mutants` 25.x, `cargo-nextest`, `cargo clippy`, the existing `rimap-content` test suite (`crates/rimap-content/src/**/*.rs#[cfg(test)]` modules + `crates/rimap-content/tests/*.rs`).

**Spec reference:** [`docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`](../specs/2026-04-30-test-strategy-improvements-design.md), §4.3 and §4.5.

**Issue reference:** [#192](https://github.com/randomparity/rusty-imap-mcp/issues/192).

**B1 plan it follows:** [`2026-04-30-test-strategy-b1-rimap-content.md`](2026-04-30-test-strategy-b1-rimap-content.md), Tasks 8 and 9.

**Branch:** `feat/issue-192-rimap-content-mutation-cleanup` (cut from `main` once this plan lands).

---

## Pre-flight

Confirm we're on a feature branch (not `main`), the tree is clean, and the mutation-testing toolchain is in place.

- [ ] **Step 0: Verify branch, clean state, and tooling**

Run:
```bash
git branch --show-current
git status --short
which cargo-mutants cargo-nextest
cargo mutants --version
```

Expected:
- `git branch --show-current` is `feat/issue-192-rimap-content-mutation-cleanup`. If not, stop and create it: `git checkout -b feat/issue-192-rimap-content-mutation-cleanup`.
- `git status --short` is empty.
- `cargo-mutants` and `cargo-nextest` are on PATH. If missing: `cargo install --locked cargo-mutants cargo-nextest`.
- `cargo mutants --version` prints a 25.x version. Older versions emit a different `missed.txt` format and break the parsing in Task 2.

---

## Task 1: Refresh the `cargo-mutants` baseline on `rimap-content`

**Why:** Issue #192 cites a 2026-04-30 baseline of 80 survivors outside `src/bin/`. PRs may have landed since then (the issue lists post-#191 commits as recent activity), so the per-file distribution can drift before this plan executes. We re-run first and treat the refreshed list — not the issue's table — as the source of truth.

**Files:**
- Touched only as a side effect: `mutants.out/` (gitignored).
- No commit at this task; the survivor inventory is consumed by Tasks 3+.

- [ ] **Step 1: Run the targeted mutation suite**

Run:
```bash
cargo mutants --package rimap-content --no-shuffle 2>&1 | tee /tmp/mutants-rimap-content.log
```

Expected: 30–90 minutes. Output writes to `mutants.out/` and the tee'd log. If `cargo mutants` errors out before the per-mutant phase ("baseline build failed"), fix the workspace's `cargo nextest run --package rimap-content --all-features --locked` first — `cargo-mutants` will not run if the unmutated baseline doesn't build and pass.

- [ ] **Step 2: Snapshot the per-file survivor distribution**

Run:
```bash
mkdir -p /tmp/mutation-cleanup
grep -E "^crates/rimap-content/src/" mutants.out/missed.txt \
  | grep -v "^crates/rimap-content/src/bin/" \
  > /tmp/mutation-cleanup/all-survivors.txt
wc -l /tmp/mutation-cleanup/all-survivors.txt
awk -F: '{print $1}' /tmp/mutation-cleanup/all-survivors.txt \
  | sort | uniq -c | sort -rn \
  > /tmp/mutation-cleanup/by-file.txt
cat /tmp/mutation-cleanup/by-file.txt
```

Expected: a per-file count matching (within ±5) issue #192's table. Large divergence (a file dropping to 0 or doubling) means a recent PR materially changed coverage — note it but proceed; the cleanup still drives the count to zero per module.

- [ ] **Step 3: Confirm there are still survivors to clean up**

Run:
```bash
test -s /tmp/mutation-cleanup/all-survivors.txt && echo "survivors present"
```

Expected: prints `survivors present`. If the file is empty, the prior PRs already killed everything — skip to Task 13 (the docs rewrite is still required to remove the cap-exceeded callout).

---

## Task 2: Stage `mutation-baseline.md` for the per-survivor table

**Why:** Tasks 3–11 each append rows to `mutation-baseline.md`'s per-survivor annotation table. The current doc has only a "_populated by Task 8/9_" placeholder row plus a "Cap exceeded" callout (`docs/superpowers/specs/test-strategy/mutation-baseline.md:23-30`). We replace the placeholder *now* with an empty (header-only) annotation table and remove the per-file count table, so that subsequent module commits read as additive table rows rather than mixed structural-edit + content commits.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Rewrite the `rimap-content` section header**

Open `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Find the `## \`rimap-content\`` section (line 18) and replace **everything** from that heading down to (but not including) `The other four trust-boundary crates` (line 63 in the current revision) with:

````markdown
## `rimap-content`

**Last refresh:** YYYY-MM-DD (replace with today's date when committing).
**Surviving mutants in non-`bin/` code:** N (replace with the
`wc -l /tmp/mutation-cleanup/all-survivors.txt` count from Task 1 Step 2).

The follow-up plan
[`2026-04-30-rimap-content-mutation-cleanup-followup.md`](../../plans/2026-04-30-rimap-content-mutation-cleanup-followup.md)
drives this list to zero. The table below records every survivor whose
mutation is mathematically equivalent to the original code — those are kept
behind a `// cargo-mutants: known-equivalent — <rationale>` comment at the
annotation site. Survivors that are real test-suite gaps are killed by
adding a test, not annotated, and so do not appear here.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| _table populated incrementally by the per-module commits_ |  |  |  |

The `bin/epvme_runner.rs` survivors are out of scope — that crate is
diagnostic tooling, not production. Re-evaluate post-B4.

````

(Replace both `YYYY-MM-DD` and `N` literally — these are not metavariables for execution; they are the actual placeholders the doc carries until Task 13 finalises the count and date.)

- [ ] **Step 2: Verify the doc still parses as Markdown**

Run:
```bash
test -f docs/superpowers/specs/test-strategy/mutation-baseline.md
grep -c '^| ' docs/superpowers/specs/test-strategy/mutation-baseline.md
```

Expected: a non-zero count (the table header rows are present). The doc is committed as part of Task 13's final rewrite — no commit at this task.

---

## Task 3: Mutation cleanup — `parse/headers.rs`

**Why:** Header parsing is the front door for almost every malformed-message attack: continuation handling, encoded-word boundaries, charset-label cleanup. Per the spec §4.3, every survivor in `parse/` must be killed unless mathematically equivalent.

**Files:**
- Modify: `crates/rimap-content/src/parse/headers.rs` (`#[cfg(test)]` module — and inline annotation comments where applicable)
- Possibly modify: `crates/rimap-content/tests/properties.rs` or `crates/rimap-content/tests/snapshots.rs` (only if the survivor is best caught by an integration-test-level assertion)
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md` (table append for any `known-equivalent` annotations)

- [ ] **Step 1: Filter the survivor list to this module**

Run:
```bash
grep -E "^crates/rimap-content/src/parse/headers\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/headers.txt
wc -l /tmp/mutation-cleanup/headers.txt
```

Expected: a count matching issue #192's `parse/headers.rs` row (7 at the 2026-04-30 baseline). Note the count `K`. The triage loop runs `K` times.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

For each line in `/tmp/mutation-cleanup/headers.txt`, in order:

1. **Read the mutation.** The line format is `path:line:col: <description>`. Open the file at the named line and read enough context to understand the mutation. Common `cargo-mutants` mutations:
   - `replace <fn> -> T with Default::default()` — the function is replaced with a stub returning the default value of its return type.
   - `replace == with !=` (and other binop swaps).
   - `delete match arm <pattern>` — the arm is removed (matched values fall through to the next arm).
   - `replace + with -` / `replace * with /` (arithmetic).
   - `replace && with ||` (and the inverse).

2. **Decide: real gap, or equivalent mutant?** Decision tree:
   - **The mutation changes any value `parse_message` returns** (header text, charset, security warnings, error variant) → **real gap, kill it**.
   - **The mutation changes a `tracing::debug!`/`tracing::info!` payload** but no test inspects logs → **equivalent (cosmetic), annotate**.
   - **The mutation toggles a counter or flag that is never observed externally** → **equivalent, annotate**.
   - **The mutation is on an arithmetic operation whose result is the same in every reachable input** (e.g. `+ 0` vs `+ 1` on a counter that's compared `== 0`) → **equivalent, annotate** with the proof in the rationale.
   - When unsure, treat as a real gap — write a test. False annotations rot silently; redundant tests don't.

3. **If real gap, write a failing test first.**

   The `crates/rimap-content/src/parse/headers.rs` file already has a `#[cfg(test)]` module. Append a test that asserts the *exact* observable property the mutation breaks. Pattern:

   ```rust
   #[test]
   fn header_X_kills_mutant_replace_Y_with_Z() {
       // Mutation: <copy the cargo-mutants description here>
       // Assertion: <one-line statement of what observable changed>
       let raw = b"<minimal input that exercises this code path>";
       let result = parse_headers(raw);
       assert_eq!(result.<field>, <expected_value_under_unmutated_code>);
   }
   ```

   Naming convention: `<feature>_kills_mutant_<short_description>` keeps the link from test name back to the mutation visible in `git log` and in `cargo nextest`'s output. The test name is the breadcrumb if a future mutation-cleanup pass needs to re-validate.

   Run the test against unmutated code:
   ```bash
   cargo nextest run --package rimap-content --all-features header_X_kills_mutant -- --nocapture
   ```

   Expected: PASS. If it fails on unmutated code, the assertion is wrong — re-read the mutation.

4. **Verify the test catches the mutation.** Run only the mutants on this file, restricted to the cited line via the `--re` regex against the mutation name (which `cargo-mutants` formats as `<path>:<line>:<col>: <description>`):
   ```bash
   cargo mutants --package rimap-content \
     --file 'crates/rimap-content/src/parse/headers.rs' \
     --re ":<line_number>:" \
     --no-shuffle
   ```

   Substitute `<line_number>` with the line from the cited mutation. Expected: that mutant moves from `MISSED` to `CAUGHT`. If it stays `MISSED`, the test isn't sufficient — tighten the assertion. If `--re` matches no mutants, the source file's line numbering shifted (you added lines above the mutation site) — re-run `cargo mutants --list --file 'crates/rimap-content/src/parse/headers.rs'` to find the current line number.

5. **If equivalent mutant, annotate inline.** Add a comment immediately above the line the mutant rewrites:

   ```rust
   // cargo-mutants: known-equivalent — <one-line rationale that proves
   // the mutation is observably indistinguishable from the original>
   ```

   And append a row to the `## \`rimap-content\`` table in `mutation-baseline.md`:
   ```markdown
   | `parse/headers.rs:<line>` | `<mutation description>` | <rationale> | `parse/headers.rs:<line-of-comment>` |
   ```

   Rationale bar: the line must explain *why the output is the same*, not "it doesn't matter" or "internal-only." Examples of good rationales:
   - "Counter incremented for `tracing::debug!` only, never read by any test or production caller."
   - "Branch is unreachable — the calling site already filtered to `Some(_)` cases at line 412."
   - "Replaces `+ 0` with `+ 1` on a value that's only compared against `0`; both branches produce the same `if` result."

- [ ] **Step 3: Re-run mutation tests on this file only**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/headers.rs' \
  --no-shuffle
```

Expected: zero `MISSED` mutants other than ones bearing a `// cargo-mutants: known-equivalent` annotation. Annotated lines are still mutated by `cargo-mutants` and still report `MISSED`; the comment is for human readers and the baseline doc — `cargo-mutants` does not parse it. The done criterion is "every `MISSED` mutant has a corresponding annotation," verified by visual inspection against the table you appended in Step 2.

- [ ] **Step 4: Run clippy + tests for the crate**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean. New tests must pass; new annotation comments must not trip any pedantic lint.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/parse/headers.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in parse/headers.rs

Adds N tests covering specific cargo-mutants survivors uncovered by
the 2026-04-30 baseline refresh on parse/headers.rs. M known-equivalent
mutants annotated inline with rationale, recorded in mutation-baseline.md.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

Replace `N` and `M` with the actual counts from this task's loop.

---

## Task 4: Mutation cleanup — `parse/filename.rs`

**Why:** Attachment-filename parsing is a high-leverage attack surface (path-traversal sequences, RFC 2231 continuation, charset declarations on filenames). 10 survivors at the 2026-04-30 baseline.

**Files:**
- Modify: `crates/rimap-content/src/parse/filename.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/parse/filename\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/filename.txt
wc -l /tmp/mutation-cleanup/filename.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the same triage procedure as Task 3 Step 2 (read → decide → kill or annotate → verify). The file-specific signals to bias decisions:

- Mutations on path-traversal checks (`..`, `/`, `\`, NUL) → **always kill** (these are security-bearing).
- Mutations on charset-label normalization (case folding, whitespace trim) → kill if any test downstream of `parse_message` observes the filename; annotate if the normalization is pure cosmetics for `tracing::debug!`.
- Mutations on RFC 2231 continuation reassembly (the `name*0=...; name*1=...` pattern) → **always kill** — reassembly bugs split filenames in attacker-controllable ways.

- [ ] **Step 3: Re-run mutation tests on this file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/filename.rs' \
  --no-shuffle
```

Expected: every `MISSED` line corresponds to a `known-equivalent` annotation.

- [ ] **Step 4: Run clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/parse/filename.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in parse/filename.rs

Adds N tests covering cargo-mutants survivors in filename parsing
(path-traversal, RFC 2231 continuation, charset-label normalization).
M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 5: Mutation cleanup — `parse/bodies.rs`

**Why:** Body extraction (text/plain, text/html, multipart routing) is the path that picks which `sanitize_html` invocation runs. 9 survivors at baseline.

**Files:**
- Modify: `crates/rimap-content/src/parse/bodies.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/parse/bodies\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/bodies.txt
wc -l /tmp/mutation-cleanup/bodies.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- Mutations on multipart-tree walks (depth limits, part-index accounting) → kill via tests on adversarial fixtures in `tests/injection-corpus/` or `crates/rimap-content/src/parse/bodies.rs#[cfg(test)]`.
- Mutations on `text/plain` vs `text/html` selection → **always kill** — picking the wrong one bypasses sanitization.
- Mutations on transfer-decoding (base64, quoted-printable) → **always kill**.
- Mutations on byte-length accounting for `LimitExceeded` → kill with a test that crafts a near-limit body and asserts the boundary, both sides.

- [ ] **Step 3: Re-run mutation tests on this file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/bodies.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/parse/bodies.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in parse/bodies.rs

Adds N tests covering body-extraction survivors (multipart routing,
text/html vs text/plain selection, transfer decoding, byte-limit
accounting). M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 6: Mutation cleanup — `parse/mime_scrub.rs`

**Why:** This file holds `scrub_header_smuggling`, the load-bearing CRLF-injection defense already covered by the `content_rfc2047` fuzz harness (B1 Task 5). 6 survivors at baseline.

**Files:**
- Modify: `crates/rimap-content/src/parse/mime_scrub.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/parse/mime_scrub\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/mime_scrub.txt
wc -l /tmp/mutation-cleanup/mime_scrub.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- **Every** mutation in `scrub_header_smuggling` and `detect_smuggling_spans` must be killed unless equivalent — the function is a security boundary. The bar for "equivalent" here is higher than elsewhere: an annotation must reference a test elsewhere in the suite that proves the equivalence is contractual, not incidental.
- If a mutation can be reproduced via the existing CRLF-smuggling fixture (`tests/injection-corpus/rfc2047-crlf-smuggling/input.eml`), prefer killing it there rather than synthesising a fresh fixture.

- [ ] **Step 3: Re-run mutation tests on this file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/mime_scrub.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/parse/mime_scrub.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in parse/mime_scrub.rs

Adds N tests covering scrub_header_smuggling/detect_smuggling_spans
survivors. The CRLF-injection defense is on a security boundary, so
the equivalence bar for annotations is higher than other modules:
each known-equivalent row cites a test that proves the equivalence
is contractual.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 7: Mutation cleanup — `parse/{meta,attachments,mod}.rs`

**Why:** Three small files with 4 survivors total (1 + 1 + 2). Grouping them into one commit keeps the history coherent — they share the parse-pipeline domain and none individually warrants its own commit.

**Files:**
- Modify: `crates/rimap-content/src/parse/meta.rs`
- Modify: `crates/rimap-content/src/parse/attachments.rs`
- Modify: `crates/rimap-content/src/parse/mod.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/parse/(meta|attachments|mod)\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/parse-misc.txt
wc -l /tmp/mutation-cleanup/parse-misc.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- `parse/mod.rs` mutants on `LimitExceeded` thresholds → **always kill**.
- `parse/attachments.rs` mutants on attachment count or aggregate-size accounting → **always kill** (DoS-relevant).
- `parse/meta.rs` mutants on charset/language detection used downstream by sanitization → kill; mutants on metadata fields that are only logged → annotate.

- [ ] **Step 3: Re-run mutation tests on the three files**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/parse/meta.rs' \
  --file 'crates/rimap-content/src/parse/attachments.rs' \
  --file 'crates/rimap-content/src/parse/mod.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/parse/meta.rs \
        crates/rimap-content/src/parse/attachments.rs \
        crates/rimap-content/src/parse/mod.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in parse/{meta,attachments,mod}.rs

Adds N tests covering the small-survivor-count parse files: meta.rs
(1 survivor at baseline), attachments.rs (1), and parse/mod.rs (2).
M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 8: Mutation cleanup — `html/style_parse.rs`

**Why:** CSS-style parsing for the HTML sanitizer (`color`, `background`, `display`, etc. — the white-on-white and hidden-element heuristics). 8 survivors at baseline.

**Files:**
- Modify: `crates/rimap-content/src/html/style_parse.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/html/style_parse\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/style_parse.txt
wc -l /tmp/mutation-cleanup/style_parse.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- Mutations that flip the white-on-white or hidden-element decision → **always kill**: the existing `crates/rimap-content/tests/proptest_html_lookalike.rs` is a good integration-level home for these (the proptest crate gives you input-shrinking for free).
- Mutations on color/background colour comparison thresholds → kill with boundary tests (one shade above, one shade below).
- Mutations on whitespace handling inside style values → annotate if equivalent under CSS parsing (e.g. `;;` collapsing to `;`); kill otherwise.

- [ ] **Step 3: Re-run on the file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/html/style_parse.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/html/style_parse.rs \
        crates/rimap-content/tests/proptest_html_lookalike.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in html/style_parse.rs

Adds N tests covering CSS-style-parser survivors (white-on-white
detection, hidden-element heuristics, colour-threshold boundaries).
M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

(If no edit was needed in `proptest_html_lookalike.rs`, drop that path from `git add`.)

---

## Task 9: Mutation cleanup — `html/mismatch.rs`

**Why:** Detects mismatch between visible link text and the URL the link points at — a phishing surface. 7 survivors at baseline.

**Files:**
- Modify: `crates/rimap-content/src/html/mismatch.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/html/mismatch\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/mismatch.txt
wc -l /tmp/mutation-cleanup/mismatch.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- Mutations that flip whether a link is flagged as mismatched → **always kill**.
- Mutations on hostname normalization (case folding, IDNA, port handling) → kill via concrete test cases.
- Mutations on whitespace stripping inside anchor text → annotate only if the function's contract is "compare ignoring whitespace" and that contract is documented; otherwise kill.

- [ ] **Step 3: Re-run on the file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/html/mismatch.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/html/mismatch.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in html/mismatch.rs

Adds N tests covering link-text/URL-mismatch detection survivors
(hostname normalization, anchor-text whitespace handling, mismatch
boolean flips). M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 10: Mutation cleanup — `html/{extract,mod}.rs`

**Why:** Two small HTML files: `html/extract.rs` (1 survivor) and `html/mod.rs` (3). Grouping into one commit keeps the history coherent.

**Files:**
- Modify: `crates/rimap-content/src/html/extract.rs`
- Modify: `crates/rimap-content/src/html/mod.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/html/(extract|mod)\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/html-misc.txt
wc -l /tmp/mutation-cleanup/html-misc.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- `html/mod.rs` orchestrates the sanitization pipeline — mutations on the `sanitize_html` entry point or on charset routing → **always kill**.
- `html/extract.rs` link/image extraction — mutations that change extracted-URL count or the URL itself → **always kill**.

- [ ] **Step 3: Re-run on both files**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/html/extract.rs' \
  --file 'crates/rimap-content/src/html/mod.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/html/extract.rs \
        crates/rimap-content/src/html/mod.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in html/{extract,mod}.rs

Adds N tests covering the small-survivor-count html files: extract.rs
(URL/image extraction, 1 survivor at baseline) and mod.rs (sanitize_html
entry point + charset routing, 3 survivors). M known-equivalent
mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 11: Mutation cleanup — `lookalike.rs`

**Why:** Look-alike (homoglyph) detection — script-mixing flags, confusable-character tables. The single largest survivor count in the file (14 at baseline). The threat model treats every byte of email content as untrusted, so the lookalike pipeline is squarely on the security boundary.

**Files:**
- Modify: `crates/rimap-content/src/lookalike.rs`
- Possibly modify: `crates/rimap-content/tests/proptest_html_lookalike.rs` (proptest-level coverage of the homoglyph table)
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/lookalike\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/lookalike.txt
wc -l /tmp/mutation-cleanup/lookalike.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- Mutations on the script-mixing decision (Latin + Cyrillic in one identifier, etc.) → **always kill** with a concrete confusable-pair test.
- Mutations on the confusable-character table lookup → **always kill**: pick a representative pair (`а`/`a` Cyrillic-vs-Latin, `ο`/`o` Greek-vs-Latin) and assert both sides flag.
- Mutations on count thresholds (e.g. "only flag if > 3 confusables") → kill with boundary tests.
- Mutations on whitespace/normalization that is contractually idempotent → may annotate if the contract is documented and a test exercises the idempotence.

- [ ] **Step 3: Re-run on the file**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/lookalike.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/lookalike.rs \
        crates/rimap-content/tests/proptest_html_lookalike.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in lookalike.rs

Adds N tests covering homoglyph-detection survivors (script-mixing
flags, confusable-character lookups, count thresholds). The largest
single-file cleanup in this PR (14 survivors at the 2026-04-30
baseline). M known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

(If no edit was needed in `proptest_html_lookalike.rs`, drop that path from `git add`.)

---

## Task 12: Mutation cleanup — `threading.rs`, `unicode.rs`, plumbing (`raw_parts.rs`, `lib.rs`)

**Why:** The remaining files: 4 in `threading.rs`, 1 in `unicode.rs`, 3 each in `raw_parts.rs` and `lib.rs`. `threading.rs` and `unicode.rs` are active sanitization (Task 8 of the original B1 plan); `raw_parts.rs` and `lib.rs` are plumbing (Task 9 of the original B1 plan, lower bar). Grouped together because individually each file has too few survivors to merit its own commit.

**Files:**
- Modify: `crates/rimap-content/src/threading.rs`
- Modify: `crates/rimap-content/src/unicode.rs`
- Modify: `crates/rimap-content/src/raw_parts.rs`
- Modify: `crates/rimap-content/src/lib.rs`
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Filter the survivor list**

Run:
```bash
grep -E "^crates/rimap-content/src/(threading|unicode|raw_parts|lib)\.rs" \
  /tmp/mutation-cleanup/all-survivors.txt \
  | tee /tmp/mutation-cleanup/tail.txt
wc -l /tmp/mutation-cleanup/tail.txt
```

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Apply the Task 3 Step 2 procedure. File-specific bias:

- `threading.rs` mutations on the `In-Reply-To`/`References` walk that drives conversation threading → **always kill** (per spec §4.3, threading is an active sanitization path even though mis-threading isn't a security bug per se — the spec groups it with parse/html).
- `unicode.rs` mutations on `decode` → kill (charset routing is security-bearing); mutations on `normalize`/NFC paths → kill if observable in `parse_message` output.
- `raw_parts.rs` and `lib.rs` are plumbing per spec §4.3 — the bar drops to "kill if observable; annotate cosmetic equivalents." `lib.rs` mutations on the public API surface (`parse_message` re-exports, `pub use` items) should still be killed because external callers depend on those names.

- [ ] **Step 3: Re-run on the four files**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/threading.rs' \
  --file 'crates/rimap-content/src/unicode.rs' \
  --file 'crates/rimap-content/src/raw_parts.rs' \
  --file 'crates/rimap-content/src/lib.rs' \
  --no-shuffle
```

- [ ] **Step 4: Clippy + tests**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/threading.rs \
        crates/rimap-content/src/unicode.rs \
        crates/rimap-content/src/raw_parts.rs \
        crates/rimap-content/src/lib.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): close mutation gaps in threading/unicode/plumbing

Adds N tests covering the long-tail survivors: threading.rs (4 at
baseline), unicode.rs (1), and the plumbing files raw_parts.rs (3)
and lib.rs (3). Plumbing files use the spec §4.3 'kill if observable,
annotate cosmetic equivalents' rule; the others use the active-
sanitization 'kill unless mathematically equivalent' rule. M
known-equivalent mutants annotated inline.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 13: Verify zero unannotated survivors workspace-wide

**Why:** Tasks 3–12 each verified their own module, but lint/clippy/test changes can have cross-file consequences. One full run is the gate that proves the issue's done-criterion is met.

**Files:**
- Touched only as a side effect: `mutants.out/` (gitignored).
- No commit at this task; the verification log is the artifact.

- [ ] **Step 1: Full mutation run on the crate**

Run:
```bash
cargo mutants --package rimap-content --no-shuffle 2>&1 \
  | tee /tmp/mutants-rimap-content-final.log
```

Expected runtime: same 30–90 minutes as Task 1.

- [ ] **Step 2: Confirm zero unannotated survivors outside `src/bin/`**

Run:
```bash
grep -E "^crates/rimap-content/src/" mutants.out/missed.txt \
  | grep -v "^crates/rimap-content/src/bin/" \
  > /tmp/mutation-cleanup/final-survivors.txt
wc -l /tmp/mutation-cleanup/final-survivors.txt
```

- [ ] **Step 3: For each remaining `MISSED` line, verify a `known-equivalent` annotation exists at the cited site**

Run:
```bash
while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    # Check the line above the cited mutation for the annotation marker.
    above=$((lineno - 1))
    if ! sed -n "${above}p" "$file" | grep -q "cargo-mutants: known-equivalent"; then
        echo "UNANNOTATED: $line"
    fi
done < /tmp/mutation-cleanup/final-survivors.txt
```

Expected: no `UNANNOTATED:` lines printed. Any output here is a survivor that slipped through Tasks 3–12 — return to the appropriate module's task and finish triage before proceeding.

- [ ] **Step 4: Confirm `mutation-baseline.md` table row count matches the annotated-survivor count**

Run:
```bash
# Lines in mutation-baseline.md table that look like a survivor row
TABLE_ROWS=$(awk '/^## `rimap-content`/,/^## `rimap-authz`/' \
  docs/superpowers/specs/test-strategy/mutation-baseline.md \
  | grep -cE '^\| `(parse|html|src|crates|threading|unicode|raw_parts|lib|lookalike)')
ANNOTATED=$(grep -rh "cargo-mutants: known-equivalent" \
  crates/rimap-content/src/ | wc -l | tr -d ' ')
echo "table rows: $TABLE_ROWS"
echo "in-source annotations: $ANNOTATED"
test "$TABLE_ROWS" = "$ANNOTATED" && echo "match" || echo "MISMATCH"
```

Expected: `match`. If not, an annotation was added inline without a corresponding doc row, or vice versa — fix in the next task.

---

## Task 14: Finalise `mutation-baseline.md`

**Why:** Issue #192's done criteria require: cap-exceeded callout dropped, per-file table dropped, per-survivor annotation table populated, headline survivor count updated. Tasks 2 and 3–12 incrementally restructured the doc and appended rows; this task does the final clean pass and replaces the `YYYY-MM-DD`/`N` placeholders with concrete values.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Replace the date placeholder**

Open `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Find both `YYYY-MM-DD` strings (the file-level updated-date at line 3, and the `## \`rimap-content\`` last-refresh date) and replace with today's ISO date (`date -u +%Y-%m-%d`).

- [ ] **Step 2: Replace the survivor count**

In the `## \`rimap-content\`` section, replace `Surviving mutants in non-\`bin/\` code:` `N` with the count from Task 13 Step 2 (`wc -l /tmp/mutation-cleanup/final-survivors.txt`). Every counted survivor at this point is annotated, so the count equals the doc's table-row count from Task 13 Step 4.

- [ ] **Step 3: Drop the placeholder table-empty row if it survived Task 2's edit**

If the `_table populated incrementally by the per-module commits_` row from Task 2 is still in the file, remove it — by Task 13 Step 4 it has been superseded by real rows.

- [ ] **Step 4: Sanity-check the doc renders**

Run:
```bash
test -f docs/superpowers/specs/test-strategy/mutation-baseline.md
head -5 docs/superpowers/specs/test-strategy/mutation-baseline.md | grep -q "Updated:"
grep -c '^| `' docs/superpowers/specs/test-strategy/mutation-baseline.md
```

Expected: the `head` line confirms the date update and the row count is non-zero (or zero, if every survivor was a real gap and nothing was annotated).

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "docs(test-strategy): finalise rimap-content mutation-baseline

Drops the cap-exceeded callout and per-file count table from the
B1-deferred state. Per-survivor annotation table is populated by the
preceding commits in this PR; this commit only replaces the
YYYY-MM-DD/N placeholders with the final values from the
post-cleanup mutation run.

Closes the issue #192 done-criteria for the mutation-baseline doc.

Refs: #192
Refs: docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md"
```

---

## Task 15: Open the PR

**Why:** The branch is mergeable. A PR collects the per-module commits behind one review.

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin feat/issue-192-rimap-content-mutation-cleanup
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "test(rimap-content): finish mutation cleanup deferred from B1" \
  --body "$(cat <<'EOF'
## Summary

Closes #192. Drives `cargo mutants --package rimap-content` to zero unannotated surviving mutants outside `src/bin/`. Per-survivor annotations are recorded in `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

Per-module commit breakdown (one commit per module group):

- `parse/headers.rs`
- `parse/filename.rs`
- `parse/bodies.rs`
- `parse/mime_scrub.rs`
- `parse/{meta,attachments,mod}.rs`
- `html/style_parse.rs`
- `html/mismatch.rs`
- `html/{extract,mod}.rs`
- `lookalike.rs`
- `threading.rs` + `unicode.rs` + `raw_parts.rs` + `lib.rs`
- `mutation-baseline.md` finalisation

## Test plan

- [ ] `cargo mutants --package rimap-content --no-shuffle` reports zero unannotated `MISSED` mutants outside `src/bin/`.
- [ ] `mutation-baseline.md`'s `rimap-content` section shows: no cap-exceeded callout, no per-file count table, populated per-survivor annotation table, headline survivor count matches the table row count.
- [ ] `just ci` is green (rustfmt, clippy, check, test, test-msrv, cargo-deny, zizmor self-check).
- [ ] No `bin/epvme_runner.rs` survivor was touched (still out of scope per spec §4.3).
- [ ] Spec §4.5 done-criterion 3 is met.

EOF
)"
```

- [ ] **Step 3: Watch CI**

Run:
```bash
gh pr checks --watch
```

Expected: every existing CI check is green. No new fuzz workflow runs are triggered by this PR (the fuzz workflow's path filter requires changes under `crates/rimap-content/**` — which this PR has — so the `pr-smoke` job runs as a side effect; that is expected and should also be green).

- [ ] **Step 4: Request review**

Run:
```bash
gh pr ready 2>/dev/null || true   # in case it was opened as draft
gh pr comment --body "Ready for review — issue #192 done-criteria verified locally and in CI."
```

---

## Wrap-up

- [ ] **Step 1: Confirm spec §4.5 done-criterion 3 is satisfied**

The criterion: *"`cargo mutants --package rimap-content` reports 0 surviving mutants in non-`bin/` code, or every survivor has a `known-equivalent` annotation with rationale."*

Verification:
- Task 13 Step 2's output is the survivor count.
- Task 13 Step 3's output (no `UNANNOTATED:` lines) proves every survivor has an annotation.
- Task 13 Step 4's output (`match`) proves the doc table covers each annotation.

If all three hold, the criterion is met.

- [ ] **Step 2: Confirm issue #192 done-criteria are satisfied**

Each of the issue's three bullets:

1. *"`cargo mutants --package rimap-content` reports zero unannotated survivors outside `src/bin/`."* — verified in Task 13.
2. *"`mutation-baseline.md`'s `rimap-content` section is rewritten: drop the cap-exceeded callout and the per-file table; populate the per-survivor annotation table with every `known-equivalent` row; update the headline survivor count."* — verified in Task 14.
3. *"Spec §4.5 done-criterion 3 is met."* — verified in Wrap-up Step 1.

- [ ] **Step 3: Close the issue**

Once the PR merges, issue #192 closes automatically (the PR title `Closes #192` triggers the link). Confirm:
```bash
gh issue view 192
```

Expected: state is `CLOSED`.

---

## Self-review checklist (writer-side, do not skip)

- **Spec coverage:** issue #192's three done-criteria each map to a task — bullet 1 → Task 13, bullet 2 → Tasks 2 + 14, bullet 3 → Wrap-up Step 1. The spec §4.3 active-vs-plumbing distinction is encoded in Tasks 3–12's per-file bias notes (active sanitization tasks state "always kill"; plumbing Task 12 explicitly drops the bar).
- **No placeholders:** every command and code block contains literal text. The two `YYYY-MM-DD`/`N` placeholders in `mutation-baseline.md` are explicit doc-template tokens, replaced by Task 14 Steps 1–2 with concrete values.
- **Type/name consistency:** the file paths in the per-module tasks (`crates/rimap-content/src/parse/headers.rs`, etc.) match the verified-by-`find` repo layout. `parse_message`, `sanitize_html`, `scrub_header_smuggling`, `unicode::decode` are referenced by the same names used in the B1 plan and the existing test suite.
- **TDD-shape:** each module task's triage loop is failing-test-first ("write the test → run against unmutated code: PASS → re-run mutation: now CAUGHT"). The annotation path skips TDD by design — equivalent mutants have no failing-test framing.
- **One commit per logical change:** every task ends in one commit. Tasks 7, 10, and 12 explicitly group small files; the commit messages name every file in the group so `git log --oneline` reads as one cleanup per module *group*, matching the issue's "5–8 PR-sized commits batched by module" estimate.
- **Out-of-band actions are flagged:** the 30–90-minute `cargo mutants` runs in Tasks 1 and 13 are noted in-place. The follow-up issue for `bin/epvme_runner.rs` survivors is *not* in scope for this plan (per spec §4.3, that work is post-B4).
- **Cost/value tradeoffs documented:** Task 11's "largest single-file cleanup" framing, Task 12's combined-file rationale, and Task 6's higher-equivalence-bar callout are each motivated inline rather than left implicit.
