# `epvme_runner` Mutation Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Triage the surviving `cargo-mutants` mutants inside `crates/rimap-content/src/bin/epvme_runner.rs` (issue #193). Drive the file's `MISSED` count to zero by either (a) adding a test in the binary's `#[cfg(test)]` module that kills the mutant when the mutation affects the dataset's pass/fail signal or the JSON summary schema, or (b) annotating the mutation as `known-equivalent` with a one-line rationale and a row in `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

**Architecture:** Test-only and docs-only changes. No behavioral changes to `epvme_runner` itself, except possibly tightening a `#[cfg(test)]`-visible helper if a survivor cannot otherwise be observed. New tests live in the existing `mod tests` block at the end of `crates/rimap-content/src/bin/epvme_runner.rs` (the `simple_email`/`write_sample` helpers are already in place). Annotations live as `// cargo-mutants: known-equivalent — <rationale>` comments at the mutation site. The baseline doc gains a new `### \`bin/epvme_runner.rs\`` subsection under the existing `## \`rimap-content\`` heading.

**Tech Stack:** `cargo-mutants` 25.x or 27.x, `cargo-nextest`, `cargo clippy`, the existing `tempfile`-driven tests in `epvme_runner.rs`'s `#[cfg(test)]` module.

**Host parallelism cap (do not skip):** Every `cargo mutants` invocation in this plan must include `--jobs 2`. Default parallelism (one job per CPU core) has produced 300GB+ memory allocations on this host and frozen other applications. Trade longer wall-clock time for stability. Applies to both full-crate runs and per-file/per-line verification runs.

**Spec reference:** [`docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`](../specs/2026-04-30-test-strategy-improvements-design.md), §4.3 third bullet ("`bin/epvme_runner.rs` — survivors stay open. Diagnostic tooling, not production.") — issue #193 picks this up after Sprint B4 completes, per the spec's deferral.

**Issue reference:** [#193](https://github.com/randomparity/rusty-imap-mcp/issues/193).

**Baseline reference:** [`docs/superpowers/specs/test-strategy/mutation-baseline.md`](../specs/test-strategy/mutation-baseline.md), `## \`rimap-content\`` section. The 2026-04-30 refresh recorded 16 missed mutants inside `crates/rimap-content/src/bin/`.

**Branch:** `feat/issue-193-epvme-runner-mutation-cleanup` (cut from `main` before Task 1).

**Triage bar (from issue #193):** kill any mutation that affects the dataset's pass/fail signal (i.e. anything observable through `is_success`, `processed_files`, `ok_count`, `parse_error_count`, `read_failure_count`, `panic_count`, `recorded_failures`, `warning_counts`, `parse_error_counts`, or the CLI exit code) or the JSON summary schema (the field set, names, and types serialised into `RunSummary`/`FailureRecord`). Annotate everything else — diagnostic stdout phrasing, log-style summary lines, internal counter ordering — as `known-equivalent`.

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
- `git branch --show-current` is `feat/issue-193-epvme-runner-mutation-cleanup`. If not, stop and create it: `git checkout -b feat/issue-193-epvme-runner-mutation-cleanup`.
- `git status --short` is empty.
- `cargo-mutants` and `cargo-nextest` are on PATH. If missing: `cargo install --locked cargo-mutants cargo-nextest`.
- `cargo mutants --version` prints a 25.x version. Older versions emit a different `missed.txt` format and break the parsing in Task 1.

---

## Task 1: Refresh the `cargo-mutants` baseline against current `main`

**Why:** The 2026-04-30 baseline cited 16 `MISSED` mutants in `src/bin/` at commit `d83b81a` (PR #191). Subsequent merges (e.g. issue #194's grapheme-truncation refactors landed on 2026-05-01) may have shifted line numbers or coverage. We re-run first and treat the refreshed list — not the issue's count — as the source of truth.

**Files:**
- Touched only as a side effect: `mutants.out/` (gitignored).
- No commit at this task; the survivor inventory feeds Tasks 3+.

- [ ] **Step 1: Run the targeted mutation suite on `rimap-content`**

Run:
```bash
cargo mutants --package rimap-content --no-shuffle --jobs 2 2>&1 | tee /tmp/mutants-rimap-content.log
```

Expected: 30–90 minutes. Output writes to `mutants.out/` and the tee'd log. If `cargo mutants` errors out before the per-mutant phase ("baseline build failed"), fix the workspace's `cargo nextest run --package rimap-content --all-features --locked` first — `cargo-mutants` will not run if the unmutated baseline doesn't build and pass.

- [ ] **Step 2: Snapshot the `bin/` survivor list**

Run:
```bash
mkdir -p /tmp/mutation-cleanup-193
grep -E "^crates/rimap-content/src/bin/epvme_runner\.rs" mutants.out/missed.txt \
  > /tmp/mutation-cleanup-193/bin-survivors.txt
wc -l /tmp/mutation-cleanup-193/bin-survivors.txt
cat /tmp/mutation-cleanup-193/bin-survivors.txt
```

Expected: a count near 16 (the 2026-04-30 figure). If the count is materially different (e.g. <5 or >25), note it in the eventual commit message — that's a signal that recent refactors changed coverage.

- [ ] **Step 3: Bucket survivors by function group**

Each line in `bin-survivors.txt` has the format `path:line:col: <description>`. Group lines by which top-level function in `epvme_runner.rs` contains them. The functions are (in source order):

| Function | Approx line range | Bucket |
|---|---|---|
| `main`, `run` | 87–122 | A — entry/exit |
| `parse_args`, `usage` | 124–187 | B — CLI args |
| `collect_eml_files`, `walk_eml_files`, `is_eml_path` | 189–242 | C — file discovery |
| `run_dataset`, `parse_one`, `panic_message`, `unknown_warning_code_label`, `record_failure` | 244–355 | D — dataset loop |
| `print_summary` | 357–403 | E — stdout summary |
| `write_json_report`, `is_success` | 405–429 | F — JSON / success |

Run:
```bash
cd /tmp/mutation-cleanup-193
awk -F: '{ print $2 ": " $0 }' bin-survivors.txt | sort -n > by-line.txt
cat by-line.txt
```

Read `by-line.txt` and tag each survivor with its bucket letter (A–F) in a scratch note. Tasks 3–8 below correspond to buckets A–F respectively. Note any bucket with zero survivors — that task is skipped.

- [ ] **Step 4: Confirm there are still survivors to clean up**

Run:
```bash
test -s /tmp/mutation-cleanup-193/bin-survivors.txt && echo "survivors present"
```

Expected: prints `survivors present`. If empty, the mutation refresh shows no remaining work — skip to Task 9 (the docs update is still required to record the new state).

---

## Task 2: Stage `mutation-baseline.md` for the `bin/epvme_runner.rs` subsection

**Why:** The current `## \`rimap-content\`` section explicitly defers `bin/` survivors ("The `bin/epvme_runner.rs` survivors are out of scope — that crate is diagnostic tooling, not production. Re-evaluate post-B4."). Issue #193 *is* the post-B4 re-evaluation, so we replace that paragraph with a new `### \`bin/epvme_runner.rs\`` subsection that owns the file's survivors. Tasks 3–8 append rows to this subsection's table; Task 9 finalises the count.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Replace the "out of scope" paragraph with a new subsection**

Open `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Find the paragraph that reads:

```markdown
The `bin/epvme_runner.rs` survivors are out of scope — that crate is
diagnostic tooling, not production. Re-evaluate post-B4.
```

Replace it with:

````markdown
### `bin/epvme_runner.rs`

**Last refresh:** YYYY-MM-DD (replace with today's date when committing Task 9).
**Surviving mutants:** N (replace with the `wc -l /tmp/mutation-cleanup-193/bin-survivors.txt` count from Task 1 Step 2 — every survivor is annotated below).

Issue [#193](https://github.com/randomparity/rusty-imap-mcp/issues/193)
drives this list to zero. Triage bar: a mutation that affects the
dataset's pass/fail signal (counts in `RunSummary`, `is_success`, the
process exit code) or the JSON summary schema is killed by adding a
test; everything else (stdout phrasing, log-style summary lines,
diagnostic-only counter ordering) is annotated as `known-equivalent`
with a one-line rationale.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| _table populated incrementally by Tasks 3–8_ |  |  |  |
````

(`YYYY-MM-DD` and `N` are real placeholders that ride in the doc until Task 9 finalises them; do not substitute now.)

- [ ] **Step 2: Verify the doc still parses as Markdown**

Run:
```bash
test -f docs/superpowers/specs/test-strategy/mutation-baseline.md
grep -c '^| ' docs/superpowers/specs/test-strategy/mutation-baseline.md
grep -n '### `bin/epvme_runner.rs`' docs/superpowers/specs/test-strategy/mutation-baseline.md
```

Expected: a non-zero `^|` count (table headers), and a single match for the new `###` heading. The doc is committed as part of Task 9's final commit — no commit at this task.

---

## Task 3: Bucket A — `main` and `run`

**Why:** Bucket A holds the top-level entry and exit-code wiring. Mutations here that change which `ExitCode` returns under what conditions affect the dataset's pass/fail signal — those are real gaps. Mutations that change error-message phrasing on stderr are cosmetic.

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (the existing `mod tests` block at the bottom; possibly inline annotation comments).
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md` (table row appends).

- [ ] **Step 1: Filter the survivor list to bucket A**

Run:
```bash
awk -F: '$2 >= 87 && $2 <= 122' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-A.txt
wc -l /tmp/mutation-cleanup-193/bucket-A.txt
```

Note the count `K`. If `K == 0`, skip to Task 4.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

For each line in `bucket-A.txt`, in source order:

1. **Read the mutation.** Open `epvme_runner.rs` at the named line. Common shapes here:
   - `replace ExitCode::SUCCESS with ExitCode::from(1)` (or the inverse) inside `main`'s match arms.
   - `delete match arm RunnerError::UsageMessage(msg)` inside `main`.
   - `replace fn run -> RunnerResult<ExitCode> with Default::default()` (the entire body stubbed).
   - `replace if is_success(&summary) condition` toggles inside `run`.

2. **Decide: real gap, or equivalent mutant?**
   - **Mutation changes the ExitCode returned for any input** → real gap. The CLI contract is `0` for "all samples parsed", `1` for "at least one sample failed", `2` for any runner error other than `--help`. Tests must lock this.
   - **Mutation deletes the `UsageMessage` arm** → real gap. `--help` must exit 0 (not 2), and the `UsageMessage` variant exists *only* to carry that exit code.
   - **Mutation changes a stderr write phrasing** (e.g. swaps the order of `{err}` and a label) → equivalent. No test inspects stderr formatting.

3. **If real gap, write a failing test first.**

   `epvme_runner.rs` is a binary, so its `mod tests` already imports `super::*` and has access to `run`. `main` itself isn't directly callable from tests, but its three match arms are testable indirectly through the helpers `run`, `is_success`, and `RunnerError`. Pattern for the most common gap (exit-code wiring under `is_success` false vs. true):

   ```rust
   #[test]
   fn run_returns_exit_one_when_dataset_has_failures() {
       // Mutation: replace ExitCode::from(1) with ExitCode::SUCCESS in `run`.
       // Assertion: a parse failure must drive run() to ExitCode::from(1).
       let tempdir = TempDir::new().unwrap();
       let root = tempdir.path();
       write_sample(root, "1/bad.eml", b"not a valid email\r\n");
       let files = vec![root.join("1/bad.eml")];
       let summary = run_dataset(root, &files, None, |_raw| {
           Err(ContentError::Malformed { reason: "synthetic".into() })
       });
       assert!(!is_success(&summary));
   }
   ```

   For the `UsageMessage` arm in `main`: that mutation is observable only through process-level invocation. If it cannot be covered by a unit test, treat it as `known-equivalent` *with a rationale that explicitly notes the gap*: "Match arm collapses two stderr-only paths; both still exit non-zero. CLI-level coverage would belong in an end-to-end test, deferred." Document and move on — the rule is "kill what we can observe in-process," not "find a way to observe everything."

   Naming convention: `<function>_<observable>_<short_mutation_description>` so the breadcrumb survives in `cargo nextest` output.

   Run the test against unmutated code:
   ```bash
   cargo nextest run --package rimap-content --all-features run_returns_exit_one -- --nocapture
   ```

   Expected: PASS.

4. **Verify the test catches the mutation.** Run only the mutants on this file, restricted to the cited line:
   ```bash
   cargo mutants --package rimap-content \
     --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
     --re ":<line_number>:" \
     --no-shuffle \
     --jobs 2
   ```

   Expected: that mutant moves from `MISSED` to `CAUGHT`. If it stays `MISSED`, tighten the assertion.

5. **If equivalent mutant, annotate inline.** Insert a comment immediately above the line the mutant rewrites:

   ```rust
   // cargo-mutants: known-equivalent — <one-line rationale>
   ```

   And append a row to the `### \`bin/epvme_runner.rs\`` table in `mutation-baseline.md`:

   ```markdown
   | `bin/epvme_runner.rs:<line>` | `<mutation description>` | <rationale> | `bin/epvme_runner.rs:<line-of-comment>` |
   ```

   Rationale bar — the line must explain *why the output that callers can observe is the same*, not "diagnostic only" without proof. Acceptable phrasings:
   - "stderr-only error phrasing; no test or production caller inspects message text."
   - "Counter `processed_files` is incremented exactly once per loop iteration regardless of mutation; the surrounding `+= 1` cannot reach `+ 0` without skipping the iteration entirely, which is gated upstream."

- [ ] **Step 3: Re-run mutation tests on this file only**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket A's line range either has a corresponding annotation comment in source *and* a row in `mutation-baseline.md`, or has been killed by a test. `cargo-mutants` does not parse the annotation comment — verification is by visual inspection against the table you appended.

- [ ] **Step 4: Run clippy + tests for the crate**

Run:
```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean. New tests must pass; new annotation comments must not trip pedantic lints.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): triage epvme_runner main/run mutants

Adds N tests covering cargo-mutants survivors in main and run.
M known-equivalent mutants annotated inline with rationale, recorded
in mutation-baseline.md.

Refs: #193"
```

Replace `N` and `M` with the actual counts. If `N == 0` and `M == 0` because bucket A had no survivors, skip the commit.

---

## Task 4: Bucket B — `parse_args` and `usage`

**Why:** CLI argument parsing is the user-facing input boundary. Mutations that change which inputs parse to which `Args` value affect the dataset's pass/fail signal indirectly — a `--limit 0` accepted as `--limit usize::MAX` would change `processed_files`. Mutations on the `usage()` string are cosmetic.

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs` (the existing `mod tests` block; possibly inline annotation comments).
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

- [ ] **Step 1: Filter the survivor list to bucket B**

Run:
```bash
awk -F: '$2 >= 124 && $2 <= 187' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-B.txt
wc -l /tmp/mutation-cleanup-193/bucket-B.txt
```

Note the count `K`. If `K == 0`, skip to Task 5.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

The `parse_args` function reads `std::env::args_os()`, so it cannot be unit-tested as written. Refactor to a testable shape *as a precondition*: introduce a private `parse_args_from(iter: impl Iterator<Item = OsString>) -> RunnerResult<Args>` and have `parse_args` delegate. This refactor is in-scope for this task — without it, mutation survivors in `parse_args` are untestable.

The refactor:

```rust
fn parse_args() -> RunnerResult<Args> {
    let mut args = std::env::args_os();
    let _program = args.next();
    parse_args_from(args)
}

fn parse_args_from<I>(mut args: I) -> RunnerResult<Args>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let mut dataset_root: Option<PathBuf> = None;
    let mut limit: Option<usize> = None;
    let mut json_out: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        // ... existing match body, unchanged ...
    }

    let Some(dataset_root) = dataset_root else {
        return Err(RunnerError::Argument(usage()));
    };

    Ok(Args { dataset_root, limit, json_out })
}
```

Commit this refactor as Step 2a *before* writing tests, so a downstream reviewer sees the structural change separately from the mutation-killing tests.

For each survivor in `bucket-B.txt`, in source order, follow the same triage decision tree as Task 3 Step 2, with these bucket-specific cues:

- **Real gap shapes:**
  - `replace --limit branch with default arm`: `--limit 5 root/` would silently lose the limit. Test:
    ```rust
    #[test]
    fn parse_args_from_accepts_limit_flag() {
        let args = parse_args_from(
            ["--limit", "5", "root"]
                .iter()
                .map(|s| std::ffi::OsString::from(s)),
        ).unwrap();
        assert_eq!(args.limit, Some(5));
        assert_eq!(args.dataset_root, PathBuf::from("root"));
    }
    ```
  - `replace usize::parse with Default::default()` on the `--limit` value: `--limit foo root/` would parse to `Some(0)`. Test the rejection path:
    ```rust
    #[test]
    fn parse_args_from_rejects_non_numeric_limit() {
        let err = parse_args_from(
            ["--limit", "foo", "root"]
                .iter()
                .map(|s| std::ffi::OsString::from(s)),
        ).unwrap_err();
        assert!(matches!(err, RunnerError::Argument(_)));
    }
    ```
  - `replace dataset_root.is_some() with false`: extra positional arg silently overwrites the first. Test the "two positionals" rejection path.
  - `replace --help arm`: `--help` would no longer be `UsageMessage`; the help text becomes a parse error. Test that `--help` → `Err(RunnerError::UsageMessage(_))`.

- **Equivalent shapes:**
  - `replace usage() body with String::new()`: the help text is a UX surface, not a contract. Annotate as `known-equivalent — usage string is human-facing only; no test or production caller inspects its content`.
  - Mutations on the order of mutually exclusive match arms inside the `while let` loop where each arm `return`s or assigns to a distinct `Option`: equivalent because no input flows through more than one arm.

Write tests, verify each catches its mutant, annotate the rest. Same loop structure as Task 3.

- [ ] **Step 3: Re-run mutation tests on this file only**

Run:
```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket B's line range is annotated or killed.

- [ ] **Step 4: Run clippy + tests**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): triage epvme_runner parse_args mutants

Refactors parse_args to delegate to parse_args_from for testability.
Adds N tests covering --limit, --json-out, --help, and positional
argument paths. M known-equivalent mutants annotated inline.

Refs: #193"
```

---

## Task 5: Bucket C — `collect_eml_files`, `walk_eml_files`, `is_eml_path`

**Why:** File discovery already has one regression test (`collect_eml_files_walks_nested_tree`) but mutation testing typically surfaces gaps in the recursive walk: `entry.file_type() is_dir` vs. `is_file` swaps, the case-insensitive extension check, the non-existent / non-directory error paths.

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs`.
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

- [ ] **Step 1: Filter the survivor list to bucket C**

Run:
```bash
awk -F: '$2 >= 189 && $2 <= 242' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-C.txt
wc -l /tmp/mutation-cleanup-193/bucket-C.txt
```

Note `K`.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Bucket-specific cues:

- **Real gap shapes:**
  - `replace !root.exists() with false`: a missing dataset root would not raise `RunnerError::Argument`. Test:
    ```rust
    #[test]
    fn collect_eml_files_rejects_missing_root() {
        let err = collect_eml_files(Path::new("/nonexistent/path/that/should/not/exist"))
            .unwrap_err();
        assert!(matches!(err, RunnerError::Argument(_)));
    }
    ```
  - `replace !root.is_dir() with false`: a path that's a file instead of a directory would walk past the guard. Test by writing a file and pointing `collect_eml_files` at it.
  - `replace eq_ignore_ascii_case with str::eq` in `is_eml_path`: `.EML` would be skipped. The existing `collect_eml_files_walks_nested_tree` test covers this if the `.EML` sample is unambiguously asserted; if the existing test only counts files, add an explicit assertion that the upper-case variant is in the result.
  - `replace file_type.is_dir() with false`: subdirectories no longer recurse. Test with a two-level tree where the only `.eml` lives in a subdir.
  - `replace files.sort() with default ()`: file order becomes platform-dependent. Test that the returned list is in lexicographic order.

- **Equivalent shapes:**
  - `replace operation: "read directory" with operation: ""`: error-context labels are stderr-only. Annotate.
  - Reordering of two consecutive `if`s inside `walk_eml_files` whose conditions are mutually exclusive (`is_dir` vs. `is_file && is_eml_path`): mutually exclusive predicates make order irrelevant.

Same triage loop as Task 3.

- [ ] **Step 3: Re-run mutation tests on this file only**

```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket C is annotated or killed.

- [ ] **Step 4: Run clippy + tests**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): triage epvme_runner file-discovery mutants

Adds N tests covering collect_eml_files, walk_eml_files, and
is_eml_path against missing-root, non-directory, case-insensitive
extension, recursion, and sort-order paths. M known-equivalent
mutants annotated inline.

Refs: #193"
```

---

## Task 6: Bucket D — `run_dataset`, `parse_one`, `panic_message`, `unknown_warning_code_label`, `record_failure`

**Why:** The dataset processing loop is the function that produces the JSON summary schema and the success/failure verdict. This is the bucket where the triage bar is most likely to flag real gaps. Existing tests (`run_dataset_reports_parse_errors_by_kind`, `run_dataset_catches_panics_and_continues`, `run_dataset_honors_limit`, `run_dataset_aggregates_warning_counts`) cover a lot of ground — survivors here pinpoint exactly what the existing tests miss.

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs`.
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

- [ ] **Step 1: Filter the survivor list to bucket D**

Run:
```bash
awk -F: '$2 >= 244 && $2 <= 355' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-D.txt
wc -l /tmp/mutation-cleanup-193/bucket-D.txt
```

Note `K`. This is expected to be the largest bucket — most of the 16 baseline survivors clustered here.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Bucket-specific cues:

- **Real gap shapes:**
  - `replace summary.processed_files += 1 with default ()`: `processed_files` no longer tracks the loop count, breaking the JSON schema. Test:
    ```rust
    #[test]
    fn run_dataset_processed_files_matches_iterations() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let a = write_sample(root, "1/a.eml", &simple_email("a"));
        let b = write_sample(root, "1/b.eml", &simple_email("b"));
        let c = write_sample(root, "1/c.eml", &simple_email("c"));
        let summary = run_dataset(root, &[a, b, c], None, parse_message);
        assert_eq!(summary.processed_files, 3);
        assert_eq!(summary.discovered_files, 3);
    }
    ```
  - `replace summary.read_failure_count += 1 with default ()`: a read error is invisible. Test by pointing at a non-readable path (use `/proc/1/mem` on Linux, or write a file then chmod 000 — skip on Windows). Or, easier, supply `&[PathBuf]` containing a path that doesn't exist:
    ```rust
    #[test]
    fn run_dataset_records_read_failures() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let missing = root.join("nonexistent.eml");
        let summary = run_dataset(root, &[missing], None, parse_message);
        assert_eq!(summary.read_failure_count, 1);
        assert_eq!(summary.recorded_failures.len(), 1);
        assert_eq!(summary.recorded_failures[0].kind, "read_error");
        assert!(!is_success(&summary));
    }
    ```
  - `replace MAX_RECORDED_FAILURES check`: more than 50 failures would still be recorded, growing `recorded_failures` unboundedly. Test with 51+ failing samples and assert `recorded_failures.len() == 50`.
  - `replace warning_counts.entry(label).or_insert(0) with default ()`: warning counts no longer increment. Already covered by `run_dataset_aggregates_warning_counts` if it asserts the count is exactly `1`; if it only asserts presence, tighten.
  - `replace ContentError::Malformed match with Default::default()` in `parse_one`: a parse error becomes a panic or vice versa. Test both branches return the right `SampleOutcome`.
  - `replace panic::catch_unwind result with Ok(...)` in `parse_one`: a panic propagates instead of being captured. Already covered by `run_dataset_catches_panics_and_continues` if the assertion is `panic_count == 1`; tighten if needed.

- **Equivalent shapes:**
  - `replace _ payload binding name in panic_message`: payload variable shadowing is bind-only; no observable difference.
  - `replace WarningSeverity::Adversarial arm with WarningSeverity::Informational arm` in `unknown_warning_code_label`: only matters if any caller distinguishes the returned label string. The label is consumed only as a hash-map key in `warning_counts` — both labels still produce a recordable bucket. Annotate, with the rationale "label string is the BTreeMap key only; downstream callers count occurrences, not differentiate buckets at this granularity."
  - `replace summary.recorded_failures.len() >= MAX_RECORDED_FAILURES with > MAX_RECORDED_FAILURES` in `record_failure`: off-by-one differs at exactly `len == 50`, which means `>=` records 50 failures and `>` records 51. The cap is a soft limit and the existing tests don't pin which side of 50 the boundary sits on. Decision: this is a real schema observation — write a test that fixes the cap at exactly 50 (kill, don't annotate).

Same triage loop as Task 3.

- [ ] **Step 3: Re-run mutation tests on this file only**

```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket D is annotated or killed.

- [ ] **Step 4: Run clippy + tests**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): triage epvme_runner dataset-loop mutants

Adds N tests covering processed_files counters, read_failure path,
MAX_RECORDED_FAILURES cap, panic capture, and warning aggregation.
M known-equivalent mutants annotated inline.

Refs: #193"
```

---

## Task 7: Bucket E — `print_summary`

**Why:** `print_summary` is pure stdout phrasing — header lines, label punctuation, ordering of optional sections. By the triage bar, none of these affect the dataset's pass/fail signal or the JSON schema. Most survivors here will annotate, not kill. The exception is anything that affects whether a section prints *at all* when its underlying data is non-empty (the `if !summary.parse_error_counts.is_empty()` guards).

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs`.
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

- [ ] **Step 1: Filter the survivor list to bucket E**

Run:
```bash
awk -F: '$2 >= 357 && $2 <= 403' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-E.txt
wc -l /tmp/mutation-cleanup-193/bucket-E.txt
```

Note `K`. If `K == 0`, skip to Task 8.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Bucket-specific cues:

- **Real gap shapes:** none expected. `print_summary` writes only to stdout, has no return value other than `io::Result<()>`, and doesn't feed back into the success verdict. Default to annotation.

- **Equivalent shapes (annotate):**
  - All `replace writeln! format string` mutations: stdout phrasing is human-facing only.
  - `replace if !summary.recorded_failures.is_empty() with true`: on an empty failure list this would print the "Recorded failures (showing up to ...)" header followed by no lines. Visually noisier but still cosmetic. Annotate with a rationale: "guarded section header omission is human-facing only; no test or programmatic consumer parses stdout."
  - `replace stdout.lock() with stderr.lock()`: would change destination. Borderline — if a CI consumer pipes stdout to a JSON sink and stderr to logs, this would be observable. But the documented contract is: JSON summary goes to `--json-out`, stdout is human-readable. Annotate, with the rationale calling out the contract.

If a survivor here genuinely seems to affect the JSON schema, the line was misclassified — re-check the function it belongs to. (`write_json_report` lives in bucket F.)

- [ ] **Step 3: Re-run mutation tests on this file only**

```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket E is annotated.

- [ ] **Step 4: Run clippy + tests**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): annotate epvme_runner print_summary mutants

Annotates K stdout-only mutants in print_summary as known-equivalent
with rationale (human-facing diagnostic phrasing, not a JSON-schema
or success-verdict surface). Recorded in mutation-baseline.md.

Refs: #193"
```

If bucket E was empty (`K == 0`), skip the commit.

---

## Task 8: Bucket F — `write_json_report` and `is_success`

**Why:** `write_json_report` writes the JSON summary — the schema is a triage-bar-protected surface. `is_success` is the single function that gates the binary's exit code. Mutations here are almost all real gaps.

**Files:**
- Modify: `crates/rimap-content/src/bin/epvme_runner.rs`.
- Possibly modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`.

- [ ] **Step 1: Filter the survivor list to bucket F**

Run:
```bash
awk -F: '$2 >= 405 && $2 <= 429' /tmp/mutation-cleanup-193/bin-survivors.txt \
  | tee /tmp/mutation-cleanup-193/bucket-F.txt
wc -l /tmp/mutation-cleanup-193/bucket-F.txt
```

Note `K`. If `K == 0`, skip to Task 9.

- [ ] **Step 2 (loop, K iterations): Triage one survivor**

Bucket-specific cues:

- **Real gap shapes:**
  - `replace fn is_success -> bool with true`: a failing dataset would still report success. Test:
    ```rust
    #[test]
    fn is_success_requires_zero_failures() {
        let mut summary = RunSummary {
            dataset_root: String::new(),
            discovered_files: 0,
            processed_files: 0,
            ok_count: 0,
            panic_count: 0,
            read_failure_count: 0,
            parse_error_count: 0,
            limit: None,
            warning_counts: BTreeMap::new(),
            parse_error_counts: BTreeMap::new(),
            recorded_failures: Vec::new(),
        };
        assert!(is_success(&summary));
        summary.parse_error_count = 1;
        assert!(!is_success(&summary));
        summary.parse_error_count = 0;
        summary.read_failure_count = 1;
        assert!(!is_success(&summary));
        summary.read_failure_count = 0;
        summary.panic_count = 1;
        assert!(!is_success(&summary));
    }
    ```
  - `replace && with || in is_success`: any single zero would mark success even when others are non-zero. Same test as above catches it.
  - `replace fs::write with Default::default()` in `write_json_report`: the JSON file is silently skipped. Test:
    ```rust
    #[test]
    fn write_json_report_creates_file_with_summary_fields() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("out.json");
        let summary = RunSummary {
            dataset_root: "root".into(),
            discovered_files: 2,
            processed_files: 2,
            ok_count: 1,
            panic_count: 0,
            read_failure_count: 0,
            parse_error_count: 1,
            limit: None,
            warning_counts: BTreeMap::new(),
            parse_error_counts: BTreeMap::new(),
            recorded_failures: Vec::new(),
        };
        write_json_report(&path, &summary).unwrap();
        let bytes = fs::read(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["discovered_files"], 2);
        assert_eq!(parsed["ok_count"], 1);
        assert_eq!(parsed["parse_error_count"], 1);
    }
    ```
  - `replace parent.as_os_str().is_empty() guard`: writing to a relative bare filename would attempt to `create_dir_all("")`. Test by writing to a path with a non-empty parent and a path with an empty parent (use `tempdir.path().join("file.json")` for the former; relative paths in tests are fragile, so consider whether this branch is worth a dedicated test).

- **Equivalent shapes:**
  - Mutations on the `RunnerError::Filesystem` `operation` label strings: error context only, no programmatic consumer.

- [ ] **Step 3: Re-run mutation tests on this file only**

```bash
cargo mutants --package rimap-content \
  --file 'crates/rimap-content/src/bin/epvme_runner.rs' \
  --no-shuffle \
  --jobs 2
```

Expected: every `MISSED` mutant in bucket F is annotated or killed.

- [ ] **Step 4: Run clippy + tests**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-content/src/bin/epvme_runner.rs \
        docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "test(rimap-content): triage epvme_runner JSON/success mutants

Adds N tests covering is_success's three-counter AND-gate and the
write_json_report file-creation contract. M known-equivalent mutants
annotated inline.

Refs: #193"
```

---

## Task 9: Final verification + baseline-doc finalisation

**Why:** Confirm the per-task work drove `bin/epvme_runner.rs` `MISSED` mutants to "annotated or killed" globally, and finalise the placeholders in `mutation-baseline.md`.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md` (replace `YYYY-MM-DD` and `N` placeholders).

- [ ] **Step 1: Re-run the full mutation suite on `rimap-content`**

Run:
```bash
cargo mutants --package rimap-content --no-shuffle --jobs 2 2>&1 | tee /tmp/mutants-rimap-content-final.log
```

Expected: same runtime as Task 1 (30–90 minutes). The `mutants.out/missed.txt` should still report a number of `bin/epvme_runner.rs` survivors equal to the count of annotated lines in the file (annotations don't suppress mutant generation; they document the human verdict).

- [ ] **Step 2: Cross-check annotation count vs. survivor count**

Run:
```bash
grep -c "// cargo-mutants: known-equivalent" \
  crates/rimap-content/src/bin/epvme_runner.rs
grep -E "^crates/rimap-content/src/bin/epvme_runner\.rs" mutants.out/missed.txt | wc -l
grep -c '`bin/epvme_runner.rs:' \
  docs/superpowers/specs/test-strategy/mutation-baseline.md
```

Expected: the first two counts match (every survivor has an inline annotation), and the third (table-row count) equals the second. If the annotation count is lower, an annotation is missing — check the bucket commits. If the table-row count is lower, a row was forgotten — append it.

- [ ] **Step 3: Replace the placeholders in `mutation-baseline.md`**

Open `docs/superpowers/specs/test-strategy/mutation-baseline.md`, find the `### \`bin/epvme_runner.rs\`` section, and:
- Replace `**Last refresh:** YYYY-MM-DD` with today's actual date (e.g. `**Last refresh:** 2026-05-01`).
- Replace `**Surviving mutants:** N` with the number from Step 2 (e.g. `**Surviving mutants:** 12`).
- Delete the placeholder row `| _table populated incrementally by Tasks 3–8_ |  |  |  |` if no real rows were appended (i.e. every survivor was killed); otherwise leave the placeholder removed (it should already have been overwritten by Task 3's first row).

- [ ] **Step 4: Run the full crate tests + clippy + deny one last time**

```bash
cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-content --all-features --locked
just deny
```

Expected: all clean.

- [ ] **Step 5: Commit the baseline-doc finalisation**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "docs(test-strategy): finalise epvme_runner mutation-baseline section

Records the post-#193 state: 0 unannotated MISSED mutants in
bin/epvme_runner.rs, with each known-equivalent annotation backed
by a rationale row in the baseline table.

Refs: #193
Closes: #193"
```

- [ ] **Step 6: Push and open the PR**

```bash
git push -u origin feat/issue-193-epvme-runner-mutation-cleanup
gh pr create --title "test(rimap-content): triage epvme_runner mutation survivors (#193)" \
  --body "$(cat <<'EOF'
## Summary

- Refreshes \`cargo-mutants\` against \`crates/rimap-content/src/bin/epvme_runner.rs\` and triages every survivor against the issue-#193 bar (kill anything affecting the dataset's pass/fail signal or the JSON summary schema; annotate everything else).
- Adds N tests in the binary's existing \`mod tests\` block covering exit-code wiring, CLI argument parsing, file discovery, dataset-loop counters, and the JSON summary contract.
- Annotates M known-equivalent mutants inline with one-line rationales and records each in \`docs/superpowers/specs/test-strategy/mutation-baseline.md\`.

## Test plan

- [ ] \`cargo nextest run --package rimap-content --all-features --locked\` is green.
- [ ] \`cargo clippy --package rimap-content --all-targets --all-features --locked -- -D warnings\` is green.
- [ ] \`cargo mutants --package rimap-content --no-shuffle --jobs 2\` reports zero unannotated \`MISSED\` mutants in \`bin/epvme_runner.rs\`.
- [ ] \`just deny\` is green.

Closes #193.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Replace `N` and `M` in the body with the actual counts before publishing.

---

## Self-Review Checklist (run after every task)

- **Spec coverage:** Issue #193 wants every `bin/epvme_runner.rs` survivor either killed by a test (when it affects the pass/fail signal or JSON schema) or annotated as `known-equivalent` with rationale. Tasks 3–8 cover every line range in the file; Task 9 cross-checks annotation count against survivor count.
- **Placeholder scan:** No `TBD` / `TODO` / "implement later" / "fill in details" in this plan. The two literal placeholders (`YYYY-MM-DD`, `N`) in Task 2 Step 1 are explicitly marked as ride-along placeholders that Task 9 finalises.
- **Type consistency:** All test code references real `RunSummary`, `FailureRecord`, `SampleOutcome`, `ContentError`, `RunnerError`, `parse_message`, `is_success`, `run_dataset`, `parse_args_from`, `write_json_report`, `is_eml_path`, `collect_eml_files`, `record_failure` items as they appear in the source. The `parse_args_from` symbol is introduced in Task 4 Step 2 before being referenced.
- **Triage bar consistency:** Every task header re-states the bar (pass/fail signal + JSON schema → kill; everything else → annotate) so a fresh subagent picking up bucket C without reading the whole plan still applies the right rule.
