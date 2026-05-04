# cargo-mutants runbook

## Why this exists

cargo-mutants 27.0.0 has a temp-tree handling bug that strands worker
copies missing source files mid-run, surfacing as `Worker thread failed:
"<file>" is not a file` even when the named file is a regular UTF-8
source on disk. The project-default workaround is `--in-place`, which
operates on the live source tree and sidesteps the temp-copy path
entirely. This runbook is the canonical source for invocations,
caveats, and the cleanup checklist for when upstream lands a fix. See
[issue #235](https://github.com/randomparity/rusty-imap-mcp/issues/235)
and upstream [`sourcefrog/cargo-mutants#611`](https://github.com/sourcefrog/cargo-mutants/issues/611).

## Blessed invocations

All commands assume a clean working tree (`git status` shows nothing).
`--in-place` mutates the live tree, so any local edits will collide.

| Situation | Command |
|---|---|
| Quarterly workspace survey (per `fuzzing-coverage.md`) | `just mutants --workspace --timeout 60 -- --test-threads 1` |
| Single-package survey | `just mutants --package <crate>` |
| Single-mutant inspection (regex on mutant name) | `just mutants --package <crate> -F '<regex>'` |

The `just mutants` recipe is a thin wrapper around `cargo mutants
--in-place`. Pass any extra flags after the recipe name; they are
forwarded verbatim.

## What `--in-place` costs you

- **Locked to `--jobs 1`.** cargo-mutants refuses parallel jobs in
  `--in-place` mode because they would race on the same files. Survey
  runs are correspondingly slower.
- **Mutates the live tree.** A `Ctrl-C` mid-run can leave a mutated
  source file in place. Recover with `git restore <file>` (or
  `git restore .` if you do not know which file).
- **Cannot edit the same files concurrently.** Do not run `just
  mutants` against a crate you are actively editing; either finish
  your edit and commit, or stash first.
- **Conflicts with rust-analyzer / IDE rebuilds.** Either disable the
  language server for the run or expect noisy diagnostics while the
  tree is briefly mutated.

## Why not just downgrade to 25.x?

cargo-mutants 25.x predates the reflink path and so does not hit the
macOS `dirhelper` race at all. It would also unlock `--jobs N` on
macOS, taking a workspace survey from ~3.5 hours to ~50 minutes. We
chose `--in-place` over the downgrade for four reasons:

- The project has a documented RAM ceiling on the development host
  (see `feedback_cargo_mutants_jobs_cap.md`); high `--jobs` settings
  freeze the box. `--in-place` forces `--jobs 1`, which neutralises
  that hazard for free.
- 25.x is roughly 18 months of missed mutant operators and bug fixes;
  the survey would catch a strictly smaller (and different) set of
  mutants than 26+.
- We do not pin cargo-mutants in this repo (it is `cargo install`-ed
  by `just setup`). Pinning to `=25.x` adds a maintenance step on
  every contributor box and a re-test when we eventually unpin.
- Cleanup when upstream lands a fix is one line (drop `--in-place`
  from the recipe). A version pin would mean an unpin + a fresh
  version-bump retest.

If wall-clock time on macOS becomes the binding constraint before
upstream fixes [#611](https://github.com/sourcefrog/cargo-mutants/issues/611),
the right move is to revisit this — but defaulting to 25.x today
trades a short-lived problem for a long-lived one.

## The bug, in detail

Symptom (from [#235](https://github.com/randomparity/rusty-imap-mcp/issues/235),
verbatim):

```
ERROR Worker thread failed: ".../cargo-mutants-rusty-imap-mcp-XXXXXX.tmp/crates/rimap-content/src/parse/sniff.rs" is not a file
Error: ".../crates/rimap-content/src/parse/sniff.rs" is not a file
```

`crates/rimap-content/src/parse/sniff.rs` is a regular UTF-8 source
file declared by `mod sniff;` in `parse/mod.rs` with no `#[path]`
attribute, no symlinks, and no sibling subdirectories. The bug is in
cargo-mutants' temp-tree handling on macOS: a worker's per-mutant
scratch tree is missing `sniff.rs` (and other files — multiple vanish
silently) even though the source has them. Per the upstream
investigation in [#611](https://github.com/sourcefrog/cargo-mutants/issues/611),
the macOS `dirhelper` background process unlinks the reflink copies
that [#557](https://github.com/sourcefrog/cargo-mutants/pull/557)
(landed in 26.0.0) introduced. Linux/btrfs, which also supports
reflinks, does not reproduce — so this is macOS-specific, not generic
to reflinks.

Diagnostic capture procedure (run from a clean tree):

```bash
mkdir -p /tmp/issue-235
cargo mutants --package rimap-content --jobs 1 --leak-dirs \
  2>&1 | tee /tmp/issue-235/repro-temp-copy.log

# If the bug fires, the leaked tempdir survives for inspection:
LEAKED=$(rg -o 'cargo-mutants-rusty-imap-mcp-[A-Za-z0-9]+\.tmp' \
  /tmp/issue-235/repro-temp-copy.log | head -1)
ls -la "/tmp/$LEAKED/crates/rimap-content/src/parse/"
diff <(ls crates/rimap-content/src/parse/) \
     <(ls "/tmp/$LEAKED/crates/rimap-content/src/parse/")
```

The diff identifies which files the worker is missing. Attach this to
any upstream report.

## Troubleshooting

- **`Worker thread failed: ... is not a file` on a clean run.** You
  forgot `--in-place` (or used bare `cargo mutants` instead of `just
  mutants`). Re-run via the recipe.
- **Mutated file left after Ctrl-C.** `git status` will show the
  mutated file as modified. `git restore <file>` to recover.
- **`error: cannot run --in-place with --jobs N` for N > 1.** Drop
  the `--jobs` flag; in-place mode is single-threaded by design.
- **Run takes too long.** Scope to a single package
  (`--package <crate>`) or a single regex (`-F '<regex>'`). The
  workspace survey is intentionally a quarterly cadence, not a
  per-PR check.

## When the upstream fix lands

Cleanup checklist (do all in one PR, close [#235](https://github.com/randomparity/rusty-imap-mcp/issues/235)):

1. Bump cargo-mutants in any pinned tooling and confirm the bare
   `cargo mutants --package rimap-content` command runs to completion.
2. Drop `--in-place` from the `mutants` recipe in `justfile` (or
   delete the recipe and document the bare command if no other
   wrapping is needed).
3. Remove the `#611` workaround comment block from
   `.cargo/mutants.toml`. Decide whether the remaining
   `minimum_test_timeout` / `timeout_multiplier` entries are still
   load-bearing; delete the file if not.
4. Strike the "Known issue" subsection from
   `docs/security/fuzzing-coverage.md`.
5. Delete this runbook.
6. Comment on [#235](https://github.com/randomparity/rusty-imap-mcp/issues/235)
   with the upstream fix release tag, then close.
