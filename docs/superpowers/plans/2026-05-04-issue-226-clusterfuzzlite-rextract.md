# Issue #226 — Re-extract ClusterFuzzLite Fuzz Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-apply on `main` the cargo-fuzz workspace member, the four B1 fuzz harnesses (`content_mime`, `content_html`, `content_rfc2047`, `content_charset`), the ClusterFuzzLite PR-smoke + nightly workflow with project config, and the `prek` / `typos` exclusions for `fuzz/corpus/`. End state: `cargo +nightly fuzz list` enumerates all four targets, ClusterFuzzLite PR-smoke runs successfully on at least one PR, all eight required CI checks remain green, and `prek run` is clean.

**Architecture:** Cherry-pick from `archive/daemon-experiment` for the fuzz-only commits whose context still applies to `main`, with three categories of deviation handled inline:

1. **Prerequisite re-exports not in the issue's commit list** — three archive-only commits (`b3c08c9`, `0e6c610`, `f8d810b`) are required for the harnesses to compile but were rolled back along with the daemon work. They are added to the cherry-pick order at the points they originally landed.

2. **Adapt to main's preserved naming.** Archive renamed `html::process` → `html::sanitize_html` in `7c15a75` (a `desloppify` pass that was *not* re-extracted to main — see PR #232's coexisting tree on main, where `process` is still the function name). The fuzz harness `content_html.rs` calls `rimap_content::testutil::sanitize_html`. Two minimal adaptations:
   - When applying `0e6c610`, bump `pub(crate) fn process` → `pub fn process` (instead of renaming) and re-export it through `testutil` as `pub use crate::html::process as sanitize_html;`. The harness keeps its archive shape; the alias contract lives in `testutil.rs` only.
   - Skip cherry-picking `7c15a75` entirely (the rename is intentionally not re-extracted on main; coexists with the issue #225 plan's parallel decision).

3. **Drop the html/mismatch.rs portion of `c96b3c1`.** `c96b3c1` does three things: (a) replace `floor_char_boundary` with `truncate_graphemes` in `mismatch.rs`, (b) extract `collect_anchor_text` helper, (c) re-export `find_header_end` through `testutil` and consume it from the `content_rfc2047` harness. Parts (a) and (b) are made obsolete on main by the grapheme-truncation re-extract that already landed (`b2fcd17`, `3022b03`, `eacdb74`) and by issue #224. Only the `find_header_end` re-export + the harness's switch to it (part c) survives the cherry-pick. Apply via fresh-edit, not cherry-pick.

No production-code logic changes (only visibility bumps on `html::process` and `parse::mime_scrub::{scrub_header_smuggling, find_header_end}`). No new workspace members (the `fuzz/` crate is `[workspace]` standalone — excluded from the workspace build because `libfuzzer-sys` is nightly-only). No new workspace dependencies. No changes to required CI checks; the new `Fuzz` workflow is *not* in the required list, matching archive history.

**Tech Stack:** Rust 2024 (workspace), nightly toolchain (fuzz only), `cargo-fuzz`, `libfuzzer-sys` 0.4, ClusterFuzzLite v1, Ubuntu 24.04 runners.

**Source issue:** [#226](https://github.com/randomparity/rusty-imap-mcp/issues/226) (Phase-2 re-extract, sub-issue of meta #229).

**Original work preserved on `archive/daemon-experiment`:**
- Original issue: [#202](https://github.com/randomparity/rusty-imap-mcp/issues/202) (closed by PR #203, merged at archive SHA `3dfff1a`).
- No single umbrella PR for the harness scaffolding — landed as a sequence of `test(fuzz):` and `ci(fuzz):` commits.

## Source commits (chronological, with re-extract disposition)

| Archive SHA | Disposition | Subject |
|---|---|---|
| `7c15a75` | **skip** | `desloppify: rename html::process to html::sanitize_html` (main keeps `process`; alias handled in testutil instead) |
| `abe0026` | cherry-pick | `test(fuzz): scaffold cargo-fuzz workspace member` |
| `fcdfcbb` | cherry-pick | `test(fuzz): drop speculative deps and tighten placeholder comment` |
| `0e6c610` | cherry-pick + edit | `test(rimap-content): expose sanitize_html and scrub_header_smuggling under test-util` (re-export `process as sanitize_html`, not the renamed `sanitize_html`; bump `process` to `pub`) |
| `f8d810b` | cherry-pick + edit | `test(rimap-content): document why pub items behind test-util are pub` (rationale comments still apply; mention `process` rather than `sanitize_html`) |
| `b3c08c9` | cherry-pick | `chore(prek): exclude fuzz/corpus/ from CRLF and typos hooks` |
| `36af0d4` | cherry-pick | `test(fuzz): add content_mime harness for parse_message` |
| `c9c9a47` | cherry-pick | `chore(fuzz): ignore libfuzzer-generated mutation files in corpus/` |
| `a730ba5` | cherry-pick | `fix(fuzz): restore CRLF in injection-corpus seeds; precise mutation ignore` |
| `3fd35d1` | cherry-pick | `test(fuzz): add content_html harness for sanitize_html` |
| `112d06a` | cherry-pick | `test(fuzz): add content_rfc2047 harness for header smuggling scrubber` |
| `177eb6f` | cherry-pick | `test(fuzz): add content_charset harness for unicode::decode` |
| `c96b3c1` | **fresh-apply (subset)** | `refactor(rimap-content): consolidate utf-8 truncation and header-boundary detection` (only the `find_header_end` `testutil` re-export + harness conversion; `mismatch.rs` portion already on main via #224) |
| `26f1935` | cherry-pick | `ci(fuzz): add ClusterFuzzLite workflow for PR smoke + nightly` |
| `b2f7be1` | cherry-pick | `ci(fuzz): trigger pr-smoke on workspace Cargo.toml/Cargo.lock changes` |
| `19a5679` | cherry-pick | `ci(fuzz): add ClusterFuzzLite project config (Dockerfile, build.sh, project.yaml)` |
| `d251296` | cherry-pick | `ci(fuzz): harden build.sh portability and add .dockerignore` |
| `a144148` | cherry-pick | `ci(fuzz): grant actions: read so ClusterFuzzLite can fetch artifacts` |

Total: **17** commits applied (16 cherry-picks + 1 fresh-apply); **1** commit skipped.

## Pre-extraction state on `main`

Verified at HEAD `1f223b3`:

- No `fuzz/` directory (working tree is clean — the issue's note about untracked files on disk is stale).
- No `.clusterfuzzlite/` directory.
- No `.dockerignore`.
- `.github/workflows/` has only `ci.yml` and `release.yml`.
- `crates/rimap-content/src/html/mod.rs:119` has `pub(crate) fn process(...)` — the archive rename to `sanitize_html` is *not* present.
- `crates/rimap-content/src/parse/mime_scrub.rs:16` has `pub(super) fn scrub_header_smuggling(...)` and `:146` has `pub(super) fn find_header_end(...)`.
- `crates/rimap-content/src/testutil.rs` exports only `warning_code_label` and `error_kind_label` — no fuzz-supporting re-exports.
- `crates/rimap-content/src/unicode.rs:49` already has `pub fn decode(...)` (no visibility change required for the `content_charset` harness).
- `crates/rimap-content/src/lib.rs:24` already exports `SecurityWarning` (no change required for `content_rfc2047`).
- `.pre-commit-config.yaml` has the `tests/injection-corpus/` exclusion family but no `fuzz/corpus/` exclusion.
- `typos.toml` has the `tests/injection-corpus/` exclusion but no `fuzz/corpus/` exclusion.
- `justfile` has no `fuzz` recipe (cherry-pick of `abe0026` adds `just fuzz <target>` and `just fuzz-list`).
- Action SHAs in archive's `fuzz.yml` (`actions/checkout@de0fac2…` v6.0.2, `google/clusterfuzzlite/actions/build_fuzzers@884713a6…` v1) match the current pinning convention used in `.github/workflows/ci.yml`. No SHA refresh required at extraction time; verify on the day of the cherry-pick in case Dependabot has bumped checkout.

## Implementation tasks

### Task 1 — Branch setup
- [ ] Create branch `phase2/issue-226-clusterfuzzlite` from `main` at `1f223b3`.
- [ ] Verify `git fetch origin archive/daemon-experiment` succeeds (the branch exists on origin).

### Task 2 — Cherry-pick scaffold (`abe0026`)
- [ ] `git cherry-pick abe0026` (touches `Cargo.toml`, `fuzz/Cargo.toml`, `fuzz/.gitignore`, `fuzz/fuzz_targets/.gitkeep`, `fuzz/src/lib.rs`, `justfile`).
- [ ] Verify `cargo metadata --format-version 1 -q` is unchanged (fuzz crate is `[workspace]` standalone). The top-level `Cargo.toml` change is purely a comment / non-workspace line.
- [ ] Verify `just fuzz-list` runs (will print "no targets yet" — that's expected until Task 7).

### Task 3 — Cherry-pick speculative-deps tightening (`fcdfcbb`)
- [ ] `git cherry-pick fcdfcbb`.
- [ ] Verify `fuzz/Cargo.toml` no longer declares `rimap-audit` / `rimap-server` path deps.

### Task 4 — Cherry-pick + edit testutil re-exports (`0e6c610`)
- [ ] `git cherry-pick 0e6c610`. **Expected conflicts:**
   - `crates/rimap-content/src/html/mod.rs`: archive renames `process` → `sanitize_html` and bumps to `pub`. Resolve by keeping `process` (main's name) and bumping its visibility from `pub(crate)` to `pub` only. The function body and call sites in `parse/bodies.rs` are unchanged.
   - `crates/rimap-content/src/testutil.rs`: archive adds `pub use crate::html::sanitize_html;`. Resolve to `pub use crate::html::process as sanitize_html;` so the harness keeps its archive-form import.
   - `crates/rimap-content/src/parse/mime_scrub.rs`: archive bumps `pub(super) fn scrub_header_smuggling` to `pub fn`. Apply identically.
   - `crates/rimap-content/src/parse/mod.rs`: archive's one-line visibility tweak applies cleanly.
- [ ] Confirm the testutil.rs additions land:
   - `pub use crate::html::process as sanitize_html;`
   - `pub use crate::html::HtmlResult;`
   - `pub use crate::parse::mime_scrub::scrub_header_smuggling;`
- [ ] `cargo build -p rimap-content --all-features` clean (no clippy run yet).

### Task 5 — Cherry-pick rationale comments (`f8d810b`)
- [ ] `git cherry-pick f8d810b`. **Expected conflict:** `html/mod.rs` doc-comment text on `pub fn sanitize_html` references the archive name. Resolve by keeping the comment but referencing `process` instead of `sanitize_html` where the function name appears.
- [ ] `cargo build -p rimap-content --all-features` clean.

### Task 6 — Cherry-pick prek/typos exclusions (`b3c08c9`)
- [ ] `git cherry-pick b3c08c9`. Touches `.pre-commit-config.yaml` and `typos.toml`. No expected conflicts.
- [ ] `prek run --all-files` clean.

### Task 7 — Cherry-pick `content_mime` harness (`36af0d4`)
- [ ] `git cherry-pick 36af0d4`. Touches `fuzz/Cargo.toml` (adds `[[bin]]` for `content_mime`), `fuzz/corpus/content_mime/*.eml` (28 seeds), `fuzz/fuzz_targets/content_mime.rs`, removes `fuzz/fuzz_targets/.gitkeep`.
- [ ] Verify `cargo +nightly fuzz list` (run from `fuzz/`) prints `content_mime`.
- [ ] **Do not** run `just fuzz content_mime` yet — corpus is still LF-broken until Task 9 (`a730ba5`) restores CRLF.

### Task 8 — Cherry-pick mutation-file gitignore (`c9c9a47`)
- [ ] `git cherry-pick c9c9a47`. Touches `fuzz/.gitignore` only.

### Task 9 — Cherry-pick CRLF restore + precise mutation ignore (`a730ba5`)
- [ ] `git cherry-pick a730ba5`. Touches `fuzz/.gitignore` and 24 corpus `.eml` files (CRLF line-ending restoration). The prek mixed-line-ending hook stays out of the way thanks to Task 6's exclusion.
- [ ] Verify byte-equality between `fuzz/corpus/content_mime/rfc2047-crlf-smuggling.eml` and `tests/injection-corpus/rfc2047-crlf-smuggling.eml` with `cmp`. If non-equal, the prek hook re-mangled the seed during a hook run between Tasks 7 and 9 — re-copy from `tests/injection-corpus/`.
- [ ] **Smoke test:** `just fuzz content_mime` for ~10 seconds (Ctrl-C). Expect ASAN-clean execution, no crashes on the seed corpus.

### Task 10 — Cherry-pick `content_html` harness (`3fd35d1`)
- [ ] `git cherry-pick 3fd35d1`. Touches `fuzz/Cargo.toml`, `fuzz/corpus/content_html/*.html` (21 seeds), `fuzz/fuzz_targets/content_html.rs`.
- [ ] Verify `cargo +nightly fuzz list` includes `content_html`.

### Task 11 — Cherry-pick `content_rfc2047` harness (`112d06a`)
- [ ] `git cherry-pick 112d06a`. Touches `fuzz/Cargo.toml`, `fuzz/corpus/content_rfc2047/*.eml` (7 seeds), `fuzz/fuzz_targets/content_rfc2047.rs`.
- [ ] Verify `cargo +nightly fuzz list` includes `content_rfc2047`.
- [ ] Note: harness still uses the inline windows-based header-end scan at this point. Task 13 swaps it for `find_header_end`.

### Task 12 — Cherry-pick `content_charset` harness (`177eb6f`)
- [ ] `git cherry-pick 177eb6f`. Touches `fuzz/Cargo.toml`, `fuzz/corpus/content_charset/*` (no-extension files), `fuzz/fuzz_targets/content_charset.rs`.
- [ ] Verify `cargo +nightly fuzz list` includes `content_charset`. All four targets present.
- [ ] Verify the human-curated seeds with bare names (no extension) are tracked by git (the `c9c9a47` SHA1-shape mutation ignore in Task 8 leaves them alone).

### Task 13 — Fresh-apply `find_header_end` re-export + harness adoption (subset of `c96b3c1`)
- [ ] **Do not** `git cherry-pick c96b3c1` — the `mismatch.rs` portion will conflict trivially with already-landed grapheme-truncation work (#224) and the helper extraction is not needed (the duplication it solves does not exist on main after the re-extract).
- [ ] In `crates/rimap-content/src/parse/mime_scrub.rs`: bump `find_header_end` from `pub(super)` to `pub` (matching the `scrub_header_smuggling` visibility bump from Task 4).
- [ ] In `crates/rimap-content/src/testutil.rs`: add `pub use crate::parse::mime_scrub::find_header_end;` with the same docstring shape as the existing re-exports.
- [ ] In `fuzz/fuzz_targets/content_rfc2047.rs`: replace the inline `windows(4) / windows(2)` header-end scan with a call to `rimap_content::testutil::find_header_end`. Note the offset semantics — `find_header_end` returns `(end, sep_len)` where `end` excludes the blank line (returns `pos + 2` for LF-LF, `pos + 4` for CRLF-CRLF semantics depending on which separator). Read the function on main to confirm exact return shape before rewriting; the archive's commit message notes the prior harness was off by 2 bytes (`pos + 4` vs. `pos + 2`).
- [ ] Single commit message: `refactor(rimap-content): expose find_header_end via test-util for fuzz harness` with `Refs: #226`.
- [ ] `cargo build -p rimap-content --all-features` and `cd fuzz && cargo +nightly fuzz build content_rfc2047` clean.

### Task 14 — Cherry-pick fuzz workflow (`26f1935`)
- [ ] `git cherry-pick 26f1935`. Touches `.github/workflows/fuzz.yml` only.
- [ ] `actionlint .github/workflows/fuzz.yml` clean.
- [ ] `zizmor .github/workflows/fuzz.yml` clean (or document any informational findings).

### Task 15 — Cherry-pick workspace-trigger paths (`b2f7be1`)
- [ ] `git cherry-pick b2f7be1`. Touches `.github/workflows/fuzz.yml`.

### Task 16 — Cherry-pick ClusterFuzzLite project config (`19a5679`)
- [ ] `git cherry-pick 19a5679`. Touches `.clusterfuzzlite/Dockerfile`, `.clusterfuzzlite/build.sh`, `.clusterfuzzlite/project.yaml`.
- [ ] `shellcheck .clusterfuzzlite/build.sh` and `shfmt -d .clusterfuzzlite/build.sh` clean.

### Task 17 — Cherry-pick build.sh portability + .dockerignore (`d251296`)
- [ ] `git cherry-pick d251296`. Touches `.clusterfuzzlite/build.sh`, `.dockerignore`, `.github/workflows/fuzz.yml`.
- [ ] `shellcheck` and `shfmt` re-verified clean on the updated `build.sh`.

### Task 18 — Cherry-pick `actions: read` permission (`a144148`)
- [ ] `git cherry-pick a144148`. Touches `.github/workflows/fuzz.yml` only — adds `actions: read` to the workflow `permissions:` block.

### Task 19 — Local validation
- [ ] `just check` clean.
- [ ] `just fmt-check` clean.
- [ ] `just lint` clean (no warnings from the bumped visibilities or new public items).
- [ ] `just test` (workspace baseline) — count unchanged from `1f223b3` baseline (no test additions, no test deletions).
- [ ] `just deny` clean (no new top-level deps).
- [ ] `prek run --all-files` clean. Verify the mixed-line-ending hook does not modify any `fuzz/corpus/` file.
- [ ] `cd fuzz && cargo +nightly fuzz build` — all four targets compile.
- [ ] Optional: `just fuzz content_mime` for 60s on the seed corpus, expect no crashes.

### Task 20 — PR + CI validation
- [ ] Push branch, open PR titled `phase2: re-extract ClusterFuzzLite fuzz infrastructure (#202, #226)`.
- [ ] PR body lists the closes/refs links: `Closes #226. Refs #202, #229.`
- [ ] Wait for all 8 required checks to pass (`rustfmt`, `clippy`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`, plus the two macOS jobs).
- [ ] Confirm the new `Fuzz / pr-smoke (content_mime)` and `Fuzz / pr-smoke (content_html)` jobs both trigger and pass on this PR (the workflow is touched by the PR, satisfying its own path filter). These are *not* required checks; they must succeed for acceptance but their failure does not block merge per branch-protection config.
- [ ] Do not mark the new fuzz checks required — that decision is out of scope for #226 and would need a follow-up branch-protection change.

## Acceptance criteria (from issue #226)

- [ ] `fuzz/` directory present with all 4 harnesses (`content_mime`, `content_html`, `content_rfc2047`, `content_charset`).
- [ ] `.github/workflows/fuzz.yml` present and runs successfully on at least one PR-smoke trigger.
- [ ] `actions: read` permission set on the workflow.
- [ ] CI green on all 8 required checks.

## Risks & open questions

- **CRLF mangling during cherry-picks.** The prek mixed-line-ending hook is configured to auto-fix CRLF → LF on commit. Task 6 lands the `fuzz/corpus/` exclusion *before* the harness corpus seeds arrive (Task 7+). If the cherry-pick order is rearranged, prek will silently re-corrupt the corpus mid-extract. The order in this plan is load-bearing — don't reorder Tasks 6–9.
- **Rust nightly toolchain assumption.** `libfuzzer-sys` and `cargo-fuzz` require nightly. The fuzz crate's `rust-version = "1.94.0"` in archive's `fuzz/Cargo.toml` is a documentation marker only (nightly is a separate axis from MSRV). If the local nightly is too old to build, `rustup install nightly` resolves it; CI uses ClusterFuzzLite's pinned toolchain inside the `base-builder-rust` image and is independent.
- **ClusterFuzzLite REST API access.** `actions: read` grants the `run_fuzzers` action permission to fetch prior-run artifacts. If the archive's pinned ClusterFuzzLite SHA (`884713a6c30a92e5e8544c39945cd7cb630abcd1`) has been rotated by upstream since archive was written, the workflow will fail at action resolution. Verify the SHA still resolves on `google/clusterfuzzlite` at extraction time; if not, refresh to the current `v1` tag SHA and document in the cherry-pick conflict notes.
- **`find_header_end` return-shape drift.** The `c96b3c1` archive commit was authored when `find_header_end` returned a single offset; main has the function returning `Option<(usize, usize)>` (offset + separator length). Task 13's harness rewrite must consume the tuple, not the bare offset. Read `crates/rimap-content/src/parse/mime_scrub.rs:146` on main before writing the harness call, *not* on archive.
- **`mismatch.rs` no longer compiles in the cherry-pick context.** Confirmed pre-extract that `floor_char_boundary` is gone from `html/mismatch.rs` on main (replaced via `b2fcd17` / `eacdb74`). The `c96b3c1` skip rationale stands. If a future grapheme-related re-extract reintroduces `floor_char_boundary`, Task 13 needs to grow the `mismatch.rs` portion back in.
- **Workflow not in required check list.** Per the issue's acceptance criteria, the fuzz workflow's failure does not gate merge. This is intentional for the initial extraction. A follow-up issue can promote `pr-smoke (content_mime)` and `pr-smoke (content_html)` to required after a stable run history accumulates. Not in scope for #226.
- **No new dependencies.** Verified — the only added `Cargo.toml` is `fuzz/Cargo.toml`, which depends on `libfuzzer-sys = "0.4"` (in a standalone workspace) and `rimap-content` via path. `cargo deny` does not see the fuzz crate (it's outside the workspace).

## Out of scope

- Promoting fuzz workflow checks to required.
- Adding harnesses for crates beyond `rimap-content` (`rimap-imap`, `rimap-server`).
- Cross-corpus mutation testing.
- The `cbea1a4` revert of issue #201 corpus seed and the `e08ce10` upstream notes — those belong to a separate post-archive cleanup, not to fuzz infrastructure.
- The `7c15a75` `process → sanitize_html` rename — main's preserved naming stands.

## Reference

- Rollback narrative: `docs/superpowers/specs/2026-05-02-multi-client-stdio-design.md` §12.
- Original test-strategy spec: `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md` (Sprint B1).
- Companion phase-2 plans: issue #225 (mutation-cleanup waves), issue #224 (truncate-graphemes).
- Phase-2 meta: issue #229.
