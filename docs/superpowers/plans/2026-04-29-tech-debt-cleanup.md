# Tech Debt Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the five P1/P2 findings from the 2026-04-29 tech-debt audit: a phantom Cargo feature that breaks `just test-integration`, a pre-commit/CI clippy flag drift, stale "Sprint 1 / future" hedges in AGENTS.md, a typo'd `.gitignore` line, and a four-way version duplication of `cargo-auditable` in release CI.

**Architecture:** Five independent, surgical changes. Each is a single-file (or near-single-file) edit, each is its own commit, none depends on the others. P3 finding #6 (`imap_login` 127-line refactor) is intentionally **not** in this plan — per the audit's own recommendation it is "background polish, when touching the file" and should be filed as a follow-up issue if pursued.

**Tech Stack:** Rust workspace, `just` recipes, prek (pre-commit-in-Rust), GitHub Actions, `cross` for cross-compilation.

---

## Pre-flight

Confirm the working branch isn't `main` and the worktree is clean before starting.

- [ ] **Step 0: Verify branch and clean state**

Run:
```bash
git branch --show-current
git status --short
```

Expected: branch starts with `claude/` or some feature prefix (NOT `main`). `git status --short` empty (no untracked or modified files).

If on `main`, stop and create a feature branch first.

---

## Task 1: Fix phantom `proton-bridge-tests` feature in `just test-integration`

**Why:** `justfile:196` invokes `cargo nextest run --workspace --locked --features proton-bridge-tests`, but no such Cargo feature is defined anywhere in the workspace. The Proton tests gate on the `PROTON_BRIDGE_TEST=1` env var (see `crates/rimap-imap/tests/integration/proton.rs:40`). The recipe has been broken since the proton harness landed; AGENTS.md still tells operators to run it.

**Files:**
- Modify: `justfile:188-196`

- [ ] **Step 1: Reproduce the failure**

Run:
```bash
PROTON_BRIDGE_TEST=1 cargo nextest run --workspace --locked --features proton-bridge-tests --no-run
```

Expected: cargo errors with `error: none of the selected packages contains this feature: proton-bridge-tests` and exits non-zero.

Record this so the post-fix run can be compared.

- [ ] **Step 2: Replace the recipe body to scope the run to the proton test binary**

Edit `justfile`. Find:

```
# Proton Bridge integration suite (gated on PROTON_BRIDGE_TEST=1).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${PROTON_BRIDGE_TEST:-0}" != "1" ]; then
        echo "set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests"
        exit 1
    fi
    cargo nextest run --workspace --locked --features proton-bridge-tests
```

Replace the final `cargo nextest run` line with a scoped invocation that matches the convention already documented in `crates/rimap-imap/tests/integration/proton/README.md` and the spec at `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md:233`:

```
# Proton Bridge integration suite (gated on PROTON_BRIDGE_TEST=1).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${PROTON_BRIDGE_TEST:-0}" != "1" ]; then
        echo "set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests"
        exit 1
    fi
    cargo nextest run -p rimap-imap --locked --test proton
```

- [ ] **Step 3: Verify the recipe parses and dispatches correctly**

Run:
```bash
just --evaluate test-integration 2>&1 | head -5
PROTON_BRIDGE_TEST=1 cargo nextest run -p rimap-imap --locked --test proton --no-run
```

Expected: `--no-run` build succeeds (compiles the test binary; does not run it). No `feature not found` error. The Proton tests themselves require live Bridge env vars to actually run — `--no-run` only verifies the dispatch path is sound.

- [ ] **Step 4: Verify the gating still works**

Run:
```bash
just test-integration
```

Expected: prints `set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests` and exits 1 (the env-var guard is unchanged).

- [ ] **Step 5: Commit**

```bash
git add justfile
git commit -m "fix(justfile): scope test-integration to proton test, drop phantom feature

The 'proton-bridge-tests' Cargo feature does not exist in any workspace
member. The recipe failed with 'none of the selected packages contains
this feature' for any operator who tried to run it. Scope nextest to
'-p rimap-imap --test proton' to match the convention in the proton
README and the v1 spec."
```

---

## Task 2: Align pre-commit clippy flags with CI

**Why:** AGENTS.md asserts "If `just ci` passes locally, CI will pass." The pre-commit hook at `.pre-commit-config.yaml:53` runs `cargo clippy --workspace --all-targets --locked -- -D warnings` — it is missing the `--all-features` flag that CI (`.github/workflows/ci.yml:49`) and `just lint` both pass. A feature-gated clippy warning can pass `prek run` and fail CI on push, defeating the local-vs-CI lockstep guarantee.

**Files:**
- Modify: `.pre-commit-config.yaml:53`

- [ ] **Step 1: Confirm the divergence**

Run:
```bash
grep -E "cargo clippy|cargo-clippy" .pre-commit-config.yaml .github/workflows/ci.yml justfile
```

Expected output should show ci.yml and justfile invoking with `--all-features`, and `.pre-commit-config.yaml` invoking without it. If they already match, this task is already done — skip to Task 3.

- [ ] **Step 2: Apply the fix**

Edit `.pre-commit-config.yaml`. Find:

```
      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --all-targets --locked -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]
```

Change the `entry:` line to:

```
        entry: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

- [ ] **Step 3: Verify the hook executes the new command**

Run:
```bash
prek run cargo-clippy --all-files
```

Expected: hook runs and exits 0. The full clippy pass takes longer than the previous flag-less run; that is the intended cost.

- [ ] **Step 4: Verify CI parity**

Run:
```bash
diff <(grep -E '^\s+entry: cargo clippy' .pre-commit-config.yaml | sed 's/.*entry: //') \
     <(grep -E '^\s+- run: cargo clippy' .github/workflows/ci.yml | sed 's/.*- run: //')
```

Expected: empty diff (the two clippy invocations are now identical).

- [ ] **Step 5: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "chore(prek): align pre-commit clippy with CI flags

Add --all-features so prek run matches '.github/workflows/ci.yml' and
'just lint'. Without this, a feature-gated clippy warning can pass the
local hook and fail CI, breaking AGENTS.md's 'just ci passes locally,
CI will pass' guarantee."
```

---

## Task 3: Drop stale Sprint 1 / "future" hedges from AGENTS.md

**Why:** AGENTS.md was written before Sprint 1 landed and still talks about `tracing`, `thiserror`, `anyhow`, `test-injection`, and `test-integration` as future work. All five have shipped:

- `tracing` is used in 25 source files.
- `thiserror` is in every library crate's `Cargo.toml`; `anyhow` is in `rimap-server`.
- `tests/injection-corpus/` has 13 fixtures and `crates/rimap-content/tests/injection_corpus.rs` runs them.
- `crates/rimap-imap/tests/integration/proton.rs` exists and works (after Task 1).

The hedges mislead new contributors and contradict the actual code state.

**Files:**
- Modify: `AGENTS.md:53`, `AGENTS.md:54`, `AGENTS.md:114-117`, `AGENTS.md:125-126`, `AGENTS.md:139`

- [ ] **Step 1: Edit lines 53-54 (just-target descriptions)**

In `AGENTS.md`, find:

```
just test-injection  # adversarial email corpus (content pipeline, future)
just test-integration  # Proton Bridge integration tests (gated, future)
```

Replace with:

```
just test-injection  # adversarial email corpus (content pipeline)
just test-integration  # Proton Bridge integration tests (gated on PROTON_BRIDGE_TEST=1)
```

- [ ] **Step 2: Edit lines 114-117 (tracing hedge)**

In `AGENTS.md`, find:

```
- **No `println!` / `eprintln!` / `dbg!` / `todo!` in non-test source.**
  `print_stdout` and `print_stderr` are denied workspace-wide because stdout is
  reserved for MCP transport (stderr is held in reserve for a future `tracing`
  subscriber). In tests, debug output via these macros is allowed. In `main.rs`
  and library code, use `tracing` (coming in Sprint 1) or `writeln!` on a
  captured handle.
```

Replace with:

```
- **No `println!` / `eprintln!` / `dbg!` / `todo!` in non-test source.**
  `print_stdout` and `print_stderr` are denied workspace-wide because stdout is
  reserved for MCP transport; stderr is owned by the `tracing` subscriber
  installed at boot. In tests, debug output via these macros is allowed. In
  `main.rs` and library code, use `tracing` or `writeln!` on a captured handle.
```

- [ ] **Step 3: Edit lines 125-126 (thiserror/anyhow hedge)**

In `AGENTS.md`, find:

```
- **`thiserror` for library crates, `anyhow` for `rimap-server`** (when those
  dependencies land in Sprint 1).
```

Replace with:

```
- **`thiserror` for library crates, `anyhow` for `rimap-server`.**
```

- [ ] **Step 4: Edit line 139 (Sprint 1 testing-expectations heading)**

In `AGENTS.md`, find:

```
## Testing expectations (starting Sprint 1)
```

Replace with:

```
## Testing expectations
```

- [ ] **Step 5: Verify no Sprint-1 hedges remain**

Run:
```bash
grep -n "Sprint 1\|coming in Sprint\|landing in Sprint\|future \`tracing\`" AGENTS.md
```

Expected: no matches in coding-standards or testing-expectations sections. The only Sprint references that should remain are `Sprint-by-sprint implementation plans live in...` (line 27) and `is *already covered* by an upcoming sprint's spec scope` (line 222) — both of those are still accurate forward-looking process language.

- [ ] **Step 6: Verify the markdown still renders**

Run:
```bash
head -150 AGENTS.md | tail -50
```

Expected: the edited section reads cleanly with no broken bullets or stray punctuation.

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md
git commit -m "docs: drop stale Sprint 1 hedges from AGENTS.md

tracing, thiserror, anyhow, test-injection, and test-integration all
shipped. Remove '(future)', '(coming in Sprint 1)', '(when those
dependencies land in Sprint 1)', and the 'starting Sprint 1' section
heading so the doc matches code state."
```

---

## Task 4: Remove typo'd `docs/superpoweres/plans/` line from `.gitignore`

**Why:** `.gitignore:12` reads `docs/superpoweres/plans/` (note: "superpoweres" — extra "e"). The real directory is `docs/superpowers/plans/` and is tracked. The typo'd line was added in commit `af1c55a` two weeks ago and has never matched anything on disk. It is dead config.

**Files:**
- Modify: `.gitignore:12`

- [ ] **Step 1: Confirm the typo'd path does not exist on disk and the correct one is tracked**

Run:
```bash
test -e docs/superpoweres && echo "TYPO PATH EXISTS — INVESTIGATE" || echo "typo path does not exist (expected)"
git ls-files docs/superpowers/plans/ | head -3
```

Expected: first line prints `typo path does not exist (expected)`. Second command lists tracked plan files under the correct `docs/superpowers/plans/` path. If the typo path *does* exist on disk, stop and investigate — the original author may have created a directory matching the typo.

- [ ] **Step 2: Remove the dead line**

Edit `.gitignore`. Find:

```
docs/superpoweres/plans/
```

Delete the entire line. Final `.gitignore` should be:

```
/target
/mutants.out/
/mutants.out.old/
**/*.rs.bk
*.pdb
.DS_Store
.idea/
.vscode/
*.swp
.worktrees/
.desloppify/
```

- [ ] **Step 3: Verify nothing newly becomes tracked**

Run:
```bash
git status --short
git check-ignore -v docs/superpowers/plans/* 2>&1 | head -3
```

Expected: `git status --short` shows only `.gitignore` itself as modified (`M .gitignore`). `git check-ignore` either prints nothing or non-`.gitignore` matches — confirming the removed line was the only thing it could have ignored under the correct path was nothing (since the correct directory was already tracked).

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: remove dead .gitignore entry for typo'd path

'docs/superpoweres/plans/' (note: extra 'e') was added in af1c55a but
never matched anything; the real directory is docs/superpowers/plans/
and is tracked. Delete the line."
```

---

## Task 5: Centralize `cargo-auditable` version in the release workflow

**Why:** Version `0.7.4` of `cargo-auditable` is repeated in four places: `Cross.toml:8` and three `cargo install` lines in `.github/workflows/release.yml` (lines 30, 80, 108). Bumping the pin requires four synchronized edits, and a missed one produces a heterogeneous SBOM-tooling matrix across release targets without any visible CI signal. Centralize the three workflow occurrences via a workflow-level `env:` var; leave `Cross.toml` separate (it is consumed by `cross` at runtime and cannot read GHA env interpolation) but add a comment pointing to the workflow var.

**Files:**
- Modify: `.github/workflows/release.yml:9-12` (add env var) and lines 30, 80, 108 (replace literal)
- Modify: `Cross.toml:8` (add a "keep in sync" comment)

- [ ] **Step 1: Add `CARGO_AUDITABLE_VERSION` to the workflow `env:` block**

Edit `.github/workflows/release.yml`. Find:

```
env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0
  BINARY_NAME: rusty-imap-mcp
```

Replace with:

```
env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0
  BINARY_NAME: rusty-imap-mcp
  # cargo-auditable version pinned across all five build targets. Cross.toml
  # mirrors this value because the cross runner cannot read GHA env vars.
  CARGO_AUDITABLE_VERSION: "0.7.4"
```

- [ ] **Step 2: Replace the literal at line 30 (build-linux-x86_64)**

In `.github/workflows/release.yml`, find:

```
      - name: Install cargo-auditable
        run: cargo install cargo-auditable --locked --version 0.7.4
      - run: cargo auditable build --release --locked
```

(this block appears under `build-linux-x86_64`; do NOT change the identical block under `build-macos-aarch64` yet — Step 3 covers it).

Replace the `run:` line with:

```
      - name: Install cargo-auditable
        run: cargo install cargo-auditable --locked --version "${CARGO_AUDITABLE_VERSION}"
        env:
          CARGO_AUDITABLE_VERSION: ${{ env.CARGO_AUDITABLE_VERSION }}
      - run: cargo auditable build --release --locked
```

The `env:` step block is required because `${{ env.X }}` expansion only works in `run:` strings if the var is also exported into the step's environment via `env:`. Using a shell variable expansion (`${CARGO_AUDITABLE_VERSION}`) avoids any ambiguity.

- [ ] **Step 3: Repeat for line 80 (build-macos-aarch64)**

In `.github/workflows/release.yml`, locate the **second** occurrence of:

```
      - name: Install cargo-auditable
        run: cargo install cargo-auditable --locked --version 0.7.4
```

(under `build-macos-aarch64`). Replace with the same pattern as Step 2:

```
      - name: Install cargo-auditable
        run: cargo install cargo-auditable --locked --version "${CARGO_AUDITABLE_VERSION}"
        env:
          CARGO_AUDITABLE_VERSION: ${{ env.CARGO_AUDITABLE_VERSION }}
```

- [ ] **Step 4: Replace the literal in the inline `docker run` for ppc64le and s390x**

In `.github/workflows/release.yml`, find the ppc64le block (around line 108):

```
      - name: Build in ppc64le container
        # rust:1.88.0-bookworm as of 2026-04-13
        run: |
          docker run --rm --platform linux/ppc64le \
            -v "${{ github.workspace }}:/workspace" \
            -w /workspace \
            rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 \
            bash -c "apt-get update && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config && cargo install cargo-auditable --locked --version 0.7.4 && cargo auditable build --release --locked"
```

Replace with:

```
      - name: Build in ppc64le container
        env:
          CARGO_AUDITABLE_VERSION: ${{ env.CARGO_AUDITABLE_VERSION }}
        # rust:1.88.0-bookworm as of 2026-04-13
        run: |
          docker run --rm --platform linux/ppc64le \
            -v "${{ github.workspace }}:/workspace" \
            -w /workspace \
            -e CARGO_AUDITABLE_VERSION \
            rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 \
            bash -c "apt-get update && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config && cargo install cargo-auditable --locked --version \"${CARGO_AUDITABLE_VERSION}\" && cargo auditable build --release --locked"
```

The `-e CARGO_AUDITABLE_VERSION` flag forwards the value into the docker container; without it the inner `bash -c` would see an empty string. The double-quoted shell expansion inside `bash -c` is escaped with `\"…\"` so YAML preserves the quotes.

Repeat the same change for the s390x block immediately below:

```
      - name: Build in s390x container
```

Apply the identical edit pattern (only the `linux/s390x` platform string differs).

- [ ] **Step 5: Add the "keep in sync" comment to `Cross.toml`**

Edit `Cross.toml`. Find:

```
# Cross configuration for the aarch64-unknown-linux-gnu release build.
# Installs cargo-auditable inside the cross container so the release
# binary embeds an SBOM identical to the four other targets. See issue
# #79 and .github/workflows/release.yml.
[target.aarch64-unknown-linux-gnu]
pre-build = [
    "apt-get update && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config",
    "cargo install cargo-auditable --locked --version 0.7.4",
]
```

Replace with:

```
# Cross configuration for the aarch64-unknown-linux-gnu release build.
# Installs cargo-auditable inside the cross container so the release
# binary embeds an SBOM identical to the four other targets. See issue
# #79 and .github/workflows/release.yml.
#
# IMPORTANT: cargo-auditable version below MUST match the
# CARGO_AUDITABLE_VERSION env var in .github/workflows/release.yml.
# The cross runner cannot read GHA env interpolation, so this value
# is duplicated by necessity. Bump both together.
[target.aarch64-unknown-linux-gnu]
pre-build = [
    "apt-get update && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config",
    "cargo install cargo-auditable --locked --version 0.7.4",
]
```

- [ ] **Step 6: Verify all `0.7.4` literals are accounted for**

Run:
```bash
grep -n "0.7.4" .github/workflows/release.yml Cross.toml
```

Expected: exactly **one** match — `Cross.toml:9` (the literal pin under `[target.aarch64-unknown-linux-gnu]`). The three former occurrences in `release.yml` are gone.

- [ ] **Step 7: Verify the workflow still parses with `actionlint`**

Run:
```bash
actionlint .github/workflows/release.yml
```

Expected: no output (success). If `actionlint` is not installed, run `just setup` first.

- [ ] **Step 8: Verify with zizmor**

Run:
```bash
zizmor .github/workflows/release.yml
```

Expected: zero findings, or only the same findings that existed before this change. The `${{ env.X }}` → step `env:` pattern is the zizmor-blessed way to interpolate workflow vars into `run:` strings.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/release.yml Cross.toml
git commit -m "ci(release): centralize cargo-auditable version

Three release.yml call sites used to hardcode 0.7.4; lift to a workflow
env var CARGO_AUDITABLE_VERSION so a bump touches one line. Cross.toml
keeps its own literal because the cross runner cannot read GHA env
interpolation, with a comment that calls out the duplication."
```

---

## Wrap-up

- [ ] **Step 1: Run the full local-CI equivalent**

Run:
```bash
just ci
```

Expected: all checks pass — `fmt-check`, `lint`, `test`, `test-msrv`, `deny`, `typos`. No new failures introduced by Tasks 1-5.

- [ ] **Step 2: Confirm five focused commits**

Run:
```bash
git log --oneline main..HEAD
```

Expected: five new commits on the branch, in order:

1. `fix(justfile): scope test-integration to proton test, drop phantom feature`
2. `chore(prek): align pre-commit clippy with CI flags`
3. `docs: drop stale Sprint 1 hedges from AGENTS.md`
4. `chore: remove dead .gitignore entry for typo'd path`
5. `ci(release): centralize cargo-auditable version`

- [ ] **Step 3: File a follow-up issue for P3 finding #6 (deferred)**

The audit's P3 item — `imap_login` at `crates/rimap-imap/src/connection.rs:375` is 127 lines, exceeding the 100-line/function limit — is intentionally **not** in this plan. Per AGENTS.md "Deferrals become GitHub issues," open one:

```bash
gh issue create \
  --title "rimap-imap: extract helpers from Connection::imap_login (>100 lines)" \
  --body "Audit on 2026-04-29 found that 'crates/rimap-imap/src/connection.rs:375' \
('imap_login') is 127 lines, exceeding the global 100-line/function limit. Suggested \
extraction points: \`read_greeting\`, \`assert_login_enabled\` \
(CAPABILITY+LOGINDISABLED probe), and \`probe_post_login_capabilities\` \
(MOVE/UIDPLUS/LIST-STATUS cache). Behavior-preserving refactor; existing tests \
should cover it. Audit recommended treating this as background polish — touch when \
already in the area." \
  --label "tech-debt"
```

If the `tech-debt` label does not exist yet, drop the `--label` flag or create the label first via `gh label create tech-debt --color BFD4F2`.

- [ ] **Step 4: Open a PR**

```bash
gh pr create --title "tech-debt: address P1+P2 findings from 2026-04-29 audit" --body "$(cat <<'EOF'
## Summary

- Fix phantom `proton-bridge-tests` Cargo feature in `just test-integration`
- Add `--all-features` to pre-commit clippy so it matches CI
- Drop stale "Sprint 1 / future" hedges from AGENTS.md
- Remove typo'd `.gitignore` line that never matched anything
- Centralize `cargo-auditable` version pin in the release workflow

P3 finding (`imap_login` 127-line refactor) is filed as a separate follow-up issue
per the audit's "background polish, when touching the file" recommendation.

## Test plan

- [ ] `just ci` passes locally
- [ ] `PROTON_BRIDGE_TEST=1 cargo nextest run -p rimap-imap --test proton --no-run` builds (no `feature not found`)
- [ ] `prek run cargo-clippy --all-files` passes
- [ ] `actionlint .github/workflows/release.yml` clean
- [ ] `zizmor .github/workflows/release.yml` clean
- [ ] `grep -c "Sprint 1" AGENTS.md` returns 0 in coding-standards section
- [ ] `grep "0.7.4" .github/workflows/release.yml Cross.toml` returns exactly one Cross.toml match
EOF
)"
```

Expected: PR is created and the URL is printed.

---

## Self-review checklist (writer-side, do not skip)

- **Spec coverage:** Items 1-5 from the audit are tasks 1-5; item 6 is explicitly deferred to a tracked issue in Wrap-up Step 3. Pre-flight covers branch hygiene per AGENTS.md "never commit on main."
- **No placeholders:** every code block contains the exact diff; no "TBD" or "similar to above."
- **Type/name consistency:** `CARGO_AUDITABLE_VERSION` is used identically in workflow `env:`, step `env:`, docker `-e`, and `bash -c` shell expansion. Recipe target `test-integration` is unchanged; only its body is rewritten.
- **Frequent commits:** five tasks → five commits, each independently revertable.
- **TDD-shape:** Tasks 1, 2 explicitly reproduce the failure first (acts as the failing test); Tasks 3, 4, 5 are doc/config edits where the verification step (grep / actionlint / zizmor) plays the role of the test.
