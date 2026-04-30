# CI macOS Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #184 by adding a `macos-latest` `cargo check` job to `.github/workflows/ci.yml` so Linux-only API drift (the regression class that produced #180) is caught at PR time instead of slipping to merge.

**Architecture:** One new job, `check-macos`, parallel to the existing `clippy`/`test`/`msrv` jobs. The job runs `cargo check --workspace --locked --all-targets` on `macos-latest` (currently macOS 14 ARM64) with the pinned dev toolchain (1.94.0) and a separate `Swatinem/rust-cache` key so it does not collide with the Linux caches. No `cargo test` step — Dovecot tests intentionally stay Linux-only per #184's "out of scope" section. No `--all-features`, because `--all-features` on macOS adds nothing the existing Linux clippy job doesn't already cover and would only slow the cold cache.

**Why one job rather than a matrix on the existing `clippy`/`test` jobs:**

1. The existing Linux jobs run `apt-get install libdbus-1-dev pkg-config` for the `keyring` Linux backend. macOS uses the Apple Security framework via the workspace's `apple-native` feature on `keyring` (`Cargo.toml:38`) and needs no native-deps step. Inserting a conditional `if: runner.os == 'Linux'` into a matrix bloats the diff and obscures the per-OS contract.
2. A standalone job named `check-macos` is unambiguous in the GitHub branch-protection UI when (the user's call) we promote it to a required check.
3. The release workflow already has `build-macos-aarch64` (`.github/workflows/release.yml:72`) running `cargo auditable build --release --locked` on `macos-latest`, so we already know the workspace builds clean on macos-14 ARM64. This plan ports that signal earlier in the lifecycle (PR time, not tag-push time).

**Why `--all-targets` rather than `-p rimap-core -p rimap-imap -p rimap-audit`:**

Issue #184 lists the three crates as a *minimum* and explicitly leaves the door open ("Optionally extend to the full workspace `cargo check --workspace --locked` if the runner cost is acceptable."). The cold-cache cost of the full workspace is roughly 5-7 minutes; with `Swatinem/rust-cache` the warm-cache cost is ~2-3 minutes — well under the existing `clippy` job's wall time and dwarfed by `SonarQube`. The full-workspace check catches API drift in `rimap-content`, `rimap-authz`, `rimap-smtp`, `rimap-config`, and `rimap-server` — none of which are guaranteed to be Linux-pure forever (e.g., a future `notify`/`fsevents` dependency in `rimap-audit`, a future Apple-keychain-specific path in `rimap-config`). `--all-targets` ensures unit-test and integration-test target compilation is part of the gate, which is what would have caught #180: `crates/rimap-core/src/fs.rs` is `#![cfg(unix)]` and compiles on macOS, but only its `--all-targets` build pulls in the test modules that exercise the `OFlags` API surface.

**Why no `continue-on-error` posture:**

#184 mentions `continue-on-error: true` as a "possible" rollout strategy. We are not using it. Reasoning:

- The release workflow has been building macos-aarch64 for every tag since the project was tagged. The current state of `main` is known-green on macOS (#183 verified this end-to-end). There is no transitional period to absorb.
- A `continue-on-error: true` job is a decorative job: it produces a green check no matter what, so it cannot fail a PR, so it cannot drive the behavior change the issue exists to enforce. We would simply be paying for a runner without buying any signal.
- If the new job turns out to be flaky in practice (e.g., macos-latest runner exhaustion at peak GHA load), we revisit then. Reactive, not speculative.

**What you (the operator) must do separately from this plan:**

After the PR lands, the new `check-macos` job becomes a status check in the repo's required-checks list. Per `AGENTS.md:166-171`, branch protection on `main` is "strict (branch must be up to date)" and the existing required checks are `rustfmt`, `clippy`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`, plus `SonarQube`. Adding `check-macos` to this list is a deliberate policy change that the GitHub UI requires manually. **The plan stops at making the job exist and pass green.** Promoting it to a required check is called out in Wrap-up Step 2 — it is the operator's call to ratify after the first successful run.

**Tech Stack:** GitHub Actions, `actionlint`, `zizmor`, `cargo check`, `Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4` (already pinned in repo).

---

## Pre-flight

Confirm the working branch isn't `main`, the worktree is clean, and the local toolchain matches CI (we are about to edit a workflow file — `actionlint`/`zizmor` need to run cleanly before push).

- [ ] **Step 0: Verify branch, clean state, and tooling**

Run:
```bash
git branch --show-current
git status --short
which actionlint zizmor
```

Expected:
- `git branch --show-current` prints a feature branch (NOT `main`). If on `main`, stop and create one: `git checkout -b ci/issue-184-macos-matrix`.
- `git status --short` is empty.
- `actionlint` and `zizmor` are both on `PATH`. If either is missing, install them per the global `~/.claude/CLAUDE.md` "CLI tools" table (or run `just setup`, which installs the prek-managed copies).

---

## Task 1: Reproduce the gap, then add `check-macos`

**Why:** Issue #184 says: "any future Linux-only API drift (in `rustix`, `libc`, `tokio`, etc.) is invisible until a developer hits it on a Mac." We close that gap by adding a single job. The TDD-shape here is "prove the gap exists before patching it" — the verification leans on the symmetry between the Linux `clippy` job (which today is the only thing exercising `cargo check` semantics on every PR) and the macOS counterpart we are about to add.

**Files:**
- Modify: `.github/workflows/ci.yml` (insert new job after `clippy`, around line 50)

- [ ] **Step 1: Confirm the gap in the current workflow**

Run:
```bash
grep -E "^\s+runs-on:" .github/workflows/ci.yml | sort -u
```

Expected output (single line, repeated):
```
    runs-on: ubuntu-24.04
```

If any other runner is already present, stop — the gap may have been partially filled and this plan needs revision.

- [ ] **Step 2: Insert the `check-macos` job**

Edit `.github/workflows/ci.yml`. Find the `clippy` job that ends at line 49 (`- run: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`) and the blank line before `test:` at line 51.

Insert the following job between `clippy` and `test`:

```yaml
  check-macos:
    name: check (macOS)
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9  # v1 (toolchain: 1.94.0) # zizmor: ignore[superfluous-actions]
        with:
          toolchain: 1.94.0
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4  # v2.9.1
        with:
          key: macos
      - run: cargo check --workspace --locked --all-targets

```

Notes on each line:

- `name: check (macOS)` — the parenthesized OS suffix matches the existing convention (`test (stable)`, `test (MSRV 1.88.0)`).
- `runs-on: macos-latest` — currently macOS 14 ARM64. We accept GitHub's "latest" alias here because the release workflow already uses it for `build-macos-aarch64` and we want the two to stay in lockstep (a future bump from `macos-14` to `macos-15` should hit both jobs simultaneously).
- No `apt-get` / native-deps step — the `keyring` crate's `apple-native` feature has no system-package prereqs.
- `dtolnay/rust-toolchain` action SHA matches the other jobs in this file. The `# v1 (toolchain: 1.94.0) # zizmor: ignore[superfluous-actions]` trailing comment is the same one the other dtolnay invocations use (zizmor flags `dtolnay/rust-toolchain` as superfluous because it is technically replaceable with `rustup toolchain install`; we keep the action because it is what every other job uses).
- `Swatinem/rust-cache` with `key: macos` — separate cache namespace from the implicit Linux default, the `msrv` key, and the `sonarqube` key. Mixing macOS and Linux build artifacts in one cache key is a known footgun.
- `cargo check --workspace --locked --all-targets` — checks every crate including their test/example/bench targets, but does not run anything. Compiles `crates/rimap-core/src/fs.rs` (`#![cfg(unix)]`) under macOS-`cfg`, which is exactly the surface that #180's regression touched.
- No `--all-features` — the existing Linux `clippy` job already exercises every feature flag; on macOS we want fast, baseline coverage. If a feature ever becomes platform-conditional we can add `--all-features` here as a focused follow-up.
- No `RUSTFLAGS: "-D warnings"` override — the workflow-level `env:` block at the top of the file (`RUSTFLAGS: "-D warnings"` at line 18) applies to every job by default. We deliberately inherit it: a warning-emitting build on macOS is a build we want to fail.

- [ ] **Step 3: Verify the workflow parses cleanly**

Run:
```bash
actionlint .github/workflows/ci.yml
```

Expected: no output (success). If `actionlint` reports an indentation problem, double-check that the inserted block matches the existing `clippy` block's indentation (4 spaces for the job name, 6 spaces for `name:`/`runs-on:`, 6 spaces for `steps:`, 8 spaces for `- uses:` and friends).

- [ ] **Step 4: Verify zizmor sees no new findings**

Run:
```bash
zizmor .github/workflows/ci.yml
```

Expected: zero findings, or only the same pre-existing findings the workflow had before this change. The new job uses the same hardening posture as the rest of the file:
- Workflow-level `permissions: contents: read` (line 13-14) inherits.
- `actions/checkout` is pinned to a 40-char SHA with `persist-credentials: false`.
- `dtolnay/rust-toolchain` carries the same `# zizmor: ignore[superfluous-actions]` opt-out the rest of the file uses.

If zizmor flags something new, stop and post the finding before continuing — it most likely indicates a typo in the SHA pin or the `persist-credentials` line.

- [ ] **Step 5: Verify all four pinned actions match the existing repo pins**

Run:
```bash
grep -nE "actions/checkout@|dtolnay/rust-toolchain@|Swatinem/rust-cache@" .github/workflows/ci.yml \
  | awk '{print $NF}' | sort -u
```

Expected: every SHA in the file appears in this consolidated list, and each appears under exactly one form. If `actions/checkout` shows two distinct SHAs, the new block accidentally diverged from the repo's pin and must be corrected. (The matching pins as of 2026-04-29: `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`, `dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9`, `Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4`.)

- [ ] **Step 6: Sanity-check the job locally on Linux**

We cannot run macOS CI from a Linux dev box, but we can confirm the `cargo check --workspace --locked --all-targets` invocation we are about to ask CI to run is itself sound:

```bash
cargo check --workspace --locked --all-targets
```

Expected: clean exit. If this fails on Linux it will also fail on macOS — there is no reason to push a known-broken invocation to CI.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add macOS cargo-check job to catch Linux-only API drift

Closes #184. Adds 'check (macOS)' as a peer of 'clippy', running
'cargo check --workspace --locked --all-targets' on macos-latest with
the pinned 1.94.0 dev toolchain and a dedicated rust-cache key.
Catches the regression class from #180 (rustix OFlags::PATH became
Linux-only) at PR time rather than at developer-on-Mac time.

No 'cargo test' step on macOS: Dovecot integration tests need Docker
compose and intentionally stay Linux-only.

No 'continue-on-error' posture: the release workflow already builds
macos-aarch64 cleanly on every tag, so 'main' is known-green at the
moment this job lands. A decorative-mode job would not buy the signal
the issue exists to provide."
```

---

## Wrap-up

- [ ] **Step 1: Push the branch and verify the new job runs green**

```bash
git push -u origin "$(git branch --show-current)"
gh pr create --title "ci: add macOS cargo-check job (closes #184)" --body "$(cat <<'EOF'
## Summary

Closes #184. Adds `check (macOS)` to `.github/workflows/ci.yml`, running
`cargo check --workspace --locked --all-targets` on `macos-latest` with the
pinned 1.94.0 dev toolchain.

The regression class from #180 (`rustix` `OFlags::PATH` becoming Linux-only)
slipped to merge because CI ran only on `ubuntu-24.04`. This job catches that
class of drift at PR time. No `cargo test` step — Dovecot integration tests
intentionally stay Linux-only (out of scope per #184).

## Test plan

- [ ] `actionlint .github/workflows/ci.yml` clean
- [ ] `zizmor .github/workflows/ci.yml` clean
- [ ] `check (macOS)` job runs to completion on this PR and reports green
- [ ] After merge: operator promotes `check (macOS)` to a required status
      check on the `main` branch protection rule (separate, manual step;
      not part of this PR)
EOF
)"
```

Wait for CI to complete on the PR. The new `check (macOS)` job should appear in the status-checks list and pass.

- [ ] **Step 2: After merge — promote `check (macOS)` to a required status check**

This is a **manual operator action** in the GitHub web UI, not a code change. It is intentionally outside the PR's diff so the policy decision (which checks gate `main`) is auditable separately from the workflow change.

1. Settings → Branches → Branch protection rules → `main` → Edit
2. "Require status checks to pass before merging" → "Status checks that are required"
3. Add `check (macOS)` to the list (alongside `rustfmt`, `clippy`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`, `SonarQube`)
4. Save changes

After this step, `AGENTS.md:166-171`'s required-checks enumeration is technically out of date by one item. That doc-sync is *not* part of this plan — it is a one-line change that should ride with the next AGENTS.md edit, not a standalone PR.

- [ ] **Step 3: Close issue #184**

GitHub will auto-close on merge because the commit message contains `Closes #184`. Confirm the auto-close fired:

```bash
gh issue view 184 --json state -q .state
```

Expected: `CLOSED`. If still `OPEN`, close manually with `gh issue close 184 -c "Landed in <PR-number>; macOS check job is green and operator-promoted to required status."`.

---

## Self-review checklist (writer-side, do not skip)

- **Spec coverage:** the plan implements #184's "Suggested scope" (the optional full-workspace variant), explicitly addresses each "Out of scope" item by *not* doing it, and ratifies the "Why this is a follow-up" framing by keeping the change isolated to one job.
- **No placeholders:** the inserted YAML block is the literal text to paste, with each pinned SHA copied verbatim from the existing workflow.
- **Type/name consistency:** the new job is named `check-macos` (job key) with display `check (macOS)`. Both names are referenced consistently in the commit message, the PR body, and the operator-action step. The cache key is `macos` (lowercase, matches existing convention of `msrv`/`sonarqube`).
- **One commit, one logical change:** a single workflow file edit, a single TDD-shaped task, a single commit. No drive-by edits.
- **Out-of-band actions are flagged, not hidden:** branch-protection promotion is a deliberate operator step, called out in Wrap-up Step 2. Not silently expected of the PR reviewer.
- **TDD-shape:** Step 1 confirms the gap (`grep` shows only `ubuntu-24.04`), Step 2 patches it, Steps 3-6 are the verifications that play the role of "the test now passes."
- **Cost/value tradeoff is documented:** the architecture section explains why we go full-workspace rather than three named crates, and why no `continue-on-error`. A future reviewer reverting either decision will find the rationale here.
