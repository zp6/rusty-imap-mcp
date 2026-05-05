# Issue #228 — Re-extract Deps Bumps + Dependabot/CI Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-apply on `main` the small Phase-2 grab-bag of deps bumps and Dependabot/CI hygiene that was lost in the multi-client-daemon rollback. End state: workspace runs on the post-#171 "safe-five" major bumps plus `fs4 1.x`; the cargo-major-deferral planning doc is preserved at its original path; SonarQube no longer fails on Dependabot PRs; `AGENTS.md` accurately enumerates the seven required CI checks; and the moot items (PR #120 actions group bump, PR #182 daemon-era desloppify) are explicitly closed out rather than mechanically replayed.

**Architecture:** Cherry-pick from `archive/daemon-experiment` where the change still applies cleanly to main (verified via dry-run cherry-pick — all targeted commits auto-merge with no conflicts). Two of the seven listed PRs are recommended as **skip / close as moot** with a documented rationale; one PR (#176) is bundled with the bumps PR (#177) it justifies for review economy. The remaining items land as **four small targeted PRs** rather than seven, in an order that lets the SonarQube Dependabot guard land before any deps bump that might draw a Dependabot follow-up.

No production-logic refactors. No new workspace members. No new top-level dependencies. The five major deps bumps (toml, directories, sha2, strum, linkify) and `fs4 1.x` are all source-compatible after the small test-site adaptations already encoded in the archive commits.

**Tech Stack:** Rust 2024 (workspace), MSRV 1.88.0, `cargo`, `cargo deny`, GitHub Actions, Dependabot.

**Source issue:** [#228](https://github.com/randomparity/rusty-imap-mcp/issues/228) (Phase-2 re-extract, sub-issue of meta #229).

**Original PRs preserved on `archive/daemon-experiment`:**

| Original PR | Subject | Archive merge SHA | Change commit(s) |
|---|---|---|---|
| #176 | docs/plan-cargo-major-deferred | `5c2c7e7` | `14bc97d` |
| #177 | deps/cargo-major-safe-five | `1868be8` | `49caeb1` |
| #178 | deps/fs4-1x | `0e9240a` | `e3a8488` |
| #120 | dependabot/github_actions/actions-minor-patch | `8985f4b` | `c189a6a` |
| #175 | ci/skip-sonarqube-for-dependabot | `9fc43a1` | `6c36901` |
| #182 | desloppify/code-health (cleanup pass) | `54c1cb5` | 9 commits — daemon-era |
| #186 | docs/agents-required-checks-sync | `930b28f` | `6397e3c` |

Cherry-pick the **change commit** column, not the merge SHA — the merge commits on archive are second-parents of `archive/daemon-experiment` and contain only merge resolution.

## Per-PR disposition

| Original PR | Disposition | Notes |
|---|---|---|
| #176 | **cherry-pick** (bundled with #177) | Docs-only artifact at `docs/superpowers/plans/2026-04-29-cargo-major-deferred-from-pr171.md`. Clean apply confirmed. The plan describes the A/B/C split that this issue's #177 + #178 implement; bundling preserves the chronological "plan first, then the bumps it justifies" review story. |
| #177 | **cherry-pick** (with #176) | Five workspace deps bumps: `toml 0.8 → 1`, `directories 5 → 6`, `sha2 0.10 → 0.11`, `strum 0.26 → 0.28`, `linkify 0.10 → 0.11`. Source impact: 3 test sites in `crates/rimap-config/src/model.rs` (toml `ValueDeserializer` API change) and 2 dropped `windows-sys` skip-tree entries in `deny.toml`. Auto-merges cleanly on Cargo.toml/Cargo.lock/model.rs/deny.toml. |
| #178 | **cherry-pick** | `fs4 0.13 → 1.x` migration in `rimap-audit`: `FileExt` import path moves to crate root, `try_lock_exclusive` → `try_lock`, return shape changes to `Result<(), TryLockError>`. The `lock-on-drop` invariant is preserved. Auto-merges cleanly across `Cargo.toml`, `Cargo.lock`, `rimap-audit/src/reader/mod.rs`, `rimap-audit/src/writer/{mod.rs,emit.rs,rotation.rs}`. |
| #120 | **skip — let Dependabot re-emit** | Bumps `taiki-e/install-action` and `EmbarkStudios/cargo-deny-action` minor/patch revisions. The archive PR pinned to SHAs from 2026-04-29; Dependabot is on a weekly cadence and will re-issue the bump against current main on its next cycle, almost certainly to a newer SHA. Cherry-picking would land a stale bump that gets superseded within days. **Action:** verify Dependabot fires on the next weekly cycle (after PR #175's SonarQube guard lands so the new PR doesn't fail on missing SONAR_TOKEN); if it does not fire by 2026-05-19, fall back to a manual re-extract of `c189a6a` refreshed to current SHAs. |
| #175 | **cherry-pick** (lands first) | Adds `github.actor != 'dependabot[bot]'` to the SonarQube job's `if:` guard so Dependabot PRs no longer fail SonarQube on the missing `SONAR_TOKEN` secret. Single-line ci.yml change. Skipped jobs satisfy required-checks branch protection, so no protection edit is needed. **Order matters:** this must land before the next Dependabot run (and therefore before the #120 re-emit) so the next Dependabot PR is not blocked. |
| #182 | **skip — moot, daemon-era** | The 9-commit desloppify cleanup pass overwhelmingly targets daemon-era code that does not exist on main: 7 of 9 commits touch `tests/daemon_*.rs`, `crates/rimap-server/src/{boot/registry.rs,daemon/run.rs}`, the `BootError` introduction, and the `run_audit_blocking` helper — all rolled back with the daemon. The remaining sliver (`RimapError::Authz → Tagged` rename in `d498630` and `cargo-machete ignored = ["ulid"]` in `rimap-audit/Cargo.toml`) is not "re-extraction" — it is a fresh refactor question whose merits should be argued on its own. Additionally, commit `7c15a75` (`html::process → sanitize_html` rename) is **explicitly** *not* re-applied to main per the parallel decision documented in the issue #226 plan. **Action:** close this checklist item with a comment pointing at this plan's rationale; if the `Authz → Tagged` rename remains desirable, file a separate refactor issue. |
| #186 | **cherry-pick** | One-paragraph `AGENTS.md` edit syncing the required-checks enumeration. Main currently says "all six status checks" + SonarQube; archive bumps it to "all seven status checks" with `check (macOS)` added to the inline list. Confirmed accurate against current branch protection (`gh api repos/.../branches/main/protection/required_status_checks` returns 8 contexts: rustfmt, clippy, test (stable), cargo-deny, zizmor self-check, SonarQube, test (MSRV 1.88.0), check (macOS) — i.e. seven plus SonarQube). Auto-merges cleanly. |

Net result: **four PRs** opened (PR α through PR δ below), **two PRs** explicitly skipped with rationale, totalling 5 cherry-picks of 5 archive change commits.

## Pre-extraction state on `main`

Verified at HEAD `60aa245`:

- `Cargo.toml` workspace deps: `toml = "0.8"`, `directories = "5.0"`, `sha2 = "0.10"`, `strum = "0.26"` (with the v0.26.4 audit comment), `linkify = "0.10.0"`, `fs4 = "0.13"`. None of the safe-five or fs4 bumps are present.
- `Cargo.lock`: holds the pre-bump versions of all six crates. `rand 0.8.6` and `rand 0.9.4` both still present (rand 0.10 deferral is still required — verified via the unchanged transitive pins on `chrono 0.4.44`, `governor 0.10.4`, `proptest 1.11.0`, `ulid 1.2.1`).
- `deny.toml:109-112`: skip-tree contains `windows-sys` 0.48, 0.52, 0.59 — all three. PR #177's diff drops 0.48 and 0.52 because the directories-6 bump consolidates them.
- `crates/rimap-audit/src/writer/{mod.rs,rotation.rs}`: still uses `use fs4::fs_std::FileExt;` and `FileExt::try_lock_exclusive(&file)` returning `Result<bool, io::Error>`. Pre-fs4-1.x.
- `crates/rimap-config/src/model.rs:551-571`: three `ImapEncryption` test sites use `ValueDeserializer::new(...)`. Pre-toml-1 API.
- `.github/workflows/ci.yml:128-159` SonarQube job: `if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false` — fork guard only, no Dependabot guard.
- `.github/workflows/ci.yml` action SHAs: `taiki-e/install-action@cf39a74…` v2.75.0 (5 occurrences) and `EmbarkStudios/cargo-deny-action@3fd3802…` v2.0.15 (1 occurrence). Both pre-PR-#120.
- `AGENTS.md:168`: "PR workflow: feature branch -> push -> PR against main. CI runs all six status checks (`rustfmt`, `clippy`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`), plus `SonarQube` for code quality." Pre-PR-#186.
- `docs/superpowers/plans/`: contains the existing Phase-2 re-extract plans (issues #224, #225, #226, plus the test-strategy specs from PR #243). Does **not** contain `2026-04-29-cargo-major-deferred-from-pr171.md`.
- `crates/rimap-server/tests/`: holds `audit_fail_open.rs`, `audit_merge.rs`, `dispatch_ticket.rs`, `dry_run_cli.rs`, `e2e.rs` only. No `daemon_*.rs` integration tests (confirms the rolled-back state that makes PR #182 moot).
- `crates/rimap-content/src/html/mod.rs:131`: `pub fn process(...)` — main's preserved naming. The desloppify rename to `sanitize_html` is *not* present and is intentionally not re-extracted.
- `crates/rimap-core/src/error.rs:149`: `RimapError::Authz` is the canonical variant name; no `Tagged` rename has been re-applied.

## Implementation tasks

### PR α — SonarQube skip on Dependabot PRs (PR #175)

**Branch:** `phase2/issue-228-sonarqube-dependabot-skip` from `main`. **Lands first** so the next Dependabot run is not blocked by the missing `SONAR_TOKEN`.

#### Task α.1 — Branch and cherry-pick
- [ ] `git checkout -b phase2/issue-228-sonarqube-dependabot-skip main`
- [ ] `git cherry-pick 6c36901`. Auto-merges cleanly on `.github/workflows/ci.yml:112-119` (the SonarQube job's `if:` block). Verified.
- [ ] Diff sanity: only `.github/workflows/ci.yml` is touched, only the `if:` line is changed, +5/-2.

#### Task α.2 — Local validation
- [ ] `actionlint .github/workflows/ci.yml` clean (the multi-line `if:` uses YAML folded scalar `>-` syntax which actionlint accepts).
- [ ] `zizmor .github/workflows/ci.yml` clean (no new findings — the change strengthens, not weakens, the secret-handling posture).
- [ ] `prek run --all-files` clean.

#### Task α.3 — PR + CI validation
- [ ] Push branch, open PR titled `phase2: skip SonarQube on Dependabot PRs (#228)`.
- [ ] PR body: `Closes part of #228 (PR #175). Refs: #229.` Note that #228 is the umbrella; this PR closes the #175 checklist row only.
- [ ] All 8 required checks green. SonarQube continues to run (this PR is not from Dependabot, so the new guard is bypassed).

### PR β — Cargo-major deferral plan + safe-five bumps (PRs #176 + #177)

**Branch:** `phase2/issue-228-cargo-major-safe-five` from `main` after PR α merges.

#### Task β.1 — Branch and cherry-pick docs (#176)
- [ ] `git checkout -b phase2/issue-228-cargo-major-safe-five main`
- [ ] `git cherry-pick 14bc97d`. Adds `docs/superpowers/plans/2026-04-29-cargo-major-deferred-from-pr171.md` (420 lines, docs-only). No conflicts.

#### Task β.2 — Cherry-pick safe-five bumps (#177)
- [ ] `git cherry-pick 49caeb1`. Auto-merges across `Cargo.toml`, `Cargo.lock`, `crates/rimap-config/src/model.rs`, `deny.toml`. Verified clean apply.
- [ ] Inspect the resulting `Cargo.toml` workspace deps: confirm `toml = "1"`, `directories = "6"`, `sha2 = "0.11"`, `strum = "0.28"` (with the updated SC-PROC-01 audit comment naming the 0.26 → 0.28 re-audit), `linkify = "0.11"`.
- [ ] Inspect `deny.toml`: confirm only `{ name = "windows-sys", version = "0.59" }` remains in the skip-tree section (0.48 and 0.52 dropped). Verify against `Cargo.lock`: there must be no `windows-sys 0.48` or `windows-sys 0.52` entries (`grep -c '^name = "windows-sys"' Cargo.lock` should match the surviving major-line count). If either reappears via a transitive bump on the cherry-pick, restore the corresponding skip-tree entry rather than failing `cargo deny` — the rationale comment for "Multiple `windows-sys` major lines coexist" still applies.
- [ ] Inspect `crates/rimap-config/src/model.rs:551-571`: confirm three `ValueDeserializer::parse(...).unwrap()` call sites.

#### Task β.3 — Local validation
- [ ] `cargo build --workspace --all-targets --all-features --locked` clean.
- [ ] `just lint` clean — no new clippy findings from the bumps (e.g. `linkify 0.11` API surface changes are not used by `rimap-content`'s callers; `strum 0.28` does not change derive output for our enums).
- [ ] `just test` clean — workspace test count unchanged; `rimap-config` deserialization tests for `ImapEncryption` (`deserializes_starttls`, `deserializes_tls`, `rejects_unknown_value`) still pass under the new `ValueDeserializer::parse` shape.
- [ ] `just deny` clean — no new advisories from the bumps; license set unchanged; the windows-sys skip-tree edit reflects post-bump reality.
- [ ] `cargo audit` clean (no fresh RUSTSEC against the new versions).
- [ ] `cargo fmt --all -- --check` clean.
- [ ] Re-confirm SC-PROC-01 strum audit: the commit message records the 2026-04-29 re-audit; the calendar date sits within the 30-day re-audit window for 2026-05-05 cherry-pick. No additional audit step required at extraction time.

#### Task β.4 — PR + CI validation
- [ ] Push, open PR titled `phase2: cargo-major safe-five + deferral plan (#228)`.
- [ ] PR body lists both archive PRs: `Closes part of #228 (PRs #176 + #177). Refs: #171 (closed without merging), #229.` Mention that the deferral plan in the docs-only commit explains *why* `fs4` and `rand` are split out (PR γ for fs4; rand 0.10 deferred indefinitely).
- [ ] All 8 required checks green. The SonarQube job runs as expected (this PR is not from Dependabot).
- [ ] `cargo-deny` job in CI verifies the windows-sys skip-tree edit holds against the cherry-picked `Cargo.lock`.

### PR γ — fs4 1.x migration (PR #178)

**Branch:** `phase2/issue-228-fs4-1x` from `main` (independent of PR β; can run in parallel for review, must serialize on merge to keep `Cargo.lock` clean).

#### Task γ.1 — Branch and cherry-pick
- [ ] `git checkout -b phase2/issue-228-fs4-1x main` (or rebase onto post-β `main` if β has merged — the bumps in β do not touch `fs4`).
- [ ] `git cherry-pick e3a8488`. Auto-merges cleanly across `Cargo.toml`, `Cargo.lock`, `crates/rimap-audit/src/reader/mod.rs`, `crates/rimap-audit/src/writer/{mod.rs,emit.rs,rotation.rs}`.
- [ ] Inspect the rotation.rs and writer/mod.rs sites: confirm the new shape matches:
  - Import: `use fs4::{FileExt, TryLockError};` (was `use fs4::fs_std::FileExt;`)
  - Call: `FileExt::try_lock(&file)` (was `try_lock_exclusive`)
  - Match arms map `Ok(())` → success, `Err(TryLockError::WouldBlock)` → `AuditError::Locked`, `Err(TryLockError::Error(io_err))` → `AuditError::Open`/`Rotate` per the existing site.
- [ ] Confirm doc-comment references to `try_lock_exclusive` in `crates/rimap-audit/src/writer/{emit.rs:86,mod.rs:8,rotation.rs:67,89,91}` are also updated to `try_lock` — the cherry-pick should carry this in the same commit. If any stale reference survives, fix in-flight before opening the PR.

#### Task γ.2 — Local validation
- [ ] `cargo build -p rimap-audit --all-features --locked` clean.
- [ ] `cargo test -p rimap-audit --all-features --locked` clean — including `tests/concurrent_lock.rs` which is the regression suite for the `LOCK_EX-on-drop` invariant. Archive's commit message asserts "all 136 rimap-audit tests pass" post-migration.
- [ ] `just lint` clean (no new clippy findings; `TryLockError` is a typed enum, no exhaustiveness warnings).
- [ ] `just deny` clean — fs4 1.x license metadata unchanged (Apache-2.0 OR MIT); no new transitive deps.

#### Task γ.3 — PR + CI validation
- [ ] Push, open PR titled `phase2: fs4 1.x migration in rimap-audit (#228)`.
- [ ] PR body: `Closes part of #228 (PR #178). Refs: #229.` Mention the `lock-on-drop` invariant is preserved (fs4 1.x keeps close-releases-flock semantic).
- [ ] All 8 required checks green.

### PR δ — AGENTS.md required-checks sync (PR #186)

**Branch:** `phase2/issue-228-agents-required-checks` from `main`.

#### Task δ.1 — Branch, cherry-pick, validate
- [ ] `git checkout -b phase2/issue-228-agents-required-checks main`
- [ ] `git cherry-pick 6397e3c`. Auto-merges cleanly on `AGENTS.md:163-173`. Verified.
- [ ] Inspect: confirm `AGENTS.md` now reads "all seven status checks (`rustfmt`, `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`), plus `SonarQube` for code quality." (Cross-check against `gh api repos/randomparity/rusty-imap-mcp/branches/main/protection/required_status_checks | jq .contexts` — must match.)
- [ ] `prek run --all-files` clean.

#### Task δ.2 — PR
- [ ] Push, open PR titled `phase2: docs(agents) — sync required-checks list (#228)`.
- [ ] PR body: `Closes part of #228 (PR #186). Refs: #229.`
- [ ] All 8 required checks green.

### Skip-and-document tasks

#### Task ε.1 — Document #120 skip
- [ ] After PR α merges, monitor Dependabot's next weekly cycle (next run schedule visible in `.github/dependabot.yml` — `interval: "weekly"`, no `time:` set, defaults to ~04:30 UTC on the day-of-week of repo creation).
- [ ] If Dependabot opens a fresh `actions-minor-patch` group PR within 7 days of PR α landing, comment on issue #228 noting that #120 is superseded by the new Dependabot PR; do not cherry-pick `c189a6a`.
- [ ] If no Dependabot PR appears by 2026-05-19, manually re-extract: `git checkout -b phase2/issue-228-actions-minor-patch main; git cherry-pick c189a6a`. Before pushing, refresh the action SHAs against the current `taiki-e/install-action` and `EmbarkStudios/cargo-deny-action` releases (use `gh api repos/<owner>/<repo>/git/refs/tags/v<X.Y.Z> --jq .object.sha` to resolve the latest tag; pin to that SHA with the `# vX.Y.Z` comment per the project's action-pinning convention). Open as `phase2: ci(deps) — refresh actions-minor-patch group (#228)`.

#### Task ε.2 — Document #182 skip
- [ ] Comment on issue #228 (or in the PR α / PR β / PR δ description) referencing this plan's "PR #182 — skip — moot, daemon-era" rationale: 7 of 9 commits target rolled-back daemon code; the parallel `7c15a75` rename is explicitly excluded by the issue #226 plan; the surviving slivers (`Authz → Tagged` rename, `cargo-machete ignored = ["ulid"]`) are not re-extraction.
- [ ] If the `Authz → Tagged` rename is still desirable, file a separate refactor issue with that exact scope (and reference `d498630` for the call-site list and the rationale paragraph from its commit body). Do not bundle into #228.

## Acceptance criteria (from issue #228)

- [ ] Each landed re-extraction is a small targeted PR with a clear scope (4 PRs total — α, β, γ, δ).
- [ ] CI green on all 8 required checks for each PR.
- [ ] `cargo deny check` clean on the merged tip post-β (advisories, licenses, bans, sources — the windows-sys skip-tree edit is verified against the bumped `Cargo.lock`).
- [ ] Issue #228 checklist updated:
  - [ ] PR #176 — landed via PR β
  - [ ] PR #177 — landed via PR β
  - [ ] PR #178 — landed via PR γ
  - [ ] PR #120 — closed as moot (Dependabot re-emit) or landed via Task ε.1 fallback
  - [ ] PR #175 — landed via PR α
  - [ ] PR #182 — closed as moot (daemon-era; documented in Task ε.2)
  - [ ] PR #186 — landed via PR δ
- [ ] Issue #228 closes when all seven checklist rows are resolved (landed or explicitly skipped with rationale).

## Risks & open questions

- **rand 0.10 deferral still applies.** Verified `Cargo.lock` shows `chrono 0.4.44` / `governor 0.10.4` / `proptest 1.11.0` / `ulid 1.2.1` all still pull `rand 0.9` (with `rand 0.8.6` also present transitively for older consumers). The deferral rationale in PR #176's plan stands; do not opportunistically include rand bumps in PR β. Re-evaluate after each minor bump of those four crates.
- **windows-sys skip-tree drift.** PR #177 drops the 0.48 and 0.52 entries because directories-6 unifies the windows-sys subtree onto 0.61. If a transitive crate has *added* a 0.48 or 0.52 dep on `main` since archive (unlikely but possible), `cargo deny check` will fail post-cherry-pick. Mitigation: run `cargo deny check` locally before opening PR β; if the check fails, restore the relevant skip-tree entries with a fresh `# Why:` comment naming the consumer.
- **strum SC-PROC-01 re-audit window.** Archive's commit message records the 2026-04-29 re-audit; cherry-pick on 2026-05-05 sits within the 30-day window. If extraction slips past 2026-05-29, perform a fresh re-audit (same checks: maintainer, build.rs absence, transitive proc-macros, RUSTSEC scan) and update the inline comment timestamp.
- **toml 1.x test-only API breakage.** The `ValueDeserializer::new(&str)` → `parse(&str).unwrap()` migration is contained to three test sites in `rimap-config/src/model.rs`. If a future contributor reintroduces the old API surface anywhere else (e.g. in a fixture helper), the build will break post-β. Spot-check via `rg 'ValueDeserializer::new'` after PR β lands.
- **fs4 1.x lock-on-drop semantic.** PR γ's commit message asserts the invariant is preserved. The regression suite (`crates/rimap-audit/tests/concurrent_lock.rs`) is the verification mechanism. If that test does not exist on main, treat its absence as a *separate* problem — do not skip the suite. (Spot-checked: it exists on archive; verify on main pre-PR-γ.)
- **Dependabot grouping wakeup race.** If PR α's SonarQube guard does not land before Dependabot's next cycle, the new Dependabot PR will fail the SonarQube required check and stall. Mitigation: prioritize α; if it slips, manually retrigger CI on the Dependabot PR after α merges (the skip then takes effect).
- **AGENTS.md drift.** PR δ syncs the doc against branch protection as of 2026-05-05. If branch protection adds/removes a check between extraction and merge (e.g. a follow-up issue promotes the `Fuzz` workflow's smoke jobs to required), update the AGENTS.md text in-flight rather than landing a stale list.
- **PR #182 surviving slivers.** The `Authz → Tagged` rename and `cargo-machete ignored = ["ulid"]` are not re-extracted by this plan. If a future contributor argues for them, the canonical reference is archive `d498630` (rename) and the rimap-audit `Cargo.toml` shape from the same commit. Do not retro-bundle into #228.

## Out of scope

- The rand 0.10 bump (deferred indefinitely; re-evaluate when transitive consumers drop their rand 0.9 pin).
- The `html::process → sanitize_html` rename (explicitly excluded; main's preserved naming stands per the issue #226 plan).
- The `RimapError::Authz → Tagged` rename (separate refactor issue if desired; not re-extraction).
- Promoting any new check (Fuzz, SBOM, etc.) to required — out of scope for #228.
- Branch protection rule edits — none of the four landing PRs require a protection-rule change.
- The cargo-machete `ignored = ["ulid"]` carve-out for `rimap-audit/Cargo.toml` (sliver of #182; defer with the rest of #182 unless the audit log reintroduces a machete false-flag).

## Reference

- Rollback narrative: `docs/superpowers/specs/2026-05-02-multi-client-stdio-design.md` §12.
- Phase-2 meta: issue [#229](https://github.com/randomparity/rusty-imap-mcp/issues/229).
- Companion phase-2 plans: issues #224 (truncate-graphemes), #225 (mutation-cleanup waves), #226 (ClusterFuzzLite), #227 (test-strategy spec).
- Cargo-major deferral plan (re-extracted by PR β): `docs/superpowers/plans/2026-04-29-cargo-major-deferred-from-pr171.md` (post-cherry-pick path).
- Branch protection contexts: `gh api repos/randomparity/rusty-imap-mcp/branches/main/protection/required_status_checks` returns the canonical list — keep AGENTS.md's enumeration in sync via PR δ.
