# Open Issues Roadmap — April 2026

**Status:** Draft 2026-04-19
**Scope:** All 21 open GitHub issues as of 2026-04-19, grouped into two tiers and
six Tier-1 sub-groups. This spec drives a family of per-sub-group implementation
plans, not a single monolithic plan.

## Table of Contents

1. [Goals & Non-Goals](#1-goals--non-goals)
2. [Tier Split](#2-tier-split)
3. [Tier 1 Sub-Group Inventory](#3-tier-1-sub-group-inventory)
4. [Recommended Execution Order (Appendix A)](#appendix-a-recommended-execution-order)
5. [Tier 2 Deferred List](#4-tier-2-deferred-list)
6. [Next Steps](#5-next-steps)

---

## 1. Goals & Non-Goals

### Goals

- Map all 21 open issues to coherent, independently mergeable sub-groups.
- Surface inter-issue sequencing (type changes land before consumers; foundation
  enums land before the code that branches on them).
- Give a recommended parallelism plan that isolates merge surface.
- Leave per-task TDD breakdowns to the individual sub-group plans generated
  on demand via the `writing-plans` skill.

### Non-Goals

- Rewriting or re-triaging the issues themselves. Severity markers and
  acceptance criteria are taken from the issue bodies as-is.
- Scheduling. This is an ordering/grouping doc, not a calendar.
- Closing issues that aren't reflected in one of the six sub-groups.

---

## 2. Tier Split

- **Tier 1 — 16 issues.** HIGH and MEDIUM severity. Covered by six
  implementation plans (one per sub-group).
- **Tier 2 — 5 issues.** LOW severity, posture decisions, and test-only debt.
  Folded into a single later plan after Tier 1 completes.

The split is by severity markers present in each issue's body (reviewer findings
with explicit HIGH/MEDIUM/LOW tags, or issue bodies that classify their own
impact). A few judgment calls:

- **#98** (trusted-meta misclassification on `list_folders`) is self-tagged
  INFO but touches a trust-boundary classification, so it is in Tier 1.
- **#81** (account enumeration posture) is a decision, not code — it stays in
  Tier 2 to avoid stalling Tier 1 on policy.
- **#79** (aarch64 SBOM) could move up if a release is imminent. Currently
  Tier 2.

---

## 3. Tier 1 Sub-Group Inventory

Each sub-group below is self-contained enough to land on its own branch with
its own PR. Internal sequencing is binding (later tasks depend on earlier ones
within the sub-group). Inter-group sequencing is guidance, see Appendix A.

### Sub-group 1 — Folder listing & types

**Goal:** Type the folder-attribute surface, validate server-returned mailbox
names, classify folder metadata correctly in the MCP response, and cut the
`list_folders` N+1 STATUS loop.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #91 | Replace `Folder.attributes: Vec<String>` with a typed `FolderAttribute` enum; remove redundant `selectable` cache. | 1 |
| #95 | Validate server-returned LIST mailbox names before they reach STATUS/SELECT/MOVE/COPY or the MCP response. | 2 |
| #98 | Move or sanitize `folder.name` / `folder.attributes` so server-attacker-controlled bytes do not ride under the trusted `meta` envelope. | 3 |
| #92 | Adopt RFC 5819 LIST-STATUS when the server advertises the capability; fall back to the existing LIST-then-STATUS loop. | 4 |

**Affected files:**

- `crates/rimap-imap/src/types.rs` (Folder, FolderAttribute)
- `crates/rimap-imap/src/ops/folders.rs` (list, select, status)
- `crates/rimap-imap/src/ops/folder_management.rs` (validator reuse)
- `crates/rimap-imap/src/ops/move_message.rs` (consumer of validated names)
- `crates/rimap-server/src/tools/admin/list_folders.rs` (response shape)
- `crates/rimap-server/src/mcp/response.rs` (trusted/untrusted contract)

**Why in this order:** #91 lands the typed enum that #95, #98, and #92 all
branch on. #95 adds the name validator that #98 then references from the
sanitize-or-move decision. #92 is last because its fallback path still uses
the LIST-and-loop shape that the earlier tasks just finished hardening.

**Suggested branch:** `feat/folder-listing-hardening`

### Sub-group 2 — UIDVALIDITY correctness

**Goal:** Stop fabricating `uid_validity = 0`, guard MOVE/COPY against
UIDVALIDITY rotation, and surface COPYUID in audit trails.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #97 | Change `SelectedFolder.uid_validity` from `u32` with `.unwrap_or(0)` to `Option<u32>`. | 1 |
| #96 | UIDPLUS: pass cached source UIDVALIDITY into `move_messages`, compare before UID MOVE / UID COPY, STATUS-check destination after COPY, populate `MoveResult::new_uid` from `[COPYUID ...]`. | 2 |
| #70 | Capture and echo UIDVALIDITY in flag/label/move tool responses; optionally accept an expected value and fail with a typed error on mismatch. | 3 |

**Affected files:**

- `crates/rimap-imap/src/types.rs` (SelectedFolder, Folder)
- `crates/rimap-imap/src/ops/folders.rs` (select)
- `crates/rimap-imap/src/ops/move_message.rs` (MOVE + COPY fallback)
- `crates/rimap-imap/src/ops/store.rs` (flag/label ops)
- `crates/rimap-server/src/tools/flags.rs`, `labels.rs`, `move_message.rs`
  (UIDVALIDITY echoed in responses)

**Why in this order:** #97 is a type change all downstream UIDVALIDITY work
builds on. #96 introduces the guard-and-capture pattern on MOVE; #70 applies
the same capture pattern across the flag/label surface.

**Spec/plan updates required:** `docs/superpowers/specs/2026-04-07-sprint-3-imap-design.md:120`
and `docs/superpowers/plans/2026-04-07-sprint-3-imap.md:1796,3176` reference
the old `u32` shape.

**Suggested branch:** `feat/uidvalidity-correctness`

### Sub-group 3 — Audit cancellation & fail-open hardening

**Goal:** Every `tool_start` audit record is paired with a matched
`tool_end` — even when the MCP handler future is dropped between the two.
Add the one missing test for `fail_open = true`.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #71 | Drop guard for the `emit_tool_start` / `emit_tool_end` pair in `server.rs`. | 1 (with #99) |
| #99 | Drop guard for `run_with_audit_envelope` in `mcp/audit_envelope.rs`. | 1 (with #71) |
| #72 | Test that `fail_open = true` + a write failure produces a successful tool response and increments `suppressed_failures`. | 2 |

**Affected files:**

- `crates/rimap-server/src/server.rs` (emit_tool_start, emit_tool_end)
- `crates/rimap-server/src/mcp/audit_envelope.rs` (run_with_audit_envelope)
- `crates/rimap-audit/src/writer/mod.rs` (bounded channel for Drop-time writes)

**Why in this order:** #71 and #99 are the same mechanism at two different
layers (server dispatch vs. the audit envelope wrapper). They should share a
single `AuditEnvelopeGuard` / `ToolCallGuard` primitive that both call sites
construct. #72 is an independent test and can land first or last within the
sub-group.

**Design note:** The guard's `Drop` impl must be synchronous. Prefer a bounded
channel the existing audit writer task drains over spawning detached Tokio
tasks from `Drop` — keeps shutdown drainable and the guard lightweight.

**Suggested branch:** `feat/audit-cancellation-guard`

### Sub-group 4 — Credential hardening

**Goal:** Redact the username surface across error chains, namespace keyring
entries by account id, and make the env-var fallback opt-in for multi-account
configs.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #76 | Redact `username@host` from `ConfigError::NoCredential` and `ConfigError::Keychain` Display strings. | 1 |
| #77 | Change keyring key format from `<username>@<host>` to `<account-id>/<username>@<host>`; add `migrate-keyring` subcommand; back-compat read path on startup. | 2 |
| #78 | Add a `fallback` config knob (`keyring-only` vs `keyring-then-env`); audit-log the credential source. | 3 |

**Affected files:**

- `crates/rimap-config/src/error.rs` (Display impls)
- `crates/rimap-config/src/credential.rs` (account_key, resolve_credential)
- `crates/rimap-config/src/loader.rs` (parse the new `fallback` knob)
- `crates/rimap-config/src/validate.rs` (optional — gate `fallback` by
  single/multi-account mode)
- `crates/rimap-server/src/bin/` (or wherever CLI subcommands live, for
  `migrate-keyring`)
- `docs/multi-account.md` (update the "recommendation" to the enforceable
  config knob)

**Why in this order:** #76 is the smallest surface and lands first to remove
the username leak from error chains. #77 is the breaking keyring-key change
with the widest blast radius. #78 builds on #77 — the `audit_log credential
source` field is more meaningful once keys are already namespaced.

**Breaking-change note:** #77 changes the keyring key format. Migration is
covered by the `migrate-keyring` subcommand and the back-compat fallback
on startup. Document in CHANGELOG.

**Suggested branch:** `feat/credential-hardening`

### Sub-group 5 — MCP dispatch hygiene

**Goal:** Enforce namespaced tool names in multi-account mode, and emit the
`tools/list_changed` notification so clients don't operate against stale
default-account views.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #73 | Reject bare tool names (e.g. `send_email`) in `call_tool` when `is_legacy_single_account() == false`. Sub-capability dotted names stay valid. | 1 |
| #80 | Emit `notifications/tools/list_changed` when `handle_use_account` successfully changes the active account. | 2 |

**Affected files:**

- `crates/rimap-server/src/server.rs` (call_tool dispatch, handle_use_account)
- `crates/rimap-server/src/session.rs` (if list_changed depends on session)

**Why in this order:** #73 is a correctness gate; #80 is a UX signal. Either
order is viable — landing #73 first keeps the dispatch contract clean before
clients are told about the change.

**Suggested branch:** `feat/mcp-dispatch-hygiene`

### Sub-group 6 — Config parser refactor

**Goal:** Parse the TOML config once instead of twice.

| Issue | Summary | Internal order |
|-------|---------|----------------|
| #74 | `load_and_validate` currently parses via `toml::Table` for classification, then re-parses via `toml::from_str::<MultiAccountConfig>` or `Config`. Parse once, classify typed keys, deserialize the existing value. | 1 |

**Affected files:**

- `crates/rimap-config/src/loader.rs` (load_and_validate)

**Why standalone:** Touches one function, one error variant. No other sub-group
depends on it, and it does not depend on any other.

**Suggested branch:** `refactor/config-single-pass-parse`

---

## Appendix A — Recommended Execution Order

Guidance, not binding. Pick a different order if release pressure or
reviewer availability changes the calculus.

### Phase 1 — Parallel (3 worktrees)

Sub-groups 3, 4, and 6 are fully independent — different crates and modules,
no shared types.

- **Worktree A:** Sub-group 3 (audit cancellation) — `crates/rimap-server`,
  `crates/rimap-audit`.
- **Worktree B:** Sub-group 4 (credential hardening) — `crates/rimap-config`.
- **Worktree C:** Sub-group 6 (config parser) — `crates/rimap-config/loader.rs`
  only. Coordinate with B on conflicts (same crate, different files).

Rationale: Phase 1 clears the standalone work and gets the credential-hardening
trust-boundary fixes in early.

### Phase 2 — Serial

Sub-groups 1 and 2 both touch `rimap-imap` (`types.rs`, `ops/folders.rs`,
`ops/move_message.rs`). Run them serially to keep merge surface small.

- **First:** Sub-group 1 (folder listing & types). Lands the typed
  `FolderAttribute` enum and the server-origin name validator. Both widen
  `types.rs` and rework `ops/folders.rs::list`.
- **Second:** Sub-group 2 (UIDVALIDITY correctness). Touches the adjacent
  `SelectedFolder` shape in `types.rs` and `ops/folders.rs::select`, plus
  `ops/move_message.rs`. Sequencing after sub-group 1 avoids a three-way
  merge on `types.rs` and `ops/folders.rs`.

If the two sub-groups end up not conflicting in practice (same files, different
lines), they can parallelize — reassess at plan-writing time.

### Phase 3 — Last

- Sub-group 5 (MCP dispatch hygiene) — runs after Phase 2 so that any folder
  or UID error types introduced by the earlier phases are already in the
  `call_tool` error surface.

---

## 4. Tier 2 Deferred List

These roll into a later plan (tentatively `docs/superpowers/plans/YYYY-MM-DD-open-issues-tier-2.md`).

| Issue | Summary | Notes |
|-------|---------|-------|
| #75 | `AccountId` case-normalize or reject case-variant duplicates. | Mcp-security N-1; not exploitable today but implicit invariant. |
| #79 | Embed `cargo-auditable` SBOM in aarch64-linux release binaries. | Move up if a release is imminent. |
| #81 | Document or narrow account-enumeration disclosure in `NoAccount` / `UnknownAccount` error messages. | Decision doc, not code — pick option 1, 2, or 3 from the issue. |
| #93 | Dedupe the `fn uid(n: u32)` test helper across `ops/fetch.rs`, `ops/move_message.rs`, and the Dovecot integration tests. | Test-only debt. |
| #94 | Share `warning_code_to_label` / `error_kind_label` between the epvme runner binary and the `injection_corpus` test harness. | Test-only debt. |

---

## 5. Next Steps

1. User reviews this roadmap. If approved, proceed.
2. Pick the first sub-group per Appendix A (Phase 1 — sub-group 3, 4, or 6).
3. Invoke the `superpowers:writing-plans` skill with the sub-group's goal,
   affected files, and internal sequencing from §3.
4. Land the sub-group behind its suggested branch.
5. Repeat per sub-group until Tier 1 is closed.
6. Revisit Tier 2 as a single later plan.
