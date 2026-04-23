# Polish PR 9 — Doc sweep: stale `AccountRegistry.active` references

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove stale `registry.active` references from the sprint-3 design spec; point readers at `SessionState.active_account` instead.

**Architecture:** Docs-only. Two inline edits to `docs/superpowers/specs/2026-04-13-sprint-3-design.md` (lines 206 and 214). After editing, verify no stale references remain in any doc under `docs/`.

**Tech Stack:** Markdown only.

---

## Files

- Modify: `docs/superpowers/specs/2026-04-13-sprint-3-design.md` (lines 205–220)

## Task 1: Rewrite account-resolution pseudocode to name the correct field

**Files:**
- Modify: `docs/superpowers/specs/2026-04-13-sprint-3-design.md:205-220`

- [ ] **Step 1: Read the current section for full context**

Run: read lines 195–230 of `docs/superpowers/specs/2026-04-13-sprint-3-design.md` so the surrounding paragraphs inform the rewrite. The stale field is named on lines 206 and 214.

- [ ] **Step 2: Edit line 206 (`### Account Resolution` bullet)**

Replace:

```markdown
2. Else if `registry.active` is set — use the session default.
```

With:

```markdown
2. Else if `SessionState.active_account` is set — use the session default.
```

- [ ] **Step 3: Edit line 214 (`use_account` tool description)**

Replace:

```markdown
- Sets `registry.active` to the named account.
```

With:

```markdown
- Sets `SessionState.active_account` on the calling session to the named account.
```

- [ ] **Step 4: Verify no further stale references remain anywhere under `docs/`**

Run:
```bash
rg -n 'registry\.active|AccountRegistry\.active|AccountRegistry::active' docs/
```
Expected: no hits, or only hits inside an explicit "superseded / historical" callout. If any remain, repeat step 2/3 on those files.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-04-13-sprint-3-design.md
git commit -m "$(cat <<'EOF'
docs: rename stale registry.active to SessionState.active_account (#139)

Task 15 of the multi-client daemon work moved the session-default
account slot off AccountRegistry onto per-session state. Update the
sprint-3 design spec accordingly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Self-review

- Every step has complete content (no TBDs).
- `rg` grep in step 4 confirms coverage across all docs.
- Single commit, docs-only.
