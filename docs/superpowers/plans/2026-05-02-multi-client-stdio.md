# Multi-client stdio (B1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing audit-lock-collision failure actionable, and document the multi-client config pattern, so users running multiple MCP clients on the same machine can configure around the constraint.

**Architecture:** Pure UX change. The `AuditError::Locked` message gets rewritten to name the resolution and point at a new docs anchor. Three documentation files (`docs/audit-log.md`, both quickstarts, README) get a "Running multiple MCP clients" section / cross-link. No code architecture changes; no new mechanisms; no new dependencies. See spec at `docs/superpowers/specs/2026-05-02-multi-client-stdio-design.md`.

**Tech Stack:** Rust 2024 edition; `thiserror` for error display; existing `cargo nextest` / `cargo test` test runners; pre-commit hooks via `prek` already installed.

**Open questions resolved here (from spec §11):**
- **Error message format:** single-line. The error names path + resolution + docs anchor in one line. Long-form guidance lives in `docs/audit-log.md`. Reasons: predictable terminal rendering, simple `to_string()` test assertions, conventional `thiserror` style.
- **README troubleshooting placement:** create a new minimal `## Troubleshooting` section between `## Documentation` (line 156) and `## License` (line 164). One bullet now; gives a place to add future entries.

---

## File Structure

| File | Change | Responsibility after change |
|---|---|---|
| `crates/rimap-audit/src/record/error.rs` | Modify `#[error]` on `Locked` variant; update tests | Defines the new actionable message; tests pin path + anchor presence |
| `docs/audit-log.md` | Insert new section "Running multiple MCP clients" between "File handling" and "Rotation" | Authoritative reference for the multi-client config pattern; the docs anchor target |
| `docs/quickstart-gmail.md` | Insert one paragraph after the `[audit]` config block | Cross-link from setup flow to the multi-client docs |
| `docs/quickstart-proton-bridge.md` | Insert one paragraph after the `[audit]` config block | Same as Gmail quickstart |
| `README.md` | New `## Troubleshooting` section before `## License` | One-line entry pointing at the docs anchor |

Test files touched:
- `crates/rimap-audit/src/record/error.rs` (the inline `mod tests { … }` block at line 120)

No new files. No deletions.

---

## Task 1: Update the `AuditError::Locked` Display message

**Files:**
- Modify: `crates/rimap-audit/src/record/error.rs:31-39` (the `#[error]` attribute on the `Locked` variant)
- Modify: `crates/rimap-audit/src/record/error.rs:151-159` (the `locked_message_names_the_path` test)
- Modify: `crates/rimap-audit/src/record/error.rs` (add a new sibling test inside the same `mod tests` block)

- [ ] **Step 1: Read the current code**

```bash
cat crates/rimap-audit/src/record/error.rs | sed -n '31,40p'
cat crates/rimap-audit/src/record/error.rs | sed -n '151,160p'
```

Expected: see the current `Locked` variant with text `"audit file ... only one instance may run against a given audit path"`, and the existing test asserting on `/tmp/a.jsonl` and `another rusty-imap-mcp process`.

- [ ] **Step 2: Update the existing test for new wording (failing test first)**

In `crates/rimap-audit/src/record/error.rs`, replace the existing `locked_message_names_the_path` test (lines 151-159) with:

```rust
    #[test]
    fn locked_message_names_the_path() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/a.jsonl"), "got: {msg}");
        assert!(
            msg.contains("another rusty-imap-mcp process"),
            "got: {msg}"
        );
        assert!(
            msg.contains("distinct `[audit].path`"),
            "message must name the resolution; got: {msg}"
        );
    }

    #[test]
    fn locked_message_includes_docs_anchor() {
        // The error string is the canonical entry-point users see when the
        // lock collides. It must point at the docs anchor so the cross-link
        // does not silently rot when docs/audit-log.md is edited.
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("docs/audit-log.md#running-multiple-mcp-clients"),
            "got: {msg}"
        );
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run:

```bash
cargo test -p rimap-audit --lib -- record::error::tests::locked_message
```

Expected: both tests FAIL — the existing message does not contain `distinct `[audit].path`` nor the docs anchor.

- [ ] **Step 4: Update the `Locked` variant's `#[error]` attribute**

In `crates/rimap-audit/src/record/error.rs`, replace lines 31-35 (the `#[error(...)]` line preceding `Locked`) with:

```rust
    /// The audit file is already locked by another process.
    #[error(
        "audit file `{path}` is already locked by another rusty-imap-mcp process. \
         Each MCP client must use a distinct `[audit].path`; \
         see docs/audit-log.md#running-multiple-mcp-clients"
    )]
    Locked {
```

The string is one logical line (single `\` line continuations only — no `\n`), so the rendered error is one line.

- [ ] **Step 5: Run the tests to verify they pass**

Run:

```bash
cargo test -p rimap-audit --lib -- record::error::tests::locked_message
```

Expected: both `locked_message_names_the_path` and `locked_message_includes_docs_anchor` PASS.

- [ ] **Step 6: Run the full audit crate test suite to confirm no regression**

Run:

```bash
cargo test -p rimap-audit
```

Expected: all tests pass, including `crates/rimap-audit/tests/concurrent_lock.rs` (which asserts on the `AuditError::Locked` variant shape, not its message).

- [ ] **Step 7: Run clippy on the audit crate**

Run:

```bash
cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-audit/src/record/error.rs
git commit -m "$(cat <<'EOF'
feat(rimap-audit): make AuditError::Locked actionable

The lock-collision error now names the resolution (use a distinct
`[audit].path` per MCP client) and points at the docs anchor that
holds the worked configuration examples. Pin the docs cross-link in a
test so docs/audit-log.md heading renames are caught.

Variant shape unchanged; call sites and downstream conversions are
not touched.
EOF
)"
```

---

## Task 2: Add "Running multiple MCP clients" section to `docs/audit-log.md`

**Files:**
- Modify: `docs/audit-log.md` — insert a new section between "File handling" (lines 109-124) and "Rotation" (line 126)

- [ ] **Step 1: Read the current section boundaries**

```bash
sed -n '108,128p' docs/audit-log.md
```

Expected: see the end of the "File handling" section (line ~124) and the start of "## Rotation" (line 126).

- [ ] **Step 2: Insert the new section**

In `docs/audit-log.md`, immediately after the existing "File handling" section (after line 124, before the blank line that precedes `## Rotation`), insert:

```markdown

## Running multiple MCP clients

`rusty-imap-mcp` holds an exclusive lock on its configured `[audit].path`
for the lifetime of the process. A second process against the same path
fails immediately with `ERR_CONFIG`. The lock guards append atomicity,
the per-process `seq` allocator, the inode tamper chain, and the
in-memory provenance ring — all forensic invariants that depend on a
single writer.

To run multiple MCP clients on the same machine — for example, two
Claude Code windows on different projects, or Claude Code alongside
Codex — give each MCP client its own `rusty-imap-mcp` config file with
a distinct `[audit].path`.

### Supported scenarios

#### Single MCP client

The default. Nothing to configure beyond the standard setup. One
`[audit].path`, one `rusty-imap-mcp` PID, one audit file.

#### Cross-application: Claude Code + Codex

Each host application has its own MCP config; point each at a
different `rusty-imap-mcp` config file with its own audit path.

`~/.claude.json` (Claude Code, user-scope):

```json
{
  "mcpServers": {
    "rusty-imap": {
      "command": "/usr/local/bin/rusty-imap-mcp",
      "args": ["--config", "/home/dave/.config/rusty-imap-mcp/claude.toml"]
    }
  }
}
```

`~/.codex/config.toml` (Codex):

```toml
[mcp_servers.rusty-imap]
command = "/usr/local/bin/rusty-imap-mcp"
args = ["--config", "/home/dave/.config/rusty-imap-mcp/codex.toml"]
```

`~/.config/rusty-imap-mcp/claude.toml`:

```toml
[audit]
path = "~/.local/state/rusty-imap-mcp/audit-claude.jsonl"
# ... rest of config identical between the two
```

`~/.config/rusty-imap-mcp/codex.toml`:

```toml
[audit]
path = "~/.local/state/rusty-imap-mcp/audit-codex.jsonl"
# ...
```

#### Cross-project: per-project `.mcp.json`

For users whose MCP usage is tied to a specific repository, register
`rusty-imap-mcp` at project scope rather than user scope. Each project
gets its own `.mcp.json` and its own audit path.

```bash
cd /home/dave/src/work-project
claude mcp add --scope project rusty-imap /usr/local/bin/rusty-imap-mcp \
  -- --config /home/dave/.config/rusty-imap-mcp/work.toml
```

This writes `/home/dave/src/work-project/.mcp.json`:

```json
{
  "mcpServers": {
    "rusty-imap": {
      "command": "/usr/local/bin/rusty-imap-mcp",
      "args": ["--config", "/home/dave/.config/rusty-imap-mcp/work.toml"]
    }
  }
}
```

A second project gets the same treatment with its own paths. Each
Claude Code window opened in a project loads that project's
`.mcp.json` and spawns its own `rusty-imap-mcp` child against that
project's audit file.

### Unsupported: same MCP-client config across multiple windows

If you have one `rusty-imap-mcp` entry in `~/.claude.json` (user
scope) and open two Claude Code windows, both windows spawn their own
child against the same audit path. The second child fails to acquire
the lock and exits with `ERR_CONFIG`.

Two options:

1. Move the entry to project scope (`.mcp.json`) so each project gets
   its own audit path, as in the cross-project example above.
2. Accept that one window will lose its `rusty-imap-mcp` MCP server.
   The other features of that Claude Code window are unaffected; only
   the rusty-imap-mcp tools are unavailable in the losing window
   until the holding window exits.

A future database-backed audit store will remove this constraint by
sharing the audit log across processes; until then, distinct
`[audit].path` values per concurrent MCP client are the supported
pattern.

### Per-account rate limits and circuit breakers

Each `rusty-imap-mcp` process maintains its own per-account
`Governor` (rate limiter) and `CircuitBreaker`. With multiple
concurrent MCP clients on the same IMAP account, each client's
budget is independent. Operators who need a single per-account
ceiling enforced across all local clients should track the future
database-backed audit store, which will share this state by
construction.
```

- [ ] **Step 3: Verify the anchor renders correctly**

The error message in Task 1 references `docs/audit-log.md#running-multiple-mcp-clients`. Markdown auto-anchors lowercase the heading and replace spaces with hyphens, so "Running multiple MCP clients" → `#running-multiple-mcp-clients`. Verify by inspection:

```bash
grep -n "^## Running multiple MCP clients" docs/audit-log.md
```

Expected: matches one line.

- [ ] **Step 4: Commit**

```bash
git add docs/audit-log.md
git commit -m "$(cat <<'EOF'
docs(audit-log): add "Running multiple MCP clients" section

Document the supported multi-client configuration patterns
(cross-application, cross-project) and the unsupported case
(multiple windows sharing one user-scope config). Includes worked
config snippets for Claude Code (~/.claude.json + project-scope
.mcp.json) and Codex. Anchor target for the rewritten
AuditError::Locked message.
EOF
)"
```

---

## Task 3: Cross-link from `docs/quickstart-gmail.md`

**Files:**
- Modify: `docs/quickstart-gmail.md` — add one paragraph immediately after the `[audit]` config block (the block ending at line 48)

- [ ] **Step 1: Read the current audit block**

```bash
sed -n '44,52p' docs/quickstart-gmail.md
```

Expected: see the `[audit]` config snippet (lines 46-48) followed by the existing "Replace `you@gmail.com`..." paragraph.

- [ ] **Step 2: Insert the cross-link paragraph**

In `docs/quickstart-gmail.md`, between the closing ` ``` ` of the audit block (line 48) and the next paragraph "Replace `you@gmail.com` with your Gmail address." (line 50), insert:

```markdown

If you plan to run multiple MCP clients against this account (e.g.
two Claude Code windows on different projects, or Claude Code
alongside Codex), see
[Running multiple MCP clients](audit-log.md#running-multiple-mcp-clients)
for the per-client configuration pattern.
```

The relative link `audit-log.md#running-multiple-mcp-clients` is correct because both files live under `docs/`.

- [ ] **Step 3: Verify the link resolves**

```bash
grep -n "running-multiple-mcp-clients" docs/quickstart-gmail.md docs/audit-log.md
```

Expected: `docs/quickstart-gmail.md` references the anchor; `docs/audit-log.md` defines it via `## Running multiple MCP clients`.

- [ ] **Step 4: Commit**

```bash
git add docs/quickstart-gmail.md
git commit -m "$(cat <<'EOF'
docs(quickstart-gmail): cross-link to multi-client audit pattern

Point users from the Gmail setup flow at the new
docs/audit-log.md#running-multiple-mcp-clients section so the
multi-client constraint is discoverable from first-time setup.
EOF
)"
```

---

## Task 4: Cross-link from `docs/quickstart-proton-bridge.md`

**Files:**
- Modify: `docs/quickstart-proton-bridge.md` — add one paragraph immediately after the `[audit]` config block (line 84)

- [ ] **Step 1: Read the current audit block**

```bash
sed -n '80,90p' docs/quickstart-proton-bridge.md
```

Expected: see the `[audit]` config snippet around lines 83-84 followed by the next paragraph.

- [ ] **Step 2: Insert the cross-link paragraph**

In `docs/quickstart-proton-bridge.md`, between the closing ` ``` ` of the audit block and the paragraph that follows it, insert:

```markdown

If you plan to run multiple MCP clients against this account (e.g.
two Claude Code windows on different projects, or Claude Code
alongside Codex), see
[Running multiple MCP clients](audit-log.md#running-multiple-mcp-clients)
for the per-client configuration pattern.
```

(Same wording as Task 3 — duplicated here so this task is self-contained.)

- [ ] **Step 3: Verify the link resolves**

```bash
grep -n "running-multiple-mcp-clients" docs/quickstart-proton-bridge.md docs/audit-log.md
```

Expected: `docs/quickstart-proton-bridge.md` references the anchor; `docs/audit-log.md` defines it.

- [ ] **Step 4: Commit**

```bash
git add docs/quickstart-proton-bridge.md
git commit -m "$(cat <<'EOF'
docs(quickstart-proton-bridge): cross-link to multi-client audit pattern

Point users from the Proton Bridge setup flow at the new
docs/audit-log.md#running-multiple-mcp-clients section so the
multi-client constraint is discoverable from first-time setup.
EOF
)"
```

---

## Task 5: Add `## Troubleshooting` section to `README.md`

**Files:**
- Modify: `README.md` — insert a new `## Troubleshooting` section between `## Documentation` (line 156) and `## License` (line 164)

- [ ] **Step 1: Read the surrounding sections**

```bash
sed -n '155,170p' README.md
```

Expected: see the end of `## Documentation` and the start of `## License`.

- [ ] **Step 2: Insert the new section**

In `README.md`, between the end of the `## Documentation` section and the `## License` heading (line 164), insert:

```markdown

## Troubleshooting

- **`rusty-imap-mcp` exits at startup with `audit file ... is already locked`** —
  another `rusty-imap-mcp` process holds the audit lock. Each MCP
  client must use a distinct `[audit].path`; see
  [Running multiple MCP clients](docs/audit-log.md#running-multiple-mcp-clients)
  for the configuration pattern.
```

- [ ] **Step 3: Verify the link resolves**

```bash
grep -n "running-multiple-mcp-clients" README.md docs/audit-log.md
```

Expected: `README.md` references the anchor; `docs/audit-log.md` defines it.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs(readme): add Troubleshooting section with multi-client lock entry

One bullet pointing at docs/audit-log.md#running-multiple-mcp-clients
for the audit-lock-collision case. Establishes a Troubleshooting
section so future entries have a stable home.
EOF
)"
```

---

## Task 6: Final verification

**Files:** none modified — verification only.

- [ ] **Step 1: Run the full workspace test suite**

Run:

```bash
cargo test --workspace
```

Expected: all tests pass. The audit error tests from Task 1 confirm the new wording; nothing else changed.

- [ ] **Step 2: Run clippy across the workspace**

Run:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 3: Run cargo fmt check**

Run:

```bash
cargo fmt --check
```

Expected: clean.

- [ ] **Step 4: Cross-check every anchor reference**

Confirm all cross-links resolve to a defined anchor:

```bash
echo "--- references ---"
grep -rn "running-multiple-mcp-clients" \
  README.md docs/ crates/rimap-audit/src/record/error.rs
echo "--- definition ---"
grep -n "^## Running multiple MCP clients" docs/audit-log.md
```

Expected references (5 total, exactly):
- `README.md` — 1 hit (Task 5 troubleshooting bullet)
- `docs/quickstart-gmail.md` — 1 hit (Task 3)
- `docs/quickstart-proton-bridge.md` — 1 hit (Task 4)
- `crates/rimap-audit/src/record/error.rs` — 2 hits (the `#[error]` string literal in Task 1 Step 4, and the test assertion in Task 1 Step 2)

Expected definition: 1 hit on the heading line in `docs/audit-log.md` (Task 2).

If any reference appears without a matching definition (or vice versa), an anchor name has drifted — fix before proceeding.

- [ ] **Step 5: Push the branch**

```bash
git push -u origin feat/multi-client-b1
```

Expected: branch pushed; PR can be opened on GitHub.

---

## What this plan does NOT do

Out-of-scope (per spec §3 and §8):

- No daemon, no service install scripts, no socket/named-pipe transport.
- No `--instance` CLI flag, no audit path templates, no per-process auto-derivation.
- No new `[audit]` config fields. No new audit record kinds.
- No shared rate limiter / circuit breaker. No cross-process provenance ring.
- No `audit merge --paths` glob. No database backend.
- No re-extraction of non-daemon work from `archive/daemon-experiment` (Phase 2 of the rollback; tracked separately).

If reviewers ask for any of these, redirect to the spec's §3 (non-goals) and §8 (deferred).
