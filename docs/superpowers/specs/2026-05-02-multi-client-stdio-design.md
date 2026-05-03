# Multi-client stdio — design

Issue: (file on merge)
Target crates: `rimap-audit` (error message), docs only elsewhere.
Related:
- Replaces: `docs/superpowers/specs/2026-04-22-multi-client-daemon-design.md` (preserved on `archive/daemon-experiment`).
- Code references at HEAD `948a29f`: `crates/rimap-audit/src/record/error.rs:31-39` (`AuditError::Locked`), `crates/rimap-audit/src/writer/mod.rs:127` (lock acquisition), `docs/audit-log.md:109-124` (current file-handling docs).

## 1. Problem

`rusty-imap-mcp` enforces a hard "one process per audit path" invariant via `fs4::FileExt::try_lock_exclusive`. A user running two MCP clients on the same audit path fails to start the second server with `audit file already locked; only one instance may run against a given audit path`. The error names the path but does not tell the user what to do about it, and no project documentation describes the multi-client pattern.

The lock itself is load-bearing — it guards append atomicity, monotonic per-process `seq`, the inode tamper chain, the in-memory provenance ring, and the in-memory rate-limit / circuit-breaker state. We are not relaxing it. We are signposting the existing mechanism so users can configure around the collision.

The earlier multi-client daemon design (`2026-04-22-multi-client-daemon-design.md`, now archived) attempted to solve this by introducing a long-running daemon process plus a stdio shim, with platform-specific service integration (systemd, launchd, Windows SCM). That work was completed and merged but is being rolled back. The OS-specific service surface and the per-user operational burden of running a service exceeded the value delivered for an MCP server whose typical use is tied to a single Claude Code window or repository.

## 2. Goals

- Make the existing lock-collision failure actionable: the error tells the user *what* collided and *how* to configure around it.
- Document the multi-client configuration pattern in user-facing docs (audit-log reference, both quickstarts, README troubleshooting).
- Preserve every audit invariant from the v0 design literally — no schema changes, no new record kinds, no concurrency primitives added.
- Leave the door open for a future database-backed audit store. Anything we add now should be small enough to delete cleanly when that lands.

## 3. Non-goals

- No daemon process. No long-running singleton. No socket or named-pipe transport.
- No platform service integration (systemd, launchd, Windows SCM, Task Scheduler).
- No new CLI subcommands (`daemon`, `shim`, `service install/uninstall/run`).
- No `--instance <name>` CLI flag, no audit path templates, no per-process auto-derived audit paths (PID or ULID suffixes). The path stays exactly what the user wrote in `[audit].path`.
- No new fields in `[audit]` config block. No new audit record kinds (`session_start`, `session_end`, `peer_identity`, `session_id`).
- No shared rate limiter or circuit breaker across processes. Each process keeps its own per-account state, as in v0.
- No cross-file `audit merge` query. One file at a time; users `cat` or shell-glob for cross-file analysis.
- No new dependencies.

## 4. Architecture

Identical to pre-daemon v0 (current HEAD `948a29f`). One `rusty-imap-mcp` PID per MCP-client config entry. Each PID exclusively locks its configured `[audit].path` for its lifetime. Multi-client = multiple MCP-client configs pointing at distinct rusty-imap-mcp configs, each with a distinct audit path. No coordination between processes.

```
┌──────────────┐  stdio/MCP   ┌──────────────────────────────┐
│ MCP client A │ ───────────► │ rusty-imap-mcp (PID 1234)    │
│ (Claude work)│              │  --config work-config.toml   │
└──────────────┘              │  audit-work.jsonl (locked)   │
                              └──────────────────────────────┘

┌──────────────┐  stdio/MCP   ┌──────────────────────────────┐
│ MCP client B │ ───────────► │ rusty-imap-mcp (PID 5678)    │
│ (Codex)      │              │  --config codex-config.toml  │
└──────────────┘              │  audit-codex.jsonl (locked)  │
                              └──────────────────────────────┘
```

The two processes never know about each other. They share the same IMAP account on the upstream server, but each opens its own connection, runs its own rate limiter, writes its own audit chain.

## 5. Code change

Single change in `crates/rimap-audit/src/record/error.rs`. The `AuditError::Locked` variant keeps its shape (`Locked { path: PathBuf }`), so call sites (`crates/rimap-audit/src/writer/mod.rs:127`, `crates/rimap-audit/src/reader/mod.rs:118`, the failure paths in `rotation.rs` and `concurrent_lock.rs` tests) are not touched. Only the `#[error]` Display string changes.

Current text:
> `audit file `{path}` is already locked by another rusty-imap-mcp process; only one instance may run against a given audit path`

New text (multi-line via `\n`):
> `audit file `{path}` is already locked by another rusty-imap-mcp process.\n\nEach MCP client must use a distinct `[audit].path`. To run multiple MCP clients (e.g. two Claude Code windows on different projects, or Claude Code + Codex), point each at a different config file with its own audit path.\n\nSee docs/audit-log.md#running-multiple-mcp-clients for the configuration pattern.`

The exact wording is finalized in the implementation plan; the spec commits to the *shape* (names path, names the resolution, points at the docs anchor).

## 6. Documentation changes

### 6.1 `docs/audit-log.md`

New section after "File handling" (before "Rotation"):

**Running multiple MCP clients**

A worked example showing the pattern:
1. The constraint (one PID per audit path) and why it exists (forensic invariants).
2. The supported scenarios:
   - Single MCP client (default — no change needed).
   - Cross-application: Claude Code + Codex with distinct host configs.
   - Cross-project: per-project `.mcp.json` (project-scope) configs.
3. The unsupported scenario: two Claude Code windows sharing one user-scope MCP config entry. State plainly that this collides and how to either avoid it (use project scope) or accept that one window will fail to start the MCP server.
4. Concrete config snippets for each supported scenario, showing a Claude Code `~/.claude.json` entry, a Codex `~/.codex/config.toml` entry, and the two distinct rusty-imap-mcp config files differing only in `[audit].path`.

### 6.2 `docs/quickstart-gmail.md` and `docs/quickstart-proton-bridge.md`

In each quickstart, add a one-paragraph cross-reference under the audit-config block: "If you plan to run multiple MCP clients against this account, see `docs/audit-log.md#running-multiple-mcp-clients` for the per-client config pattern." No worked examples in the quickstarts; they stay focused on first-time setup.

### 6.3 `README.md`

Add one bullet to the existing troubleshooting section (or create a minimal one if none exists at HEAD): "If `rusty-imap-mcp` exits at startup with `audit file ... is already locked`, see `docs/audit-log.md#running-multiple-mcp-clients`."

## 7. Accepted regressions vs the archived daemon design

These are functionality the daemon design provided that we are *not* providing here. They are accepted, with the explicit understanding that they return when the database-backed audit store lands.

- **Per-account rate limiter is per-process, not per-account-globally.** Two MCP clients against the same IMAP account each get their own `Governor` budget. An attacker controlling the host can in principle multiply the per-account ceiling by spawning N MCP clients. This was the v0 behavior. The daemon's multiplexing fixed it; B1 reintroduces it.
- **Per-account circuit breaker is per-process.** Same shape: a flap visible to one client does not trip the breaker for another client.
- **Provenance ring buffer is per-process.** The ring of recently-read message-IDs that gets attached to `tool_end.provenance.message_ids_recently_read` is scoped to one PID. Sub-agents within the same MCP-client process share the parent's ring; sibling clients do not.
- **Cross-client audit queries.** `audit merge` reads one file. To query across two clients' logs the user runs it twice or pipes through `cat`/`jq`.

## 8. Explicitly deferred

- **Database-backed audit storage** (the user-stated future direction). Replaces the per-file model entirely. Naturally re-enables shared rate limits, cross-client provenance, and cross-client queries.
- **Any IPC alternative** to address the rate-limit regression in the meantime — only if the regression turns out to bite a real user.
- **`audit merge --paths a,b,c`** cross-file glob. Trivial to add later if the deferred database doesn't land first.
- **Re-extracting non-daemon work from `archive/daemon-experiment`.** Tracked as Phase 2 of the rollback (separate work; not in this spec). Includes TLS fingerprint dry-run (#151), mail-parser panic isolation (#201/#212), grapheme-safe truncation (#194), mutation-cleanup waves (#192/#193), ClusterFuzzLite (#202), test-strategy work, deps bumps, etc.

## 9. Testing

- **Unit:** `crates/rimap-audit/src/record/error.rs` already has `locked_message_names_the_path` (line 152). Update its assertion for the new wording. Add a sibling test asserting the message contains the docs anchor token (`docs/audit-log.md#running-multiple-mcp-clients`) so future edits do not silently break the cross-link.
- **Integration:** `crates/rimap-audit/tests/concurrent_lock.rs` asserts on the variant shape (`AuditError::Locked { path: p }`). Should keep passing without change. Verify in implementation.
- No new integration tests required; the runtime behavior is unchanged. The change is text-only.

## 10. Migration / back-compat

No breaking changes. No config schema changes. No CLI changes. No audit record schema changes. Existing single-client deployments are not affected — the lock acquisition path runs identical code; only the error string differs on the failure branch.

Users currently running multiple MCP clients against the same audit path are already failing today; the new error message tells them how to fix their config. No data migration is required.

## 11. Risk and open questions

- **Risk: docs anchor drift.** The error message hard-codes `docs/audit-log.md#running-multiple-mcp-clients`. If the doc heading is renamed, the link in the error rots. Mitigation: the new sibling test asserts the anchor token is present in the error message. A separate (out-of-scope here) docs link-check would catch the doc side; tracked as a future hygiene item.
- **Risk: rate-limit regression bites a real user.** If a user reports per-account ceilings being multiplied by client count, the response is to prioritize the database work, not to revisit the daemon design. Document this stance in the rejected-alternatives section of the database spec when it is written.
- **Open question: README troubleshooting placement.** At HEAD `948a29f` there is no dedicated troubleshooting section in `README.md`. The implementation plan decides whether to create a new section or place the cross-link inline in an existing section.
- **Open question: error message length.** A multi-line error message embedded via `thiserror`'s `#[error(...)]` attribute is unusual. The implementation plan decides whether to keep the multi-line form or compress to a single line with the long-form guidance only in `docs/audit-log.md`. Both options preserve the spec invariant: the error names the path, names the resolution, and points at the docs anchor.

## 12. Lineage

This design replaces the multi-client daemon design at `docs/superpowers/specs/2026-04-22-multi-client-daemon-design.md`, which was implemented (the `multi-client-daemon` PR series #150 through the `polish-pr*` follow-ups #152–#173, the macOS daemon test fix #199, and the Windows Service work #216) and then rolled back. The implemented daemon code is preserved on branch `archive/daemon-experiment` (tip `8895c5a`, pushed to `origin/archive/daemon-experiment`); see `git log 948a29f..archive/daemon-experiment` for the full commit set. Local `main` is at `948a29f` (the pre-daemon STARTTLS merge `Merge pull request #123 from randomparity/feat/imap-starttls`); `origin/main` is left at `8895c5a` pending a separate Phase 2 extraction of non-daemon improvements (TLS fingerprint dry-run #200, mail-parser panic isolation #204/#212, grapheme-safe truncation #197, mutation-cleanup #195/#196/#198, ClusterFuzzLite #202/#203, test-strategy #190/#191, deps bumps, code-health and CI work).
