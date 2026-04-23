# Polish release — post-daemon cleanup

Ship-16-issues plan targeting correctness, code quality, and test-infrastructure
gaps identified during and after the multi-client daemon merge (PR #150). No new
features. No scope expansion.

## Goals

1. Close all bug-labeled and doc-mismatch issues filed against the freshly-merged
   daemon work.
2. Land the 9 code-review follow-ups from the post-merge `/simplify` pass
   (#141–#149).
3. Complete the two test-infrastructure items that were deferred during the
   daemon implementation (#134, #136).
4. Explicitly defer the 12 scope-expansion, platform, and ergonomic items with
   documented rationale.

## Non-goals

- Scope B (multi-UID), scope C1 (HTTP/SSE), scope C2 (remote clients).
- Windows FFI work (peer-identity, DACL, SCM service). These need a dedicated
  plan that extracts unsafe code into a quarantined crate.
- IMAP connection pool depth > 1. Gated on observed contention.
- Daemon idle-timeout / lazy-spawn. Revisit only if user-started workflow
  proves friction.
- New features of any kind.

## In-scope issues (16)

### Bugs / docs (4)

| Issue | Title | Why it's in |
|-------|-------|-------------|
| [#117](https://github.com/randomparity/rusty-imap-mcp/issues/117) | `--dry-run`: add TLS preflight + CAPABILITY check to match documented behavior | Docs claim behavior the code doesn't implement |
| [#135](https://github.com/randomparity/rusty-imap-mcp/issues/135) | `process_end.total_tool_calls` aggregator (currently emits 0) | Bug: audit record always shows 0 |
| [#137](https://github.com/randomparity/rusty-imap-mcp/issues/137) | `session_end(DaemonShutdown)` missing for sessions aborted during 5s drain | Bug: design-spec contract violated on graceful shutdown |
| [#139](https://github.com/randomparity/rusty-imap-mcp/issues/139) | Doc sweep: stale `AccountRegistry.active` references in old spec | Docs contradict the code after task-15 of the daemon work |

### Code-review cleanups (9)

| Issue | Title |
|-------|-------|
| [#141](https://github.com/randomparity/rusty-imap-mcp/issues/141) | Hoist `RedactionSalt` from per-session to `DaemonState` |
| [#142](https://github.com/randomparity/rusty-imap-mcp/issues/142) | Move `log_session_start` / `log_session_end` onto `spawn_blocking` |
| [#143](https://github.com/randomparity/rusty-imap-mcp/issues/143) | Replace `RwLock<Option<AccountId>>` on `SessionState` with `ArcSwapOption` |
| [#144](https://github.com/randomparity/rusty-imap-mcp/issues/144) | Parallelize `registry::build` per-account setup |
| [#145](https://github.com/randomparity/rusty-imap-mcp/issues/145) | Tighten `DaemonState` field visibility + narrow `raw_writer` accessor |
| [#146](https://github.com/randomparity/rusty-imap-mcp/issues/146) | Share a `UlidNewtype<Tag>` macro/helper for `SessionId` + `ProcessId` |
| [#147](https://github.com/randomparity/rusty-imap-mcp/issues/147) | Share `ensure_tight_dir` helper between `socket_setup` and audit writer |
| [#148](https://github.com/randomparity/rusty-imap-mcp/issues/148) | Cache `list_tools` result as `Arc<Vec<Tool>>` on `AccountRegistry` |
| [#149](https://github.com/randomparity/rusty-imap-mcp/issues/149) | Avoid full arg-map clone in audit envelope: accept `&Map` in redact / hash APIs |

### Test infrastructure (2)

| Issue | Title |
|-------|-------|
| [#134](https://github.com/randomparity/rusty-imap-mcp/issues/134) | Shim end-to-end test: align harness with resolver path |
| [#136](https://github.com/randomparity/rusty-imap-mcp/issues/136) | Full Dovecot-backed integration test suite for daemon scenarios |

### Small refactor (1)

| Issue | Title |
|-------|-------|
| [#138](https://github.com/randomparity/rusty-imap-mcp/issues/138) | Config path resolution: deduplicate `daemon_main` and `resolve_cli_config_path` (`good first issue`) |

## Deferred issues (12) — explicit rationale

| Issue | Title | Deferral rationale |
|-------|-------|--------------------|
| [#105](https://github.com/randomparity/rusty-imap-mcp/issues/105) | Wire LIST-STATUS extended LIST | Blocked on `async-imap` upstream |
| [#107](https://github.com/randomparity/rusty-imap-mcp/issues/107) | Wire COPYUID capture | Blocked on `async-imap` upstream exposing `ResponseCode::CopyUid` |
| [#124](https://github.com/randomparity/rusty-imap-mcp/issues/124) | Multi-UID daemon support (scope B) | Scope expansion — needs its own spec |
| [#125](https://github.com/randomparity/rusty-imap-mcp/issues/125) | HTTP/SSE listener (scope C1) | Scope expansion — needs its own spec |
| [#126](https://github.com/randomparity/rusty-imap-mcp/issues/126) | Socket path configuration override | Primary use case is multi-UID (#124); defer with #124 |
| [#127](https://github.com/randomparity/rusty-imap-mcp/issues/127) | SIGHUP config reload | Ergonomic — non-trivial (rate-limit state preservation). Revisit post-polish |
| [#128](https://github.com/randomparity/rusty-imap-mcp/issues/128) | IMAP connection pool depth > 1 | Gated on observed contention |
| [#129](https://github.com/randomparity/rusty-imap-mcp/issues/129) | Windows Service (SCM) integration | Needs unsafe-FFI quarantine crate — own plan |
| [#130](https://github.com/randomparity/rusty-imap-mcp/issues/130) | Daemon idle-timeout / lazy-spawn | Revisit only if user-started workflow proves friction |
| [#131](https://github.com/randomparity/rusty-imap-mcp/issues/131) | Provenance ring buffer scoping knob | Revisit if forensics want tighter granularity |
| [#132](https://github.com/randomparity/rusty-imap-mcp/issues/132) | Real Windows peer-identity capture | Needs unsafe-FFI quarantine crate — own plan |
| [#133](https://github.com/randomparity/rusty-imap-mcp/issues/133) | Custom DACL on Windows named pipe for scope B | Blocks on #124 + unsafe-FFI quarantine |

## PR structure (12 PRs)

File-overlap forces coupling in three groups; the remaining 9 PRs are
independent.

### Merged PRs (file-overlap driven)

**PR 1 — `daemon/state.rs` cleanup (#141 + #143 + #145)**

- Files: `crates/rimap-server/src/daemon/state.rs`,
  `crates/rimap-server/src/mcp/server.rs`
- Three coupled changes on the same struct:
  - Hoist `RedactionSalt` from per-session onto `DaemonState` (#141) — one
    random salt for the daemon lifetime rather than per-accept.
  - Replace `SessionState.active_account: RwLock<Option<AccountId>>` with
    `arc-swap::ArcSwapOption<AccountId>` (#143) — removes a pointless async
    lock on a single-writer field.
  - Tighten `DaemonState` field visibility to `pub(crate)` and narrow the
    `raw_writer` accessor (#145).
- Acceptance criteria:
  - `RedactionSalt::new_random()` called exactly once in `DaemonState::new`.
  - `active_account` reads/writes are `compare_and_swap` / `load_full`, no
    `.await`.
  - No public fields on `DaemonState`; `raw_writer` exposed only where needed.
  - Existing `dispatch_ticket`, `daemon_happy_path` tests continue to pass.
- Rollback risk: low. Three mechanical changes on one struct.

**PR 2 — Session-end reliability (#137 + #142)**

- Files: `crates/rimap-server/src/daemon/run.rs`,
  `crates/rimap-server/tests/daemon_graceful_shutdown.rs`
- Two coupled changes on the session-end path:
  - Move `log_session_start` / `log_session_end` onto `spawn_blocking` (#142)
    to keep audit writes off the async accept loop.
  - Fix `session_end(DaemonShutdown)` emission for sessions aborted during
    the 5s graceful drain (#137). `drain_sessions` must issue `session_end`
    for every tracked session before `JoinSet::shutdown().await`; the fix
    must await the `spawn_blocking` introduced in #142.
- Acceptance criteria:
  - New test: graceful shutdown with N active sessions produces N
    `session_end(reason=DaemonShutdown)` records in the audit log.
  - Existing `daemon_graceful_shutdown` test extended to assert the count.
  - No regression in `daemon_happy_path` / `daemon_max_sessions` timing.
- Rollback risk: medium. Graceful-shutdown path is concurrency-sensitive.
  Mitigated by the new test.

**PR 3 — Registry perf (#144 + #148)**

- Files: `crates/rimap-server/src/boot/registry.rs`,
  `crates/rimap-server/src/mcp/server.rs`
- Two coupled perf changes in `AccountRegistry::build`:
  - Parallelize per-account setup using `futures::future::join_all` over the
    `multi.accounts` loop (#144). `resolve_special_use` does network I/O per
    account — currently serialized.
  - Cache `list_tools` result as `Arc<Vec<Tool>>` on `AccountRegistry` (#148)
    since output depends only on registered accounts, not session state.
- Acceptance criteria:
  - Startup with N accounts runs account setup concurrently (verify via
    tracing spans in tests).
  - `list_tools` returns the same `Arc<Vec<Tool>>` across calls within a
    registry generation.
  - No behavioral change for `use_account` / `tools/list_changed` semantics.
- Rollback risk: low. Both changes are pure perf; behavior unchanged.

### Standalone PRs

**PR 4 — Shared `UlidNewtype<Tag>` helper (#146)**

- Files: `crates/rimap-core/src/session.rs`,
  `crates/rimap-audit/src/record/ids.rs`, likely a new module in
  `rimap-core` or `rimap-audit` for the shared helper.
- A declarative macro (`ulid_newtype!`) or a generic `UlidNewtype<T>` type
  covers both `SessionId` and `ProcessId`.
- Acceptance criteria:
  - Both types defined via the shared helper.
  - Public API of both types unchanged (`Display`, `FromStr`, `new`,
    `new_now`, `Default`, `#[serde(transparent)]`).
  - No duplicated bodies between the two files.
- Rollback risk: low. Structural change with identical behavior.

**PR 5 — Shared `ensure_tight_dir` helper (#147)**

- Files: `crates/rimap-server/src/daemon/socket_setup.rs`,
  `crates/rimap-audit/src/writer/mod.rs`, new shared location (likely
  `rimap-audit` since it's the lower-level crate).
- The TOCTOU-safe version from `socket_setup` becomes the shared
  implementation. `set_parent_mode_0700` in the audit writer calls it.
- Acceptance criteria:
  - Single implementation covers both call sites.
  - Symlink-refusal and uid-check enforcement applied to the audit writer
    path (strictly tighter than before — catches a previously-ignored
    symlink hazard).
  - Existing socket-path and audit-writer tests pass.
- Rollback risk: low-medium. The audit writer now rejects more edge cases
  (symlinks); confirm no legitimate setup was relying on symlinked audit
  dirs.

**PR 6 — `&Map`-taking APIs in audit envelope (#149)**

- Files: `crates/rimap-server/src/mcp/audit_envelope.rs`,
  `crates/rimap-audit/src/` (redact, hash APIs).
- Change `Redactor::apply` and `hash_arguments` to accept
  `&serde_json::Map<String, Value>` directly. Eliminates the per-tool-call
  `Value::Object(args.clone())` deep-clone.
- Acceptance criteria:
  - No `Value::Object(args.clone())` wrapper in `run_with_audit_envelope`.
  - Redact and hash outputs byte-identical to current behavior
    (property test or fixture comparison).
  - No public API breakage for external users of `rimap-audit` (check
    re-exports).
- Rollback risk: low.

**PR 7 — `process_end.total_tool_calls` aggregator (#135)**

- Files: `crates/rimap-server/src/main.rs`,
  `crates/rimap-server/src/daemon/state.rs` (aggregator counter).
- Add a daemon-level `AtomicU64` incremented in `emit_session_end`;
  `daemon_main` reads it for `process_end.total_tool_calls`.
- Acceptance criteria:
  - New test: N sessions each making M tool calls yields `total_tool_calls
    = N * M` in `process_end`.
  - Existing per-session `session_end.tool_call_count` untouched.
- Rollback risk: low.

**PR 8 — `--dry-run` TLS+CAPA preflight (#117)**

- Files: `crates/rimap-server/src/cli/dry_run.rs`, likely
  `crates/rimap-imap/src/connection.rs` for a capability-inspection
  helper if one doesn't exist.
- Make `--dry-run` actually perform a TLS handshake and `CAPABILITY`
  command per account, printing the TLS fingerprint and capability list
  as the docs claim.
- Acceptance criteria:
  - `--dry-run` against Mailpit fixture prints server capabilities and
    TLS fingerprint.
  - Doc pages (`docs/quickstart-gmail.md`, `docs/quickstart-proton-bridge.md`)
    no longer overstate behavior.
  - New test: `--dry-run` against a reachable fixture succeeds; against an
    unreachable host fails with a clear error.
- Rollback risk: low. New behavior, opt-in via the existing flag.

**PR 9 — Doc sweep (#139)**

- Files: `docs/superpowers/specs/2026-04-13-sprint-3-design.md` (or other
  stale specs identified during the sweep).
- Remove / update references to the removed `AccountRegistry.active`
  field; point at `SessionState.active_account` instead.
- Acceptance criteria:
  - `rg 'registry\.active'` returns zero hits in docs (outside of historic
    context notes with explicit "superseded" markers).
- Rollback risk: none (docs only).

**PR 10 — Config-path DRY (#138)**

- Files: `crates/rimap-server/src/main.rs` (possibly a new small module
  `cli/config_path.rs`).
- Extract `resolve_or_default(override_: Option<PathBuf>) -> Result<PathBuf>`
  used by both `daemon_main` and non-daemon subcommands.
- Acceptance criteria:
  - Single helper; both call sites updated.
  - Existing CLI tests pass without modification.
- Rollback risk: none. Pure mechanical refactor (`good first issue`).

### Test-infra PRs

**PR 11 — Shim e2e resolver-path harness (#134)**

- Files: `crates/rimap-server/tests/common/daemon_harness.rs`,
  `crates/rimap-server/tests/shim_*.rs`, possibly
  `crates/rimap-server/src/daemon/socket_path.rs` (env-var hook).
- `TestDaemon` either (a) binds at the path the resolver produces under a
  controlled `$XDG_RUNTIME_DIR`/`$TMPDIR` or (b) the shim grows a
  test-only `RIMAP_DAEMON_SOCKET` env var. Option (a) preferred.
- Acceptance criteria:
  - New test: happy-path `mcp/initialize` → `tools/list` → `tools/call` →
    clean exit via the actual shim binary.
  - No production code path changes (or one carefully-scoped env-var
    hook, cfg-gated).
- Rollback risk: low. Tests only, or a narrowly-scoped production hook.

**PR 12 — Dovecot-backed daemon integration suite (#136)**

- Files: `crates/rimap-server/tests/daemon_*_live.rs` (new), possibly
  extensions to `crates/rimap-imap/tests/integration/common/` fixtures.
- Build on the existing Dovecot fixture under
  `crates/rimap-imap/tests/integration/`. Gate new tests behind
  `RIMAP_REQUIRE_LIVE_IMAP=1`.
- Five target scenarios (from phase 5 of the daemon plan): graceful
  shutdown under load, max-sessions enforcement, audit completeness under
  failures, peer-identity capture round-trip, shim reconnect after daemon
  restart.
- Acceptance criteria:
  - Five new tests under the `RIMAP_REQUIRE_LIVE_IMAP` gate.
  - CI job invokes them against the Dovecot fixture.
  - Documentation in the test file(s) explains what each scenario covers.
- Rollback risk: low. Test-only additions. Larger scope — may land in
  multiple sub-PRs if review bandwidth is tight.

## Sequencing

Four waves. Within a wave, PRs are parallelizable; between waves, later
waves depend on earlier ones.

**Wave A — low-risk, no cross-deps:**

- PR 9 (doc sweep)
- PR 7 (`process_end` aggregator)
- PR 8 (`--dry-run` TLS+CAPA)
- PR 10 (config-path DRY)

**Wave B — code-review cleanups:**

- PR 1 (`daemon/state.rs` cleanup)
- PR 4 (`UlidNewtype` helper)
- PR 5 (`ensure_tight_dir` helper)
- PR 6 (`&Map` audit APIs)

**Wave C — depends on wave B:**

- PR 2 (session-end reliability) — aligns with PR 6's audit-API changes
  and PR 1's `DaemonState` shape
- PR 3 (registry perf) — expects PR 1's `DaemonState` visibility

**Wave D — test infra:**

- PR 11 (shim e2e)
- PR 12 (Dovecot suite)

Waves D and C are order-independent and can run in parallel with each
other once wave B lands.

## Verification

Every PR must pass before merge:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --workspace` (unit + integration tests that don't require
  live IMAP)
- `cargo deny check` where dependencies change (#144, #146 may pull in
  `futures` or `arc-swap` if not already present)

PRs introducing new behavior (#117, #134, #135, #136, #137) must include
a test that fails before the change and passes after. Pure-refactor PRs
(#138, #139, #141, #143, #144, #145, #146, #147, #148, #149) rely on
existing tests to prove behavior preservation — if a test breaks, the
refactor is wrong.

The polish release is "done" when all 12 PRs are merged to `main` and
all 16 issues are closed.

## Merge policy

- One PR per day on Wave A / B items is the realistic throughput target.
- Wave C and D PRs may need multiple days each.
- No release-branch tag. Polish items land on `main` incrementally; if a
  tagged release is wanted at the end, it can happen as a separate,
  mechanical step after PR 12 merges.

## Risks

- **#137 + #142 interaction** (PR 2) is the highest-risk item. The
  graceful-shutdown drain path is concurrency-sensitive. Mitigation: the
  new test asserting N session_end records is mandatory before merge.
- **#147** (PR 5) adds symlink-refusal to a path that previously
  tolerated symlinks. If any user setup scripts symlink the audit dir,
  they will break. Mitigation: document in CHANGELOG; confirm the
  project's own packaging scripts (systemd unit, launchd plist) create
  real directories.
- **#144** (PR 3) changes the failure mode of startup — one account
  failing no longer stops the others from setting up. Confirm the
  existing error-handling policy still matches expectations (fail-fast
  vs. partial registry).

## References

- `docs/superpowers/plans/2026-04-22-multi-client-daemon-followups.md` —
  narrative registry of items 1–25 (what exists, why). This plan
  sequences a subset of those items plus the four bug-labeled issues
  (#117, #135, #137, #139) and `good first issue` #138.
- `docs/superpowers/specs/2026-04-22-multi-client-daemon-design.md` —
  design spec for the daemon work that introduced most of these
  follow-ups.
- `docs/superpowers/plans/2026-04-22-multi-client-daemon.md` — the
  original implementation plan (tasks 28, 29, phase 5 tests) whose
  deferrals are closed out by PRs 2, 3, 11, 12.
