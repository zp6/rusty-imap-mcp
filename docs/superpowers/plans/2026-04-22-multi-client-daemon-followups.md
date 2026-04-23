# Multi-client daemon — follow-up issues

Captured during and after implementation of the multi-client daemon plan
(`docs/superpowers/plans/2026-04-22-multi-client-daemon.md`). Items 1–16
came from the implementation pass and were filed as #124–#139. Items
17–25 came from a post-landing `/simplify` code-review pass and were
filed as #141–#149.

| # | Title | Issue |
|---|-------|-------|
| 1 | Multi-UID support (scope B) | [#124](https://github.com/randomparity/rusty-imap-mcp/issues/124) |
| 2 | HTTP/SSE listener (scope C1) | [#125](https://github.com/randomparity/rusty-imap-mcp/issues/125) |
| 3 | Socket path config override | [#126](https://github.com/randomparity/rusty-imap-mcp/issues/126) |
| 4 | SIGHUP config reload | [#127](https://github.com/randomparity/rusty-imap-mcp/issues/127) |
| 5 | IMAP connection pool depth > 1 | [#128](https://github.com/randomparity/rusty-imap-mcp/issues/128) |
| 6 | Windows Service (SCM) integration | [#129](https://github.com/randomparity/rusty-imap-mcp/issues/129) |
| 7 | Daemon idle-timeout / lazy-spawn | [#130](https://github.com/randomparity/rusty-imap-mcp/issues/130) |
| 8 | Provenance ring buffer scoping knob | [#131](https://github.com/randomparity/rusty-imap-mcp/issues/131) |
| 9 | Real Windows peer-identity capture | [#132](https://github.com/randomparity/rusty-imap-mcp/issues/132) |
| 10 | Custom DACL on Windows named pipe | [#133](https://github.com/randomparity/rusty-imap-mcp/issues/133) |
| 11 | Shim e2e test: resolver-path harness | [#134](https://github.com/randomparity/rusty-imap-mcp/issues/134) |
| 12 | `process_end.total_tool_calls` aggregator | [#135](https://github.com/randomparity/rusty-imap-mcp/issues/135) |
| 13 | Full Dovecot-backed integration suite | [#136](https://github.com/randomparity/rusty-imap-mcp/issues/136) |
| 14 | `session_end(DaemonShutdown)` for aborted sessions | [#137](https://github.com/randomparity/rusty-imap-mcp/issues/137) |
| 15 | Config path resolution duplication | [#138](https://github.com/randomparity/rusty-imap-mcp/issues/138) |
| 16 | Doc sweep: stale `AccountRegistry.active` refs | [#139](https://github.com/randomparity/rusty-imap-mcp/issues/139) |

## From the post-landing code-review pass

Filed after the `refactor(rimap-server,rimap-audit): code-review cleanup` commit
(0ec1717). The safe + medium findings from that pass landed in-tree; the
architectural findings below are tracked as separate issues.

| # | Title | Issue |
|---|-------|-------|
| 17 | Hoist `RedactionSalt` to `DaemonState` | [#141](https://github.com/randomparity/rusty-imap-mcp/issues/141) |
| 18 | `spawn_blocking` around session_start / session_end writes | [#142](https://github.com/randomparity/rusty-imap-mcp/issues/142) |
| 19 | `ArcSwapOption` for `SessionState.active_account` | [#143](https://github.com/randomparity/rusty-imap-mcp/issues/143) |
| 20 | Parallelize `registry::build` per-account setup | [#144](https://github.com/randomparity/rusty-imap-mcp/issues/144) |
| 21 | Tighten `DaemonState` visibility + narrow `raw_writer` | [#145](https://github.com/randomparity/rusty-imap-mcp/issues/145) |
| 22 | Shared `UlidNewtype<Tag>` for `SessionId` / `ProcessId` | [#146](https://github.com/randomparity/rusty-imap-mcp/issues/146) |
| 23 | Shared `ensure_tight_dir` helper | [#147](https://github.com/randomparity/rusty-imap-mcp/issues/147) |
| 24 | Cache `list_tools` result on `AccountRegistry` | [#148](https://github.com/randomparity/rusty-imap-mcp/issues/148) |
| 25 | `&Map`-taking APIs in `rimap-audit` to avoid arg clone | [#149](https://github.com/randomparity/rusty-imap-mcp/issues/149) |

## From the design spec (§12 — anticipated follow-ups)

### 1. Multi-UID support (scope B) — [#124](https://github.com/randomparity/rusty-imap-mcp/issues/124)

Per-identity posture mapping, socket permissions beyond same-UID,
identity-allowlist config schema. Hooks already in place: peer-identity
capture on accept, `session_start.peer_identity` field, per-session
handler ready to consume identity. Enforcement is currently strict
same-UID on Unix; Windows accepts all (DACL enforces).

### 2. HTTP / SSE listener (scope C1)

Token auth, loopback bind, optional TLS, HTTP-level rate limit. New
`[daemon] listen_http = ...` config section. Daemon grows a
transport-abstraction layer; session/tool-dispatch core unchanged.

### 3. Socket path config override

Optional `daemon.socket_path` config field. Blocks on #1 (primary use
case is multi-UID where predictable paths matter).

### 4. SIGHUP config reload

Rebuild account registry, rotate rate limiters, keep live sessions
attached. Non-trivial because rate-limit counters and breaker state
must be preserved across reload. Daemon currently requires restart to
pick up config changes.

### 5. IMAP connection pool depth > 1 per account

Replace the single `Connection` with a small pool of connections. Gated
on observed contention — `Connection`'s internal single-session mutex
serializes all operations today.

### 6. Windows Service (SCM) integration

Proper `ServiceMain`, `SERVICE_STATUS`, stop-handler. Supersedes the
v1 Task Scheduler registration script.

### 7. Daemon idle-timeout / lazy-spawn

Revisit only if the user-started (`systemctl --user enable --now`)
workflow proves friction.

### 8. Provenance ring buffer scoping knob

Per-daemon today; revisit if forensics want tighter granularity.

## Discovered during implementation

### 9. Real Windows peer-identity capture

Task 11 ships a placeholder `PeerIdentity::Windows { sid: "S-unknown",
pid: 0 }` because workspace `unsafe_code = "forbid"` blocks the Win32
FFI needed for `GetNamedPipeClientProcessId` + `OpenProcess` +
`OpenProcessToken` + `GetTokenInformation` + `ConvertSidToStringSidW`.

Two viable approaches: (a) quarantine the FFI in a separate
`rimap-win32-identity` support crate with its own `unsafe_code =
"allow"` exception, or (b) a crate-level `#![deny(unsafe_code)]` +
`#[expect(unsafe_code, reason = "...")]` on the FFI blocks inside
`rimap-server`. Approach (a) is cleaner — keeps workspace-wide
`forbid(unsafe_code)` intact and contains the FFI blast radius.

### 10. Custom DACL for scope B on Windows

Task 11's `create_server_instance` uses tokio's default
`SECURITY_ATTRIBUTES` (creator-only access). Scope B needs an explicit
DACL built via `SetSecurityInfo` / `SetEntriesInAcl`, also requiring
unsafe FFI — same quarantine options as item 9.

### 11. Shim end-to-end test with resolver-path harness alignment

Task 28 deferred the shim-via-binary happy-path test because it requires
the `TestDaemon` harness to bind at the resolver's path
(`$XDG_RUNTIME_DIR/rusty-imap-mcp/daemon.sock`) rather than a tempdir,
so the shim subprocess can independently resolve the same path. Either
align the harness with the resolver via `XDG_RUNTIME_DIR` override, or
extend the shim to accept a socket-path argument for tests.

### 12. `process_end.total_tool_calls` aggregator

`daemon_main` in `main.rs` emits `process_end` with `total_tool_calls: 0`
as a placeholder. Each session has its own `AtomicU64` counter
(`SessionState::tool_call_count`, bumped per tool-call attempt inside
`run_with_audit_envelope`) that feeds `session_end` correctly, but
summing into `process_end` requires either a daemon-level atomic counter
(incremented by each session as it ends) or a snapshot across all active
sessions at shutdown time.

### 13. Full Dovecot-backed integration test suite

Phase 5 of the original plan called for 9 integration tests; only 4
landed because `boot::registry::build` calls `resolve_special_use`
(real IMAP connect) and the test harness cannot spawn the full
production boot path without a live IMAP server. The repo already has
a Dovecot-backed fixture under `crates/rimap-imap/tests/integration/`
gated behind `RIMAP_REQUIRE_DOCKER=1`; extend that to cover daemon
session + rate-limit-sharing + breaker-sharing scenarios.

Specifically deferred tests: rate-limit sharing (T23), breaker sharing
(T24), peer-UID rejection end-to-end (T25 — unit-tested at the gate
function level), second-daemon-fails-fast (T26 — unit-tested at
`UnixSocketListener::bind`), Windows-specific named-pipe tests (T29).

### 14. `session_end(DaemonShutdown)` for aborted sessions

During graceful shutdown, `drain_sessions` in `daemon/run.rs` calls
`sessions.shutdown().await` after the 5 s deadline, aborting any tasks
still in flight. Those aborted futures never reach `emit_session_end`,
so the audit log is missing `session_end(reason=DaemonShutdown)` records
for sessions aborted mid-flight — violating design spec §6.5's contract
that "each [session] emits `session_end` with
`reason = 'daemon_shutdown'`".

Fix: track active session metadata (start time, session ID) in a
separate structure outside the `JoinSet` so the shutdown path can emit
a synthetic `session_end` for any session aborted mid-flight.

### 15. Config path resolution duplication

`daemon_main` in `main.rs` (line 123) inlines `config_override
.or_else(|| resolve_config_path(None)).ok_or_else(...)` directly, while
`resolve_cli_config_path` (line 197) contains the same pattern for the
non-daemon path. Extract a shared helper
`resolve_or_default(override: Option<PathBuf>) -> anyhow::Result<PathBuf>`
and have both call sites use it.

### 16. Doc-sweep: old spec references to removed `AccountRegistry.active`

`docs/superpowers/specs/2026-04-13-sprint-3-design.md` (lines 206, 214)
still describe `registry.active` as "session-scoped active account".
Task 15 removed that field; these spec pages reference implementation
details that no longer exist. A single docs-sweep commit would update or
explicitly mark these sections as historical.

## From the review-remediation pass

Filed during the multi-client-daemon review-remediation plan
(`docs/superpowers/plans/2026-04-23-daemon-review-remediation.md`). These
squatter-class hazards surfaced while documenting the trust-boundary
subsection and were too scoped for the in-flight remediation plan.

### 26. Unix atomic-rename bind defends pre-binding squatter  `LOCAL-FS-05`

A same-UID attacker can `bind()` the daemon socket path between the
`unlink` of a stale socket and our own `bind()`. Because the peer gate
applies to *clients* (connections inbound to the daemon), a squatter that
becomes the listener is undetected. Fix: `bind()` a temp name in the same
directory, then `rename(2)` atomically onto the target path. Or take a
`flock` on a lockfile adjacent to the socket before `bind`.

Related review finding: threat-model §7, local-security Minor M5.
Priority: Important (same-UID is trusted today, but multi-user scope B
depends on this being airtight).

### 27. Windows named-pipe `FILE_FLAG_FIRST_PIPE_INSTANCE`  `LOCAL-OS-*`

The current Windows transport uses `tokio::net::windows::named_pipe::ServerOptions`
defaults; verify (or enforce) that `first_pipe_instance(true)` is set so
a squatter cannot create the pipe name ahead of the daemon and siphon
shim connections. Without `FILE_FLAG_FIRST_PIPE_INSTANCE`, the first
process to create the pipe name wins. See
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew

Related review finding: threat-model §8.
Priority: Important.

---

*See the individual task reports in the PR's commit log for full context.*
