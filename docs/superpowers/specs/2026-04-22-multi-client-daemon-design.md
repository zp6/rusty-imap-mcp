# Multi-client daemon — design

Issue: (file on merge)
Target crates: `rimap-server` (large), `rimap-audit` (record types), `rimap-core` (newtype), `rimap-imap` (connection wrapping)
Related: spec §10 "File handling & locking" in `2026-04-07-rusty-imap-mcp-design.md`; `crates/rimap-audit/src/writer/mod.rs:127` (`try_lock_exclusive`); `crates/rimap-server/src/main.rs:124` (stdio transport); `crates/rimap-server/src/boot/registry.rs:85` (session-scoped active account).

## 1. Problem

`rusty-imap-mcp` enforces a hard "one process per audit path" invariant via `fs4::FileExt::try_lock_exclusive`. A user running two MCP clients (two Claude Code windows, Claude + Codex, etc.) on the same account fails to start the second server with `audit file already locked`. Today's MCP transport is stdio, so each MCP client spawns its own child process — the lock collides immediately.

The invariant is load-bearing: the audit log chains `process_start` → `process_end` via `previous_last_seq` + `previous_process_id`, uses inode identity for tamper detection, holds an in-memory provenance ring buffer scoped to process lifetime, and relies on a single rate-limiter / circuit-breaker instance to enforce abuse ceilings. Naively relaxing the lock would corrupt several security invariants simultaneously.

Scope A for this change: **same-user, multiple local MCP clients**. Multi-UID (B) and remote / HTTP (C1) are deferred, but the design is shaped so they land incrementally.

## 2. Goals

- Let multiple MCP clients on the same machine, running as the same user, share one `rusty-imap-mcp` backend without fighting for the audit lock.
- Preserve every audit invariant from the v1 spec §10 literally: still one writer, still inode chaining, still tamper detection.
- Improve abuse-protection: per-account rate limiting is enforced across all clients on that account (today two processes can split the budget).
- Keep per-client session state isolated: one Claude window selecting `use_account("work")` does not change another window's active account.
- Single-binary packaging; no new artifact on disk.
- Cross-platform parity: Linux, macOS, Windows. Windows supported from day one via named pipes.
- Position for scope B (multi-UID) and scope C1 (HTTP/SSE transport) without preemptively implementing them.

## 3. Non-goals

- HTTP, SSE, TCP, or any non-local transport (scope C1 — follow-up issue).
- Cross-UID access, per-identity posture mapping (scope B — follow-up issue).
- Lazy-spawn daemon lifecycle, idle auto-shutdown. The daemon is user-started via systemd / launchd / Task Scheduler and runs until SIGTERM.
- IMAP connection pool depth > 1 per account. Sessions targeting the same account serialize behind a mutex for v1.
- SIGHUP / config-reload.
- Windows Service (SCM) integration. Task Scheduler script ships for v1.
- Retaining the pre-daemon bare `rusty-imap-mcp` stdio invocation. Project is pre-1.0; replaced, not deprecated.

## 4. Architecture

One binary, subcommands replace the bare invocation:

```
┌──────────────┐   stdio/MCP    ┌───────────────────────┐   unix sock /    ┌──────────────────────────┐
│ MCP client   │ ─────────────► │ rusty-imap-mcp shim   │ ─────named pipe► │ rusty-imap-mcp daemon    │
│ (Claude etc.)│                │  (child process)      │                   │ (long-running singleton) │
└──────────────┘                └───────────────────────┘                   │ audit │ IMAP │ authz     │
                                                                            └───────┼───────┼──────────┘
                                                                                    ▼       ▼
                                                                                  fs    network
```

- `rusty-imap-mcp daemon` — foreground, long-running. Binds the platform socket, accepts connections, spawns one `rmcp::serve_server` task per accepted stream. Owns the audit writer, the per-account registry, rate limiters, credential store, the fs-lock on the audit file.
- `rusty-imap-mcp shim` — tiny stdio↔socket adapter. Connects once; byte-pipes stdin→socket and socket→stdout until EOF. No MCP awareness.
- `rusty-imap-mcp login`, `migrate-keyring`, `audit merge`, `--dry-run` — unchanged.
- Bare `rusty-imap-mcp` prints help and exits non-zero. The v0 stdio server mode is removed.

The audit fs-lock still guards the daemon itself — the lock semantics do not change. What changes is that the *lockholder* (the daemon) now multiplexes many MCP clients instead of servicing exactly one stdio pair.

### 4.1 Trust Boundaries

The daemon introduces one new trust boundary relative to the pre-daemon
stdio-per-client model: the shim↔daemon local socket.

| Boundary | Trusted side | Untrusted side | Auth | Failure mode |
|----------|--------------|----------------|------|--------------|
| shim ↔ daemon (Unix) | daemon (holds IMAP creds) | any local process reaching the socket | `SO_PEERCRED` UID match against `geteuid()` | `session_end(reason=peer_uid_rejected)`; stream dropped |
| shim ↔ daemon (Windows v1) | daemon | any local process reaching the pipe | Pipe DACL (default-owner-only); **peer identity is a placeholder, see §9.2 and follow-up #132** | pipe ACL refusal at `CreateFile` |

Attacker classes this boundary defends against:
- **local-malware-same-uid**: Already trusted by the project-wide threat model
  (§1 of the v2 spec). Same-UID processes can run arbitrary code as the user,
  including stopping/restarting the daemon and reading the keyring; the daemon
  does not attempt to defend against this.
- **co-tenant-different-uid**: Defended by UID gate (Unix) and pipe DACL
  (Windows). A different-UID process that reaches the socket path is refused
  at `peer_cred()` and logged.
- **pre-binding-squatter**: A same-UID attacker that `bind()`s the socket
  path before the daemon is **partially defended** today (symlink refusal
  at the socket path; see commit history for C3 fix) and **not fully defended**
  for the atomic-rename case (see follow-up #26).

Bytes arriving on the socket are treated as attacker-controlled until the
peer-UID gate fires. After the gate, the session is trusted to the extent
the project-wide threat model already trusts the local user.

## 5. Components

### 5.1 `rimap-core` — `SessionId`

`SessionId` is a ULID (`ulid::Ulid` crate, `features = ["serde"]`).
Lexicographically sortable and monotonic within a process via the crate's
default generator. Serialized as the 26-character Crockford-base32 form.
`Copy`, `Eq`, `Hash`, `Serialize`, `Deserialize`. Cannot be forged from `None`; the per-session handler receives a `SessionId` value and has no API for `Option<SessionId>`.

### 5.2 `rimap-audit` — record types

New record kinds `session_start` and `session_end`.

`session_start` fields: `seq`, `ts`, `process_id` (daemon's), `session_id`, `peer_identity`, `socket_path` (resolved absolute path / pipe name).

`session_end` fields: `seq`, `ts`, `process_id`, `session_id`, `reason: SessionEndReason` (`eof` | `error` | `daemon_shutdown` | `peer_uid_rejected`), `duration_ms`, `total_tool_calls` (per-session), `last_error` (only when `reason = error`).

`peer_identity` is a tagged enum covering both platforms:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum PeerIdentity {
    Unix { uid: u32, pid: i32 },
    Windows { sid: Option<String>, pid: Option<u32> },
}
```

The `Windows` variant uses `Option` for both fields to reflect the v1
placeholder behavior (see §9.2 note and follow-up #132): identity capture
is not yet wired, so shipped records carry `sid: None, pid: None` and the
pipe DACL is the sole UID gate. Scope B will populate both fields.

`tool_start`, `tool_end`, and `auth` gain `session_id: Option<SessionId>`. The field is `Option` at the record / JSON level because `auth` legitimately fires during daemon-boot IMAP bootstrap (e.g. `resolve_special_use` login) before any session exists. However, the *in-session* call sites are structurally prevented from forgetting the field: the per-session handler exposes a typed wrapper (`SessionAuditSink`) that injects `session_id` automatically, and session-scoped tool code has no API to emit an audit record without going through it. Daemon-level emitters (`process_start`, `process_end`, boot-time `auth`, `cancellation` drain without session context) use the raw `AuditWriter` and leave the field `None` — this is a small, well-defined set of call sites.

`process_start` and `process_end` are **unchanged in shape**. One pair per daemon lifetime. `previous_last_seq` / `previous_process_id` / `previous_file_inode` chaining works literally.

### 5.3 `rimap-imap` — no code change required

`Connection` is already `#[derive(Clone)]`, internally `Arc<ConnectionInner>`, and holds an internal `tokio::sync::Mutex<Option<ImapSession>>` that serializes every operation (`connection.rs:94-124`, and the doc comment on `Connection::session()` at line 176). Multiple sessions can hold `Connection` references concurrently; their IMAP commands will naturally serialize on the existing internal mutex. No outer wrapper is introduced — doing so would double-lock.

The only change is in the owning layer: `AccountRegistry` becomes `Arc`-shared at daemon boot so that every `PerSessionHandler` carries a reference without cloning the whole registry. Tool dispatch signatures (`&Connection` today) are preserved literally.

### 5.4 `rimap-authz` — shared governors

No code change. `Governor` and `CircuitBreaker` are cloned into shared `Arc`s at daemon boot; per-account instances are reused across all sessions. The v1 per-process-per-account pattern in `main.rs:256-273` becomes per-daemon-per-account.

### 5.5 `rimap-server` — new structure

New module tree under `crates/rimap-server/src/`:

```
daemon/
├── mod.rs          # DaemonState, top-level entry
├── transport.rs    # cfg-gated PlatformListener / PlatformStream
├── transport/
│   ├── unix.rs     # #[cfg(unix)]    UnixListener, UnixStream, peer_cred
│   └── windows.rs  # #[cfg(windows)] NamedPipe server, DACL, GetNamedPipeClientProcessId
├── session.rs      # PerSessionHandler, SessionState
├── shutdown.rs     # SIGTERM/SIGINT handling, session draining
└── socket_path.rs  # XDG / TMPDIR / named-pipe resolution
shim/
└── mod.rs          # connect + dual tokio::io::copy loops
```

`ImapMcpServer` stays in `mcp/server.rs`; it grows a per-session wrapper `PerSessionHandler` that holds `Arc<DaemonState>` + `SessionId` + `SessionState`. `DaemonState` contains the shared `AccountRegistry`, `AuditWriter`, cancellation channel sender. `SessionState` contains `active_account: RwLock<Option<AccountId>>` and in-flight cancellation tokens.

`main.rs` retains CLI dispatch only; the body of today's `run()` moves into `daemon::run()`. The MCP transport line (`main.rs:124`, `rmcp::transport::io::stdio()`) is removed — daemon path uses per-connection transports, shim path uses stdio at the shim-process boundary.

## 6. State lifecycle and data flow

### 6.1 Daemon boot (`rusty-imap-mcp daemon`)

1. `logging::init()`, CLI parse, `load_and_validate(config)`.
2. `AuditWriter::open(audit_path)` acquires the exclusive fs-lock. Second daemon against the same audit path fails here with the existing `AuditError::Locked` error. Error message updated to point at `systemctl --user status rusty-imap-mcp` / `launchctl list com.rusty-imap-mcp` / Task Scheduler entry.
3. Build `AccountRegistry`: per account, resolve credentials, open `Connection`, discover special-use folders, build `FolderGuard`, construct per-account `Governor` and `CircuitBreaker`. Wrap `Connection` in `Arc<tokio::sync::Mutex<_>>`; `Arc`-clone governor and breaker.
4. Resolve attachment `download_dir` (unchanged).
5. Resolve socket / named-pipe path (see §9 for platform specifics). Create parent directory with tight permissions; handle stale-socket recovery.
6. `AuditWriter::log_process_start` (unchanged plumbing — chains via inode + previous seq).
7. `PlatformListener::bind()`. Install SIGTERM / SIGINT (Unix) or Ctrl-Break (Windows) handlers that set a `tokio::sync::Notify` shutdown signal.
8. Accept loop: on each accepted stream, read peer identity. If peer identity ≠ our own, emit paired `session_start` + `session_end(reason=peer_uid_rejected)` and close. Otherwise generate `SessionId`, emit `session_start` with identity, and `tokio::spawn` `rmcp::serve_server(PerSessionHandler::new(Arc::clone(&daemon_state), session_id), stream_transport)`.

### 6.2 Client connect (`rusty-imap-mcp shim`)

1. Resolve socket path (same logic as daemon). `UnixStream::connect(path)` on Unix; `ClientOptions::new().open(path)` on Windows with bounded `ERROR_PIPE_BUSY` retry (3 attempts, 100 ms each).
2. On failure (`ENOENT`, `ECONNREFUSED`, `ERROR_FILE_NOT_FOUND`): exit 1 with an actionable stderr message naming the expected path and the platform-appropriate start command.
3. Spawn two `tokio::io::copy` tasks: `stdin → socket.write_half`, `socket.read_half → stdout`. Exit 0 when either direction closes.
4. The shim is MCP-oblivious. The daemon speaks full MCP over the socket.

### 6.3 Tool call

1. `rmcp` delivers a tool call to `PerSessionHandler`.
2. Handler resolves the target account: session's `active_account` if set by a prior `use_account`, else the config default.
3. Posture matrix check against the account's posture (unchanged logic).
4. Look up the per-account `Governor`; rate-check (now contended across all sessions talking to that account). Look up `CircuitBreaker`; gate.
5. Emit `tool_start` with `session_id`.
6. Execute IMAP / SMTP / content-pipeline work through the account's `Connection` (its internal mutex serializes concurrent session access automatically — no outer lock).
7. Emit `tool_end` with `session_id`.
8. Cancellation: session's `CancellationToken` cancels in-flight calls for this session on client disconnect. Other sessions' tokens untouched.

### 6.4 Client disconnect

1. `rmcp::serve_server` future resolves on EOF.
2. Session task cancels its own in-flight work.
3. Emit `session_end(reason=eof | error, duration_ms, total_tool_calls, last_error)`.
4. Drop `SessionState`; `Arc<DaemonState>` lives on.

### 6.5 Daemon shutdown (SIGTERM / Ctrl-Break)

1. Shutdown notify fires → stop accepting (drop `PlatformListener`).
2. For each active session: cancel in-flight work; wait up to 5 s for graceful close; drop. Each session emits `session_end(reason=daemon_shutdown)`.
3. Drain cancellation channel (existing `rimap_audit::spawn_drainer` behavior).
4. Emit `process_end`. Drop `AuditWriter` → fs-lock released.
5. `unlink` the socket (Unix) / close pipe (Windows). Exit.

> **v1 best-effort caveat:** sessions that do not drain within 5 s are
> aborted via `JoinSet::shutdown()` (with an additional 2 s timeout per
> review finding RUST-ASYNC-10) and will not emit `session_end` records
> when aborted. Tracked at follow-up #137. Readers MUST NOT assume a
> one-to-one `session_start` / `session_end` pairing for daemon-crash /
> forced-shutdown cases.

### 6.6 State-scoping table

| State                                 | Scope in daemon       | Effect vs v0                                         |
|---------------------------------------|----------------------|------------------------------------------------------|
| Audit writer, provenance ring, config | per-daemon           | Semantics preserved (one process per user is still one daemon per user in scope A). |
| IMAP `Connection`                     | per-account, internally serialized | Sessions sharing an account serialize on `Connection`'s existing internal mutex — no code change. |
| `Governor` (rate limiter)             | per-account          | **Behavior change:** cannot be split across clients.  |
| `CircuitBreaker`                      | per-account          | Correctly protects upstream regardless of client count. |
| `FolderGuard`, special-use cache      | per-account          | Built once; shared.                                   |
| Active account (`use_account`)        | per-session          | Independent selection across sessions.                |
| Cancellation tokens                   | per-session          | Client disconnect cancels only its own work.          |
| `RedactionSalt`                       | per-daemon (was per-process) | Scope widens from process to daemon; strictly stronger, since the daemon's salt now covers every session it serves. No new cross-session leak. Follow-up #141 tracks hoisting this from `mcp::server` to `DaemonState`. |

## 7. Audit log changes

Record-shape changes relative to v0, summarized:

| Record              | Change                                                                          |
|---------------------|---------------------------------------------------------------------------------|
| `process_start`     | Unchanged. One per daemon lifetime.                                             |
| `process_end`       | Unchanged in shape. `total_tool_calls` now aggregates across all sessions (stops being the hardcoded `0` placeholder per `main.rs:149-153`). |
| `session_start`     | **New.** `session_id`, `peer_identity`, `socket_path`, `ts`, `process_id`, `seq`. |
| `session_end`       | **New.** `session_id`, `reason`, `duration_ms`, `total_tool_calls`, `last_error?`. |
| `tool_start`        | Add `session_id: Option`, always `Some` in practice (session handler enforces via typed wrapper). |
| `tool_end`          | Same as `tool_start`.                                                          |
| `auth`              | Add `session_id: Option`. `None` during daemon-boot bootstrap; `Some` when emitted from a session. |
| `cancellation` drain | `session_id` when known; emitted sessionless only during shutdown drain.        |

`session_start` / `session_end` are append-only like all other kinds; they flush but do not fsync (same as `tool_start` / `tool_end`). `process_start` / `process_end` / `auth` continue to fsync.

`session_start.peer_identity` records the connecting peer's UID and PID
(Unix) or SID and PID (Windows). These values are NOT considered secrets
under the project threat model; they are intentionally persisted for
forensics. Retention is bounded by `rotate_keep` and any configured
`retention_seconds`. No username resolution (`getpwuid_r` /
`LookupAccountSid`) is performed; records remain numeric-ID only.

Insta snapshot tests cover the serialized JSON shape of each new/modified kind.

## 8. CLI surface and migration

Subcommands after this change:

- `rusty-imap-mcp daemon` — foreground daemon. Exits on signal.
- `rusty-imap-mcp shim` — stdio↔socket adapter.
- `rusty-imap-mcp login`, `migrate-keyring`, `audit merge`, `--dry-run` — unchanged.

Removed: bare invocation. Prints help, exits 1.

MCP client config migration is one line:

```diff
 "mcpServers": {
   "rusty-imap": {
-    "command": "/path/to/rusty-imap-mcp"
+    "command": "/path/to/rusty-imap-mcp",
+    "args": ["shim"]
   }
 }
```

Autostart artifacts shipped in `scripts/packaging/`:

- `rusty-imap-mcp.service` — systemd user unit with `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=%h/.local/state/rusty-imap-mcp %h/.config/rusty-imap-mcp %t`, `NoNewPrivileges=true`.
- `com.rusty-imap-mcp.plist` — macOS launchd agent, `RunAtLoad=true`, `KeepAlive.SuccessfulExit=false`.
- `register-task.ps1` — Windows Task Scheduler registration script, logon trigger, user context.

Documentation updates: `README.md`, `docs/quickstart-gmail.md`, `docs/quickstart-proton-bridge.md` each get the one-line MCP-config change and a platform-appropriate autostart section. `CHANGELOG.md` gets a migration note calling out the `args: ["shim"]` change, the behavior change in rate-limit scoping, and the new audit record kinds.

Error UX when the daemon is absent (Unix example):

```
rusty-imap-mcp shim: cannot connect to daemon at /run/user/1000/rusty-imap-mcp/daemon.sock

The rusty-imap-mcp daemon is not running. Start it with:

    systemctl --user enable --now rusty-imap-mcp.service

Or, if not using systemd:

    rusty-imap-mcp daemon

See docs/quickstart-proton-bridge.md for setup details.
```

## 9. Cross-platform layering

`daemon/transport/` contains two mutually-exclusive modules.

### 9.1 Unix (`#[cfg(unix)]`)

- Socket path: `$XDG_RUNTIME_DIR/rusty-imap-mcp/daemon.sock` (Linux with XDG_RUNTIME_DIR) or `$TMPDIR/rusty-imap-mcp-<uid>/daemon.sock` (macOS, or Linux without XDG_RUNTIME_DIR).
- Parent dir: `mkdir 0700`; if present, verify `owner == our_uid && mode == 0700 && !is_symlink` (use `openat` with `O_NOFOLLOW`).
- Socket file: `bind()` + explicit `fchmod 0600`.
- Stale socket recovery: `bind` returns `EADDRINUSE` → try `connect()`. Connect succeeds → another live daemon → exit with `Locked`. Connect fails → carcass → `unlink`, retry `bind`, log the unlink.
- Peer identity: `tokio::net::UnixStream::peer_cred()` → `(uid, pid)`.

### 9.2 Windows (`#[cfg(windows)]`)

> **v1 implementation note:** what ships in v1 is a placeholder
> `PeerIdentity::Windows { sid: None, pid: None }`. Full identity capture
> (`GetNamedPipeClientProcessId` → `OpenProcess` → `OpenProcessToken` →
> `GetTokenInformation`) requires `unsafe` FFI forbidden by the workspace's
> `unsafe_code = "forbid"` policy; tracked at follow-up #132. Until then,
> the Windows peer gate relies entirely on the named-pipe DACL for UID gating.

- Pipe name: `\\.\pipe\rusty-imap-mcp-<user>` where `<user> = GetUserNameW()`.
- ACL: `CreateNamedPipeW` with a `SECURITY_ATTRIBUTES` whose DACL grants only the current user's SID. Raw handle consumed by `NamedPipeServer::from_raw_handle_options`.
- One-instance-per-client: accept loop creates a fresh `NamedPipeServer` instance, `connect()`s to wait for the next client, then loops.
- Peer identity: `GetNamedPipeClientProcessId(handle)` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `OpenProcessToken` → `GetTokenInformation(TokenUser)` → SID. Compare to our own token SID. Identity-lookup failure (race if client exits) → `session_end(reason=peer_uid_rejected)`.
- Shim side: `ClientOptions::new().open(pipe_name)` with 3× 100 ms retry on `ERROR_PIPE_BUSY`.

### 9.3 Shared `PlatformListener` / `PlatformStream` API

```rust
pub(crate) trait PlatformListener: Send + 'static {
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;
    type Identity: Into<PeerIdentity> + Send + 'static;

    async fn accept(&mut self) -> Result<(Self::Stream, Self::Identity), io::Error>;
}
```

Identity ingress converges on the shared `PeerIdentity` enum at the audit-record boundary.

### 9.4 Windows dependency cost

Adds `windows-sys = "0.59"` (or `windows` crate) to `rimap-server`'s Windows-only dependency set for `CreateNamedPipeW`, `GetNamedPipeClientProcessId`, `OpenProcessToken`, `GetTokenInformation`. Already transitively present via rustls/ring on Windows — workspace-level cost is small.

## 10. Testing strategy

### 10.1 Unit tests

- `SessionId`: ULID property (monotone prefix), serde round-trip.
- Session-state isolation: two `PerSessionHandler`s from one shared `Arc<DaemonState>` have independent `active_account`.
- Peer-identity decoders: parse known-good `UCred` from socketpair (Unix); parse synthetic `TokenUser` (Windows).
- Socket path resolver: every `XDG_RUNTIME_DIR` / `TMPDIR` case, including permissions-wrong parent.
- Registry sharing: two `PerSessionHandler`s built from the same `Arc<AccountRegistry>` can concurrently invoke operations on the same account without panicking or corrupting state (the concurrency-correctness contract of `Connection`'s internal mutex, exercised through the daemon's session layer — not a reimplementation of `rimap-imap`'s own tests).
- Audit record shapes: insta snapshot for each new/modified kind.

### 10.2 Integration tests (`rimap-server/tests/`)

Harness `TestDaemon` runs the daemon inside the test's tokio runtime against tempdir config + tempdir audit path + OS-specific transport. Most tests talk to the daemon directly over the platform stream; shim-specific tests spawn the real shim binary via `assert_cmd`.

1. Single session happy path; audit log ordering.
2. Two concurrent sessions, independent account selection.
3. Per-account shared rate limit (the behavior-change gate).
4. Per-account shared circuit breaker.
5. Peer-identity rejection (unit-test the function end-to-end; `#[cfg(test_as_root)]` e2e on Linux best-effort).
6. Second daemon fails fast with `Locked`.
7. Stale socket recovery: pre-create dead socket, daemon unlinks and binds.
8. Live daemon wins over stale path: kill -9, restart succeeds after cleanup.
9. Graceful shutdown during in-flight work: SIGTERM mid-tool-call; assert cancellation, `session_end(reason=daemon_shutdown)`, `process_end`, fs-lock release.
10. Shim subprocess happy path.
11. Shim error message when daemon absent.

### 10.3 Windows-specific additions

- DACL verification: inspect `SECURITY_DESCRIPTOR`, assert DACL grants only current user SID.
- Identity-lookup race: kill client between accept and `OpenProcess`; assert rejection path fires without wedging the accept loop.

### 10.4 Mutation testing

`cargo mutants` over the session / shutdown / peer-identity modules. Target: repo-baseline mutation score or better on the new files.

### 10.5 MSRV

`tokio::net::UnixListener`, `UnixStream::peer_cred`, `tokio::net::windows::named_pipe`, `uuid` v7 — all stable before MSRV 1.88.0. No MSRV bump.

### 10.6 Preserved tests

All `rimap-audit` writer tests pass literally (daemon still holds the single exclusive lock). `rimap-content` adversarial corpus unaffected. `rimap-authz` matrix tests unaffected. `rimap-server` `cli/dry_run.rs` "already-locked is a warning" behavior unchanged. Posture-gated `tools/list` tests unaffected.

## 11. Error handling and failure modes

| Condition                               | Behavior                                                                                                       |
|-----------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Daemon crash (SIGKILL, panic)           | OS releases fs-lock; `process_end` missing in log (detectable). Live shims see socket RST, exit 1 with restart guidance. |
| Daemon SIGTERM mid-tool-call            | Session tokens cancel, tools surface `ToolCancelled`, `tool_end(was_cancelled=true)`, `session_end(reason=daemon_shutdown)`, `process_end`. |
| Shim crash / client gone                | Socket EOF; session task exits; `session_end(reason=eof)`. No impact on other sessions.                        |
| Disk full on audit write                | Existing behavior preserved: `ERR_INTERNAL` unless `audit.fail_open = true`.                                   |
| Peer UID mismatch                        | `session_start` + `session_end(reason=peer_uid_rejected)` emitted as a pair; connection closed.                 |
| Second daemon invoked                    | Fails at `AuditWriter::open` with `Locked`; message points at platform autostart command.                       |
| Shim: daemon not running                 | Exit 1; stderr names expected path and start command.                                                          |
| Windows: all pipe instances busy         | `ClientOptions` retry up to 3× 100 ms; then exit 1 with "daemon is busy, retry shortly."                       |

## 12. Follow-up issues

Filed after this spec merges (referencing this document's section numbers):

- **B — multi-UID support.** Per-identity posture mapping, config schema for identity allowlists, socket permissions model beyond same-UID. Hooks (peer-identity capture, paired rejection records, tagged enum shape) are in place.
- **C1 — HTTP / SSE listener.** Token auth, loopback bind, optional TLS, HTTP-level rate limit, new `[daemon] listen_http` config field.
- **Socket path config override.** Needed when B lands; optional and absent now.
- **SIGHUP config reload.** Preserve live sessions, rotate registry.
- **IMAP connection pool depth > 1 per account.** Replace the single `Connection` with a small pool of connections; gate on observed contention (today `Connection`'s internal single-session mutex serializes all operations against that account).
- **Windows Service (SCM) integration.** Proper `ServiceMain`, `SERVICE_STATUS`, stop handler. Supersedes Task Scheduler script.
- **Daemon idle-timeout / lazy-spawn.** Only if the user-started workflow proves friction in practice.
- **Provenance ring buffer scoping knob.** Per-daemon today; revisit if forensics want tighter granularity.

## 13. Decisions rejected

Captured so future readers don't relitigate:

- **Shared-append audit (Approach A in brainstorm).** Relax `try_lock_exclusive` to append-with-coordination. Rejected: breaks `process_start` chaining, inode tamper detection, provenance semantics. Worst-value trade in the space.
- **Daemon + thin stdio shim, marketed as B.** Functionally close to the C2 design; the chosen name just commits explicitly to the daemon-is-the-real-server architecture.
- **L1 — lazy-spawn daemon.** Attractive UX; race windows (two shims simultaneously spawning), idle-shutdown interactions with IDLE tool calls, double-spawn handling against fs-lock. Not worth the test surface versus a one-command user setup.
- **L3 — hybrid L1+L2.** Two code paths to test for little added value.
- **C1 — HTTP/SSE on loopback, now.** Would ship immediately without a shim, but adds non-trivial attack surface (token auth, TCP listener, constant-time comparisons, HTTP rate limit) to a project whose threat model is "every byte is adversarial." Deferred as a follow-up.
- **W1 — drop Windows.** Existing Windows release users would regress.
- **W2 — keep stdio on Windows, daemon on Unix.** Permanent `cfg` split in the codebase; diverging UX between platforms.
