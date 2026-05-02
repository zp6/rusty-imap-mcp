# Issue #129 — Windows Service (SCM) integration (design)

**Date:** 2026-05-02
**Branch:** `feat/issue-129-windows-service`
**Issue:** [#129](https://github.com/randomparity/rusty-imap-mcp/issues/129)
**Severity:** Enhancement (Windows packaging parity)

## Goal

Replace the v1 Task Scheduler logon-trigger script
(`scripts/packaging/register-task.ps1`) with a real Windows Service Control
Manager (SCM) integration: `ServiceMain` entry point, `SERVICE_STATUS`
reporting, a stop-handler that drives the daemon's existing shutdown
`Notify` to a clean drain, and install/uninstall verbs on the binary. The
Service Control Manager becomes the lifecycle owner on Windows; the
foreground `daemon` subcommand stays unchanged for development and for
non-Windows targets.

## Constraints

- Workspace-wide `unsafe_code = "forbid"` (`Cargo.toml:192`) must remain
  intact. The two related issues that genuinely need Win32 FFI ([#132]
  real Windows peer-identity capture, [#133] custom DACL on the named
  pipe) are out of scope here and remain blocked on that exception.
- The daemon already drives shutdown via an `Arc<Notify>` (see
  `crates/rimap-server/src/daemon/run.rs` and the `install_shutdown_handler`
  helper at `crates/rimap-server/src/daemon/shutdown.rs`). The service path
  must reuse that hook — no parallel shutdown plumbing.
- MSRV (Rust 1.88.0) must keep building; the new Windows-only dependency
  must satisfy MSRV on its current crates.io release.
- No new behavior on non-Windows targets. All new code is `cfg(windows)`-
  gated.

[#132]: https://github.com/randomparity/rusty-imap-mcp/issues/132
[#133]: https://github.com/randomparity/rusty-imap-mcp/issues/133

## Decisions (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Per-user service** (no `LocalSystem`/`NetworkService`) | Matches v1 behavior; daemon needs the user's Windows Credential Manager via `keyring` for IMAP credentials. System-context promotion is gated on [#133] (custom DACL) and [#124] (multi-UID). |
| 2 | **User Service Template** (Win10 1703+) | Only per-user model that doesn't require capturing the user's password at install time. SCM auto-spawns per-user instances under the logged-in user's token. |
| 3 | Use the **`windows-service`** crate | Safe Rust wrappers around `StartServiceCtrlDispatcher` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus` / `ServiceManager`. Lets us keep `unsafe_code = "forbid"` workspace-wide. |
| 4 | **Explicit CLI subcommands**: `service install`, `service uninstall`, `service run` | Deterministic, testable, mirrors the crate's own examples; `daemon` stays as the foreground/dev verb on all platforms. |
| 5 | **Delete** `scripts/packaging/register-task.ps1` in the same PR | Project rule: replace, don't deprecate. |
| 6 | Auto-redirect daemon `tracing` to `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` when running under SCM | Service launch has no console; this gives operators a default log location without requiring manual `sc.exe failure` redirection. |
| 7 | **Windows Event Log integration is out of scope** | Filed as a follow-up issue; needs separate event-source registration / message manifest plumbing. |

## Architecture

### Module layout

A single `cfg(windows)`-gated module inside `rimap-server`:

```
crates/rimap-server/src/service/
├── mod.rs              # cfg(windows); re-exports the three entry points
├── run.rs              # ServiceMain body, control handler, status pump
├── install.rs          # service install/uninstall via ServiceManager
└── tracing_sink.rs     # %LOCALAPPDATA%\…\daemon.log file appender
```

No new crate. The module compiles to nothing on non-Windows targets.

### Daemon refactor (precondition)

Today `crates/rimap-server/src/main.rs::daemon_main` (lines 113–207) builds
the `Arc<Notify>` itself by calling
`install_shutdown_handler()`. The service path needs to *supply* the
Notify rather than have it built internally. Extract the inner body
into `crates/rimap-server/src/daemon/run.rs` next to the existing
`run::run`:

```rust
// crates/rimap-server/src/daemon/run.rs
pub async fn run_with_shutdown(
    config_path: PathBuf,
    shutdown: Arc<Notify>,
    started: Option<oneshot::Sender<()>>,
) -> anyhow::Result<()> { … }
```

Both `daemon_main` (signal-driven shutdown) and the new
`service::run::service_main` (SCM-driven shutdown) call this. The
`started` oneshot lets the service path observe "listener bound, ready
to accept" so it can transition `StartPending → Running` at the right
moment; foreground passes `None`.

This is a pure refactor — foreground behavior is unchanged. It is the
first task of the implementation plan, in its own commit, with a test
that the cross-platform unit-test layer can exercise without
touching SCM.

### CLI surface

Three new subcommands, all `#[cfg(windows)]`:

```
rusty-imap-mcp service install     [--config <PATH>] [--name <NAME>]
rusty-imap-mcp service uninstall   [--name <NAME>]
rusty-imap-mcp service run         (invoked by SCM only)
```

- **`install`** — resolves the running binary's absolute path, resolves
  the config path the same way `daemon` does, then calls
  `ServiceManager::create_service` with the values in the table below
  plus `update_failure_actions` for the recovery policy. Requires
  Administrator; we detect `ERROR_ACCESS_DENIED` and emit a clear
  "run from an elevated shell" hint instead of an opaque Win32 error.
- **`uninstall`** — opens the service handle by name, calls
  `Service::delete()`. Idempotent: "service does not exist" is success.
  Errors on permission denial with the same elevated-shell hint.
- **`run`** — calls `service_dispatcher::start(SERVICE_NAME,
  ffi_service_main)`. If invoked outside SCM, the dispatcher returns
  `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`; we map that to a friendly
  "this verb is for the Service Control Manager — see `rusty-imap-mcp
  daemon` for foreground use" error and exit non-zero.

`daemon` is unchanged on every platform.

### Service registration values

| Field | Value |
|---|---|
| `name` | `RustyImapMcp` (override via `--name`) |
| `display_name` | `Rusty IMAP MCP` |
| `description` | "Audit-logged Model Context Protocol server for IMAP email." |
| `service_type` | `OWN_PROCESS \| USER_SERVICE \| USER_SERVICE_INSTANCE` |
| `start_type` | `AutoStart` |
| `error_control` | `Normal` |
| `executable_path` | absolute path of the running binary |
| `launch_arguments` | `["service", "run", "--config", <resolved>]` |
| `dependencies` | `["Tcpip"]` |
| `account_name` | none (User Service Templates inherit the user token) |
| recovery actions | `[Restart after 30s, Restart after 30s, None]`, reset count after 3600s |

The `--config` path is resolved at install time and baked into the
registered command line. This is intentional: removing the env-var
dependency is half the point of installing a Service.

## Stop-handler and SERVICE_STATUS state machine

```
StartPending  ─►  Running  ─►  StopPending  ─►  Stopped
   │
   └─► Stopped { exit_code: ServiceSpecific(N) }   (boot failure)
```

Sequence inside `service_main`:

1. Build the `event_handler` closure. It owns `Arc::clone` of the shutdown
   `Notify` and of the `ServiceStatusHandle`. Recognised controls:
   `Stop` → `notify_waiters()` + report `StopPending`; `Shutdown` → same;
   `Interrogate` → re-emit current status. All other controls return
   `ServiceControlHandlerResult::NotImplemented`.
2. `service_control_handler::register(SERVICE_NAME, event_handler)`.
3. Report `StartPending { wait_hint: 5s, checkpoint: 0 }`.
4. Build a current-thread `tokio` runtime, spawn `run_with_shutdown(…,
   shutdown.clone(), Some(started_tx))`.
5. On `started_rx.await`, report
   `Running { controls_accepted: Stop | Shutdown }`. If the daemon body
   errors during boot, report `Stopped { exit_code: ServiceSpecific(code)
   }` where `code` comes from the `ServiceExitCode` enum below, then
   return.
6. While the daemon runs, await its `JoinHandle`. When `Stop`/`Shutdown`
   fires, the control handler signals the Notify; the daemon enters its
   own drain (5 s session-drain deadline, then `JoinSet::shutdown`).
7. While the drain runs, a periodic ticker (every 2 s, capped at ~10 s
   total) re-emits `StopPending` with monotonically increasing
   `checkpoint` and a fresh `wait_hint` so SCM does not terminate us.
8. On drain completion, report `Stopped { exit_code: NoError }` and
   return from `service_main`. The `service_dispatcher::start` call
   in `run` returns; the process exits.

### Service-specific exit codes

```rust
#[repr(u32)]
enum ServiceExitCode {
    ConfigLoad      = 1,
    AuditOpen       = 2,
    RegistryBuild   = 3,
    ListenerBind    = 4,
    RuntimeFailure  = 5,
}
```

These map onto the `with_context` boundaries already present in
`daemon_main`. SCM logs `service_specific` in the System event log; an
operator correlating this with the `daemon.log` redirect (see below)
can identify the failure class without reading source.

## Tracing destination under SCM

When `service run` is the entry point, daemon `tracing` events redirect
to `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` instead of stderr. The
file is created `0600`-equivalent (no inheritable handles), append-only.
We do not rotate. Rotation is the operator's responsibility (or a
future feature); shipping a rolling-file dependency is out of scope.

`boot::logging::init` is called once at process start and installs a
global tracing subscriber, so the redirect must be selected *before*
that call. The implementation:

1. `boot::logging` grows a sibling entry point — `init_to_writer(W:
   io::Write + Send + 'static)` — that wires the same formatter as
   `init` but to the supplied writer instead of stderr.
2. `main()` continues to call `logging::init()` for every subcommand
   *except* `service run`. For `service run` we defer subscriber
   installation, hand control to `service_dispatcher::start`, and the
   `service_main` body calls `logging::init_to_writer(file_handle)`
   once it has opened the daemon-log file. `service install`,
   `service uninstall`, and `daemon` keep stderr logging.
3. `service::tracing_sink` owns the file-handle creation: resolves
   `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log`, creates the directory
   (`0700`-equivalent on Windows ACL terms), opens append-only with
   no shared inherit, and returns the handle.

If the log file cannot be opened (permission denied, missing parent)
the service falls back to `logging::init()` (stderr). Stderr under
SCM is unbuffered and lost unless the operator has set up `sc.exe
failure` redirection, but this guarantees the service can still start
and produces a structured failure record via the SCM exit code path.
The Event Log follow-up issue is what lifts this floor.

## Testing

| # | Layer | Platform |
|---|-------|----------|
| 1 | Cross-platform unit test for `run_with_shutdown(shutdown, started)` — feed a Notify, kick it from a separate task, assert clean drain | All |
| 2 | Unit test for the control-handler closure: `Stop` and `Shutdown` call `notify_waiters()`; everything else returns `NotImplemented` | Windows |
| 3 | Integration test for install/uninstall round-trip against a unique name (`RustyImapMcpTest_<pid>`): create → query → delete; skip cleanly if not elevated | Windows (CI runner is elevated) |
| 4 | Manual smoke checklist committed under `docs/manual-tests/windows-service.md`: install → log in → confirm `services.msc` shows running → `sc stop` → confirm clean drain via the audit log → `service uninstall` | Manual |

We deliberately do **not** add a CI test that round-trips
`install → start → stop → uninstall` under SCM — the timing window for
SCM start/stop on a non-interactive runner is flaky and the unit-level
control-handler test plus the install/uninstall integration test cover
the regression surface.

## Files

**Added**
- `crates/rimap-server/src/service/mod.rs`
- `crates/rimap-server/src/service/run.rs`
- `crates/rimap-server/src/service/install.rs`
- `crates/rimap-server/src/service/tracing_sink.rs`
- `docs/manual-tests/windows-service.md`

**Modified**
- `Cargo.toml` — add `windows-service` to `[workspace.dependencies]`,
  gated on `cfg(windows)` at the consumer site. Current stable version
  to be looked up at implementation time, not assumed.
- `crates/rimap-server/Cargo.toml` — depend on `windows-service` under
  `[target.'cfg(windows)'.dependencies]`.
- `crates/rimap-server/src/main.rs` — split `daemon_main` so the inner
  body lives in `daemon::run::run_with_shutdown`; add the three
  `service` subcommand handlers behind `#[cfg(windows)]`. Defer
  `logging::init` for `service run`.
- `crates/rimap-server/src/daemon/run.rs` — gain
  `run_with_shutdown(config, shutdown, started)`; existing `run` becomes
  a thin caller.
- `crates/rimap-server/src/boot/logging.rs` — add `init_to_writer(W)`
  alongside `init`.
- `crates/rimap-server/src/cli.rs` — new `Service { action, … }`
  `Command` arm with `install` / `uninstall` / `run` actions.

**Deleted**
- `scripts/packaging/register-task.ps1` (replacement is `service install`).

## Out of scope / follow-ups

- **Windows Event Log integration.** Separate event-source registration,
  message manifest, structured event IDs. Filed as its own GitHub issue
  before this design is reviewed (see "Follow-up issues filed" below).
- **System-context service** (`LocalSystem`/`NetworkService`). Blocked on
  [#133] (custom DACL) and [#124] (multi-UID). Promotion is a future
  design exercise that builds on this module.
- **Real Windows peer-identity capture.** [#132]; unrelated to lifecycle.
- **Log rotation / retention** for the `daemon.log` redirect. Operator
  responsibility for now.

## Follow-up issues filed

- (to be filed against the spec commit) — Windows Event Log integration
  for the daemon under SCM.

## Acceptance criteria

1. `rusty-imap-mcp service install` on Windows registers a User Service
   Template that auto-starts at user logon and shows up in
   `services.msc`.
2. `sc stop RustyImapMcp` (or `services.msc → Stop`) results in a clean
   drain: every active session emits `session_end`, `process_end`
   carries a non-zero `total_tool_calls` if any tools ran, the audit
   log is fsynced before the process exits, and SCM reports `Stopped`
   within the 30 s default deadline.
3. `rusty-imap-mcp service uninstall` removes the registration and is
   idempotent on a second invocation.
4. `scripts/packaging/register-task.ps1` is gone.
5. `cargo clippy --workspace --all-targets --all-features --locked --
   -D warnings` is clean on all platforms; `unsafe_code = "forbid"`
   remains in place workspace-wide.
6. `just ci` is green on Linux and macOS (no behavior change there).
7. The manual smoke checklist documented in `docs/manual-tests/windows-
   service.md` passes locally on a Windows 10/11 host.
