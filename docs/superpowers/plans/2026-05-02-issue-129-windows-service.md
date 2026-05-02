# Windows Service (SCM) integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the v1 Task Scheduler script with a Windows Service that registers as a User Service Template, drives the existing daemon `Arc<Notify>` shutdown via SCM stop control, and exposes `service install` / `service uninstall` / `service run` subcommands.

**Architecture:** A `cfg(windows)`-gated `service` module inside `rimap-server` reuses the existing `daemon::run::run` core via a small refactor (`run_with_shutdown` extraction). The `windows-service` crate provides safe wrappers around SCM APIs so the workspace `unsafe_code = "forbid"` policy stays intact.

**Tech Stack:** Rust 2024 edition, MSRV 1.88.0, tokio (current-thread runtime in service path), `windows-service` crate, `tracing-subscriber` (writer redirect), clap (subcommand definition).

**Spec:** `docs/superpowers/specs/2026-05-02-issue-129-windows-service-design.md`

**Branch:** `feat/issue-129-windows-service`

---

## File map

| Path | Disposition | Purpose |
|---|---|---|
| `crates/rimap-server/src/daemon/run.rs` | Modify | Extract `run_with_shutdown` body next to existing `run`. |
| `crates/rimap-server/src/main.rs` | Modify | Reduce `daemon_main` to a thin caller of `run_with_shutdown`; defer logging init for `service run`; wire new subcommand handlers. |
| `crates/rimap-server/src/cli/mod.rs` | Modify | Add `Service { action: ServiceAction }` arm and `ServiceAction` enum. |
| `crates/rimap-server/src/boot/logging.rs` | Modify | Add `init_to_writer` sibling. |
| `crates/rimap-server/src/service/mod.rs` | Create | `cfg(windows)`; module re-export + `SERVICE_NAME_DEFAULT` constant. |
| `crates/rimap-server/src/service/tracing_sink.rs` | Create | Resolve `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log`, open append-only. |
| `crates/rimap-server/src/service/install.rs` | Create | User Service Template install + idempotent uninstall via `windows-service`. |
| `crates/rimap-server/src/service/run.rs` | Create | `ServiceMain` body, control-handler factory, `ServiceExitCode`, dispatcher entry. |
| `crates/rimap-server/src/lib.rs` | Modify | `pub mod service;` behind `#[cfg(windows)]`. |
| `Cargo.toml` | Modify | Add `windows-service` to `[workspace.dependencies]`. |
| `crates/rimap-server/Cargo.toml` | Modify | Pull `windows-service` in under `[target.'cfg(windows)'.dependencies]`. |
| `crates/rimap-server/tests/service_install_uninstall.rs` | Create | Windows integration test (skips when not elevated). |
| `docs/manual-tests/windows-service.md` | Create | Manual smoke checklist. |
| `scripts/packaging/register-task.ps1` | Delete | Replaced by `service install`. |

---

## Task 1: Extract `run_with_shutdown` from `daemon_main`

**Files:**
- Modify: `crates/rimap-server/src/daemon/run.rs`
- Modify: `crates/rimap-server/src/main.rs`
- Modify: `crates/rimap-server/src/lib.rs` (re-export check only — no change expected)

Pure refactor: hoist the body of `daemon_main` (currently lines 113–207 of `crates/rimap-server/src/main.rs`) into a new public function `daemon::run::run_with_shutdown(config_path, shutdown, started)`. The existing signal-driven `daemon_main` becomes a thin wrapper that builds the Notify itself. No behavioral change on Unix or Windows.

The `started: Option<oneshot::Sender<()>>` parameter lets the future service-path caller observe "listener bound, ready to accept" so it can transition `StartPending → Running` at the right moment.

- [ ] **Step 1: Write the failing test**

Add to `crates/rimap-server/src/daemon/run.rs` inside the existing `#[cfg(test)]` block. This test sits cross-platform — it doesn't bind a real socket via `run_with_shutdown` (which would need a config file and registry); it asserts the new function signature compiles and is reachable from outside the module.

```rust
#[cfg(test)]
mod run_with_shutdown_signature {
    /// Pin the public signature of `run_with_shutdown` so the service-path
    /// caller and the existing `daemon_main` shim both build against the
    /// same contract. A compile-only check is enough — the integration
    /// behavior is exercised by the full daemon-spawn tests under
    /// `tests/`.
    #[test]
    fn signature_is_stable() {
        fn _assert<F>(_f: F)
        where
            F: for<'a> Fn(
                std::path::PathBuf,
                std::sync::Arc<tokio::sync::Notify>,
                Option<tokio::sync::oneshot::Sender<()>>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>,
            >,
        {
        }
        // The wrapper exists only to coerce the async fn into the trait
        // shape; if `run_with_shutdown`'s signature drifts, this fails to
        // compile.
        fn wrapper(
            p: std::path::PathBuf,
            n: std::sync::Arc<tokio::sync::Notify>,
            s: Option<tokio::sync::oneshot::Sender<()>>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>
        {
            Box::pin(super::run_with_shutdown(p, n, s))
        }
        _assert(wrapper);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p rimap-server --lib daemon::run::run_with_shutdown_signature 2>&1 | tail -5
```

Expected: FAIL with `cannot find function 'run_with_shutdown' in this module` or similar resolution error.

- [ ] **Step 3: Add `run_with_shutdown` to `daemon::run`**

Add to `crates/rimap-server/src/daemon/run.rs`, just below the `use` block and above `LiveSessions`:

```rust
use std::path::PathBuf;

use rimap_audit::ProcessEnd;
use rimap_audit::ProcessEndReason;
use rimap_config::credential::{CredentialStore, KeyringStore};
use rimap_config::loader::load_and_validate;

use crate::boot::{audit_init, registry};

/// Run the daemon end-to-end: load config, build the registry, bind the
/// listener, spawn the cancellation drainer, run the accept loop until
/// `shutdown` is signalled, drain in-flight sessions, and emit
/// `process_end`.
///
/// `started` is fired once the listener has been bound and the daemon is
/// about to enter the accept loop. The signal-driven `daemon_main` path
/// passes `None`; the SCM service path passes `Some(tx)` to drive the
/// `StartPending → Running` transition.
///
/// # Errors
///
/// Returns any fatal error encountered during boot or the accept-loop
/// run. Per-session errors are logged and never bubble up.
pub async fn run_with_shutdown(
    config_path: PathBuf,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
    started: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    #[cfg(unix)]
    crate::daemon::hardening::lock_down_process()
        .context("daemon startup hardening (rlimit_core / prctl_dumpable)")?;

    let multi = load_and_validate(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let audit = audit_init::init_audit_writer_multi(&multi, &config_path)
        .with_context(|| format!("opening audit log at {}", multi.audit.path.display()))?;

    let credentials: std::sync::Arc<dyn CredentialStore> = std::sync::Arc::new(KeyringStore);
    let download_dir: std::sync::Arc<std::path::Path> =
        std::sync::Arc::from(crate::resolve_download_dir_multi(&multi)?.into_boxed_path());

    let registry = registry::build(&multi, &audit, &credentials, &download_dir)
        .await
        .context("building account registry")?;

    let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
    let drainer_handle = rimap_audit::spawn_drainer(cancellation_rx, audit.clone());

    #[cfg(unix)]
    let listener = {
        use crate::daemon::socket_path;
        use crate::daemon::socket_setup;
        use crate::daemon::transport::unix::UnixSocketListener;
        let ep = socket_path::resolve();
        let path = ep
            .as_path_buf()
            .ok_or_else(|| anyhow::anyhow!("unix path resolver returned non-path endpoint"))?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("socket path has no parent: {}", path.display()))?;
        let our_uid = rustix::process::geteuid().as_raw();
        let _parent_fd = socket_setup::prepare_socket_dir(parent, our_uid)
            .with_context(|| format!("preparing {}", parent.display()))?;
        UnixSocketListener::bind(&path)
            .await
            .with_context(|| format!("binding daemon socket at {}", path.display()))?
    };
    #[cfg(windows)]
    let listener = {
        use crate::daemon::socket_path;
        use crate::daemon::transport::windows::NamedPipeListener;
        let ep = socket_path::resolve().context("resolving daemon pipe name")?;
        NamedPipeListener::bind(ep.as_str())
            .with_context(|| format!("creating named pipe {}", ep.as_str()))?
    };

    let max_sessions =
        usize::try_from(multi.daemon.max_concurrent_sessions.get()).unwrap_or(usize::MAX);
    let session_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(max_sessions));

    let state = std::sync::Arc::new(crate::daemon::state::DaemonState::new(
        std::sync::Arc::new(registry),
        audit.clone(),
        cancellation_tx,
        session_permits,
    ));

    if let Some(tx) = started {
        // Receiver may have been dropped if the caller gave up waiting;
        // ignore the send error in that case.
        let _ = tx.send(());
    }

    let mcp_result = run(state.clone(), listener, shutdown).await;

    let reason = match &mcp_result {
        Ok(()) => ProcessEndReason::Eof,
        Err(_) => ProcessEndReason::Error,
    };
    if let Err(e) = drainer_handle.await {
        tracing::error!(error = %e, "cancellation drainer join error");
    }
    let total_tool_calls = state.total_tool_calls();
    if let Err(e) = audit.log_process_end(ProcessEnd {
        reason,
        total_tool_calls,
    }) {
        tracing::error!(error = %e, "failed to write process_end");
    }
    mcp_result
}
```

The function `crate::resolve_download_dir_multi` currently lives in `main.rs` as a private item. Move it to `crates/rimap-server/src/lib.rs` so `run.rs` can call it. In `lib.rs`, after the existing module declarations, add the relocated body — copy it verbatim from `main.rs` and prepend `pub`. Remove the original from `main.rs` so there is exactly one definition.

Inspect `main.rs` for the helpers `run_with_shutdown` now depends on (`resolve_download_dir_multi`, and any private helpers it transitively pulls in). Anything called from `run.rs` must be `pub` from `lib.rs` or `pub(crate)` if both files share the same crate (they do — `run.rs` is in the `rimap-server` lib crate, `main.rs` is the binary). Move what you need; keep blast radius small.

- [ ] **Step 4: Reduce `daemon_main` to a thin caller**

Replace the body of `daemon_main` in `crates/rimap-server/src/main.rs` (currently lines 113–207) with:

```rust
async fn daemon_main(config_override: Option<PathBuf>) -> anyhow::Result<()> {
    use rimap_server::daemon::run::run_with_shutdown;
    use rimap_server::daemon::shutdown::install_shutdown_handler;

    let config_path = resolve_or_default(config_override)?;
    let shutdown = install_shutdown_handler();
    run_with_shutdown(config_path, shutdown, None).await
}
```

Delete the old inline body (config load, audit init, registry build, listener bind, state, run, drainer await, process_end). All of that now lives in `run_with_shutdown`. Remove the `use` statements at the top of `daemon_main` that are no longer referenced.

- [ ] **Step 5: Run the signature test**

```bash
cargo test -p rimap-server --lib daemon::run::run_with_shutdown_signature 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 6: Run the existing daemon test suite — proves no behavior regression**

```bash
cargo test -p rimap-server --test daemon_happy_path 2>&1 | tail -10
cargo test -p rimap-server --test daemon_graceful_shutdown 2>&1 | tail -10
cargo test -p rimap-server --test daemon_max_sessions 2>&1 | tail -10
```

Expected: each suite PASSES with the same count it had before this change.

- [ ] **Step 7: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`**

Expected: zero warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/daemon/run.rs crates/rimap-server/src/main.rs crates/rimap-server/src/lib.rs
git commit -m "refactor(rimap-server): extract daemon run_with_shutdown for SCM reuse"
```

---

## Task 2: Add `boot::logging::init_to_writer`

**Files:**
- Modify: `crates/rimap-server/src/boot/logging.rs`

Add a sibling entry point that wires the same formatter as `init` but writes to a caller-supplied writer instead of stderr. Used by the SCM service path to redirect to `daemon.log`.

- [ ] **Step 1: Write the failing test**

Append to `crates/rimap-server/src/boot/logging.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};

    /// `init_to_writer` accepts any `MakeWriter` implementation. A
    /// `Mutex<Vec<u8>>` is sufficient — `tracing-subscriber` already has a
    /// blanket `MakeWriter` impl for it.
    #[test]
    fn init_to_writer_accepts_mutex_vec_u8() {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        // Compile-time check only: this test passes by virtue of compiling.
        // Runtime behavior is hard to test because the global subscriber
        // is set at most once per process, and other tests in the binary
        // may have already initialized it. The presence of this call
        // proves the public signature accepts our intended writer shape.
        let _: fn(Arc<Mutex<Vec<u8>>>) = super::init_to_writer::<Arc<Mutex<Vec<u8>>>>;
        // Sanity poke at the writer type — confirms `Vec<u8>` is `Write`.
        let mut guard = buf.lock().expect("lock");
        let _ = guard.write_all(b"sanity");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p rimap-server --lib boot::logging::tests::init_to_writer 2>&1 | tail -5
```

Expected: FAIL — `cannot find function 'init_to_writer' in module 'super'`.

- [ ] **Step 3: Add `init_to_writer` next to `init`**

Add to `crates/rimap-server/src/boot/logging.rs`:

```rust
/// Initialize the global default subscriber with a caller-supplied writer
/// instead of stderr. Used by the Windows SCM service path to redirect
/// `tracing` events to a log file. Safe to call exactly once per process;
/// subsequent calls (and a subsequent `init()`) are no-ops.
pub fn init_to_writer<W>(make_writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_env("RIMAP_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(make_writer)
        .with_target(true)
        .try_init();
}
```

- [ ] **Step 4: Run test**

```bash
cargo test -p rimap-server --lib boot::logging::tests::init_to_writer 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 5: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`**

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/boot/logging.rs
git commit -m "feat(rimap-server): add boot::logging::init_to_writer for SCM redirect"
```

---

## Task 3: Add `windows-service` workspace dependency

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rimap-server/Cargo.toml`

The current stable `windows-service` crate version must be looked up at implementation time, not assumed. Use `cargo search windows-service` or check crates.io directly. Verify the crate's MSRV is ≤ 1.88.0 before pinning.

- [ ] **Step 1: Look up the current stable `windows-service` version**

```bash
cargo search windows-service --limit 1
```

Note the version string (e.g. `0.X.Y`). Replace `<VERSION>` in the steps below with that exact string. Confirm via `cargo metadata` or the crate's README that its MSRV is ≤ 1.88.0; if it isn't, escalate before continuing.

- [ ] **Step 2: Add to workspace deps**

Edit `Cargo.toml`. Locate the `[workspace.dependencies]` block and append after the `tokio` line (or wherever fits the existing alphabetical-ish grouping):

```toml
# Windows Service Control Manager integration (issue #129).
# Safe wrappers around StartServiceCtrlDispatcher / SetServiceStatus /
# ServiceManager — lets us keep `unsafe_code = "forbid"` workspace-wide.
windows-service = "<VERSION>"
```

- [ ] **Step 3: Add to `rimap-server` cfg(windows) deps**

Edit `crates/rimap-server/Cargo.toml`. Locate the existing `[target.'cfg(unix)'.dependencies]` block and add a sibling for Windows:

```toml
[target.'cfg(windows)'.dependencies]
windows-service = { workspace = true }
```

- [ ] **Step 4: Verify the workspace builds on the host platform**

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -10
```

Expected: clean. (On macOS/Linux the new dep is not pulled because of the cfg gate; this step proves we didn't break anything.)

- [ ] **Step 5: Verify cross-target Windows build (informational)**

If `x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc` is installed locally, run:

```bash
cargo check --workspace --target x86_64-pc-windows-gnu --locked 2>&1 | tail -10
```

Expected: clean. If the target isn't installed, skip — CI will gate this.

- [ ] **Step 6: `cargo deny check` — confirms no advisory or license surprise from the new dep**

```bash
cargo deny check 2>&1 | tail -20
```

Expected: clean. If new advisories surface, escalate before proceeding.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rimap-server/Cargo.toml
git commit -m "deps: add windows-service crate (cfg(windows) only) for issue #129"
```

---

## Task 4: Add `service` subcommand to the CLI

**Files:**
- Modify: `crates/rimap-server/src/cli/mod.rs`

Adds the new `Service { action }` arm and a `ServiceAction` enum with `Install`, `Uninstall`, `Run` variants. The arm is gated `#[cfg(windows)]` so the surface is invisible on non-Windows targets. Behavior wiring lands in Task 13 — this task is purely the parser definition + tests.

- [ ] **Step 1: Write failing tests**

Append to the existing `#[cfg(test)] mod tests` block in `crates/rimap-server/src/cli/mod.rs`:

```rust
    #[cfg(windows)]
    #[test]
    fn parses_service_install_with_all_flags() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "service",
            "install",
            "--name",
            "RustyImapMcpTest",
            "--config",
            r"C:\rusty.toml",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Install { name, config } => {
                    assert_eq!(name.as_deref(), Some("RustyImapMcpTest"));
                    assert_eq!(config, Some(std::path::PathBuf::from(r"C:\rusty.toml")));
                }
                other => panic!("expected Install, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_uninstall_with_default_name() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "service", "uninstall"]).unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Uninstall { name } => assert!(name.is_none()),
                other => panic!("expected Uninstall, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_run() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "service", "run"]).unwrap();
        match cli.command {
            Some(Command::Service { action }) => match action {
                ServiceAction::Run => {}
                other => panic!("expected Run, got {other:?}"),
            },
            other => panic!("expected Service, got {other:?}"),
        }
    }
```

The `ServiceAction` import is added to the test module's `use` block:

```rust
    #[cfg(windows)]
    use crate::cli::ServiceAction;
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
# On Windows:
cargo test -p rimap-server --lib cli::tests::parses_service 2>&1 | tail -10
# On non-Windows: tests are gated out and won't run, but cargo check
# proves the CFG gating is correct:
cargo check -p rimap-server --tests --locked 2>&1 | tail -5
```

Expected on Windows: FAIL with `cannot find type 'ServiceAction'`. Expected on non-Windows: tests compile (gated out).

- [ ] **Step 3: Add the `Service` Command arm and `ServiceAction` enum**

Modify `crates/rimap-server/src/cli/mod.rs`. In the `Command` enum, after the `Shim` variant, add:

```rust
    /// Windows Service Control Manager integration (issue #129).
    /// Install / uninstall the User Service Template, or enter the
    /// SCM-driven service entry point. Windows-only.
    #[cfg(windows)]
    Service {
        /// Service-management action.
        #[command(subcommand)]
        action: ServiceAction,
    },
```

After the `AuditAction` enum, add:

```rust
/// Actions under `rusty-imap-mcp service <action>`. Windows-only.
#[cfg(windows)]
#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Register the daemon as a User Service Template. Requires Administrator.
    Install {
        /// Service name (default: `RustyImapMcp`).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Config file path baked into the registered command line. If
        /// omitted, falls back to `RUSTY_IMAP_MCP_CONFIG` / the platform
        /// default at install time.
        #[arg(long, value_name = "PATH")]
        config: Option<std::path::PathBuf>,
    },
    /// Remove the User Service Template registration. Idempotent.
    /// Requires Administrator.
    Uninstall {
        /// Service name (default: `RustyImapMcp`).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// SCM-only entry point. Invoked by the Service Control Manager;
    /// not for interactive use. See `rusty-imap-mcp daemon` for the
    /// foreground equivalent.
    Run,
}
```

- [ ] **Step 4: Run the tests**

```bash
# On Windows:
cargo test -p rimap-server --lib cli::tests::parses_service 2>&1 | tail -10
# Cross-platform parser regression:
cargo test -p rimap-server --lib cli::tests 2>&1 | tail -10
```

Expected: all tests PASS on every platform.

- [ ] **Step 5: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`**

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/cli/mod.rs
git commit -m "feat(rimap-server): add cfg(windows) service subcommand to CLI"
```

---

## Task 5: Skeleton `service` module behind `cfg(windows)`

**Files:**
- Create: `crates/rimap-server/src/service/mod.rs`
- Create: `crates/rimap-server/src/service/run.rs` (empty body)
- Create: `crates/rimap-server/src/service/install.rs` (empty body)
- Create: `crates/rimap-server/src/service/tracing_sink.rs` (empty body)
- Modify: `crates/rimap-server/src/lib.rs`

Establish module structure with `cfg(windows)` gating. Each leaf file gets a one-line doc comment plus `#![cfg(windows)]` so any subsequent task can fill it in without touching boilerplate.

- [ ] **Step 1: Create `crates/rimap-server/src/service/mod.rs`**

```rust
//! Windows Service Control Manager integration (issue #129).
//!
//! Provides the per-user User Service Template install/uninstall surface
//! plus the `ServiceMain` body that translates SCM stop control into the
//! daemon's `Arc<Notify>` shutdown.

#![cfg(windows)]

pub mod install;
pub mod run;
pub(crate) mod tracing_sink;

/// Default User Service Template name used when `--name` is omitted.
pub const SERVICE_NAME_DEFAULT: &str = "RustyImapMcp";

/// User-facing display name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "Rusty IMAP MCP";

/// One-line description shown in `services.msc`.
pub const SERVICE_DESCRIPTION: &str =
    "Audit-logged Model Context Protocol server for IMAP email.";
```

- [ ] **Step 2: Create `crates/rimap-server/src/service/run.rs`**

```rust
//! `ServiceMain` body, control-handler factory, and SCM dispatcher entry.
//! Implementation lands in subsequent tasks; this stub establishes the
//! module so siblings can compile against it.

#![cfg(windows)]
```

- [ ] **Step 3: Create `crates/rimap-server/src/service/install.rs`**

```rust
//! User Service Template install / uninstall via the `windows-service`
//! crate's `ServiceManager`. Implementation lands in Tasks 9–10.

#![cfg(windows)]
```

- [ ] **Step 4: Create `crates/rimap-server/src/service/tracing_sink.rs`**

```rust
//! Resolve and open the daemon log file the service path redirects
//! `tracing` events to. Implementation lands in Task 6.

#![cfg(windows)]
```

- [ ] **Step 5: Wire the module into the lib crate**

Edit `crates/rimap-server/src/lib.rs`. Find the `pub mod` block and add:

```rust
#[cfg(windows)]
pub mod service;
```

- [ ] **Step 6: Verify compilation**

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5
```

Expected: clean (the new module is empty cfg-gated stubs).

If the host can cross-build to Windows:

```bash
cargo check --workspace --target x86_64-pc-windows-gnu --locked 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/service crates/rimap-server/src/lib.rs
git commit -m "feat(rimap-server): scaffold cfg(windows) service module skeleton"
```

---

## Task 6: Implement `service::tracing_sink`

**Files:**
- Modify: `crates/rimap-server/src/service/tracing_sink.rs`

Resolves `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log`, ensures the parent directory exists, opens append-only with `share_mode(0)` (no inheritable handles), returns a `std::fs::File`. The caller (Task 12) wraps it in a `Mutex` and hands it to `init_to_writer`.

A test override hook (`override_local_app_data` env var, gated `#[cfg(test)]`) lets the unit test point the resolver at a tempdir.

- [ ] **Step 1: Write failing tests**

Add to `crates/rimap-server/src/service/tracing_sink.rs` (replacing the stub created in Task 5):

```rust
//! Resolve and open the daemon log file the service path redirects
//! `tracing` events to.

#![cfg(windows)]

use std::path::PathBuf;

/// Subdirectory under the resolved local-app-data root.
const APP_SUBDIR: &str = "rusty-imap-mcp";

/// File name for daemon trace output.
const LOG_FILE_NAME: &str = "daemon.log";

/// Resolve the log directory for the current user under
/// `%LOCALAPPDATA%`. Errors if the env var is unset or the resulting
/// path is invalid.
fn resolve_log_dir() -> std::io::Result<PathBuf> {
    #[cfg(test)]
    if let Ok(override_path) = std::env::var("RIMAP_TRACING_SINK_OVERRIDE") {
        return Ok(PathBuf::from(override_path).join(APP_SUBDIR));
    }
    let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "LOCALAPPDATA environment variable is not set",
        )
    })?;
    Ok(PathBuf::from(local).join(APP_SUBDIR))
}

/// Resolve the full path of `daemon.log` without creating anything.
pub(crate) fn log_file_path() -> std::io::Result<PathBuf> {
    Ok(resolve_log_dir()?.join(LOG_FILE_NAME))
}

/// Ensure the log directory exists and open `daemon.log` append-only,
/// non-inheritable. Returns the open file handle.
pub(crate) fn open_log_file() -> std::io::Result<std::fs::File> {
    let path = log_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    /// Restore-on-drop guard so concurrent tests don't observe a stomped
    /// override env var.
    struct EnvOverride {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvOverride {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let prior = std::env::var_os(key);
            // SAFETY: `unsafe_code = "forbid"` blocks raw FFI but allows
            // safe std calls. set_var is safe.
            std::env::set_var(key, value);
            Self { key, prior }
        }
    }

    impl Drop for EnvOverride {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn open_log_file_creates_parent_and_opens_appendable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _g = EnvOverride::set("RIMAP_TRACING_SINK_OVERRIDE", tmp.path());
        let mut f = super::open_log_file().expect("open");
        f.write_all(b"hello\n").expect("write");
        drop(f);
        let mut f2 = super::open_log_file().expect("reopen");
        f2.write_all(b"world\n").expect("write");
        drop(f2);
        let final_path = tmp.path().join(super::APP_SUBDIR).join(super::LOG_FILE_NAME);
        let bytes = std::fs::read(&final_path).expect("read");
        assert_eq!(bytes, b"hello\nworld\n");
    }

    #[test]
    fn log_file_path_uses_override() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _g = EnvOverride::set("RIMAP_TRACING_SINK_OVERRIDE", tmp.path());
        let p = super::log_file_path().expect("path");
        assert!(p.starts_with(tmp.path()));
        assert!(p.ends_with(super::LOG_FILE_NAME));
    }
}
```

`std::env::set_var` was made `unsafe` in 2024 edition for a soundness reason — we have to use the `unsafe { ... }` form. **But** the workspace forbids `unsafe_code` outright. The cleanest path: use `temp-env` which provides safe scoped overrides. The crate is already a dev-dependency of `rimap-server` (visible in the existing `[dev-dependencies]` block).

Replace the `EnvOverride` struct and both tests with:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write as _;

    #[test]
    fn open_log_file_creates_parent_and_opens_appendable() {
        let tmp = tempfile::tempdir().unwrap();
        let path_owned = tmp.path().to_path_buf();
        temp_env::with_var(
            "RIMAP_TRACING_SINK_OVERRIDE",
            Some(path_owned.as_os_str()),
            || {
                let mut f = super::open_log_file().unwrap();
                f.write_all(b"hello\n").unwrap();
                drop(f);
                let mut f2 = super::open_log_file().unwrap();
                f2.write_all(b"world\n").unwrap();
                drop(f2);
                let final_path = path_owned
                    .join(super::APP_SUBDIR)
                    .join(super::LOG_FILE_NAME);
                let bytes = std::fs::read(&final_path).unwrap();
                assert_eq!(bytes, b"hello\nworld\n");
            },
        );
    }

    #[test]
    fn log_file_path_uses_override() {
        let tmp = tempfile::tempdir().unwrap();
        let path_owned = tmp.path().to_path_buf();
        temp_env::with_var(
            "RIMAP_TRACING_SINK_OVERRIDE",
            Some(path_owned.as_os_str()),
            || {
                let p = super::log_file_path().unwrap();
                assert!(p.starts_with(&path_owned));
                assert!(p.ends_with(super::LOG_FILE_NAME));
            },
        );
    }
}
```

- [ ] **Step 2: Run the tests**

```bash
# On Windows:
cargo test -p rimap-server --lib service::tracing_sink::tests 2>&1 | tail -10
```

Expected on Windows: PASS for both. On non-Windows, the module is `cfg(windows)`-gated and the tests don't compile in — so cross-platform regression is just `cargo check`:

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 3: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`**

Expected: clean. If clippy flags `expect_used` inside the test module, the `#[expect(clippy::unwrap_used, reason = "tests")]` annotation already covers it; promote to a wider `#[expect(clippy::expect_used, reason = "tests")]` if needed.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/service/tracing_sink.rs
git commit -m "feat(rimap-server): resolve and open daemon.log under %LOCALAPPDATA%"
```

---

## Task 7: `ServiceExitCode` enum

**Files:**
- Modify: `crates/rimap-server/src/service/run.rs`

Stable mapping from boot-failure classes to the `service_specific` field SCM logs in the System event log. Defined in `run.rs` so the `service_main` body and any helper share one source.

- [ ] **Step 1: Write the failing test**

Replace the stub in `crates/rimap-server/src/service/run.rs` with:

```rust
//! `ServiceMain` body, control-handler factory, and SCM dispatcher entry.

#![cfg(windows)]

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod exit_code_tests {
    use super::ServiceExitCode;

    #[test]
    fn variant_codes_are_stable_and_distinct() {
        assert_eq!(ServiceExitCode::ConfigLoad as u32, 1);
        assert_eq!(ServiceExitCode::AuditOpen as u32, 2);
        assert_eq!(ServiceExitCode::RegistryBuild as u32, 3);
        assert_eq!(ServiceExitCode::ListenerBind as u32, 4);
        assert_eq!(ServiceExitCode::RuntimeFailure as u32, 5);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

```bash
# On Windows:
cargo test -p rimap-server --lib service::run::exit_code_tests 2>&1 | tail -5
```

Expected: FAIL — `cannot find type 'ServiceExitCode'`.

- [ ] **Step 3: Add `ServiceExitCode` enum**

Insert after the module-level `#![cfg(windows)]` directive in `service/run.rs`:

```rust
/// Stable SCM `service_specific` exit codes for the boot-failure paths
/// in `run_with_shutdown`. SCM surfaces these in the System event log;
/// operators correlate them with `daemon.log` to identify the failure
/// class without reading source.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExitCode {
    /// Config loading or validation failed.
    ConfigLoad = 1,
    /// Audit log open / lock failed.
    AuditOpen = 2,
    /// Account registry build failed (per-account credential / IMAP setup).
    RegistryBuild = 3,
    /// Listener bind failed (named pipe creation).
    ListenerBind = 4,
    /// Generic runtime failure not covered by the more specific variants.
    RuntimeFailure = 5,
}
```

- [ ] **Step 4: Run test**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/service/run.rs
git commit -m "feat(rimap-server): add ServiceExitCode enum for SCM boot-failure mapping"
```

---

## Task 8: Control-handler factory

**Files:**
- Modify: `crates/rimap-server/src/service/run.rs`

The `service_main` body needs a closure that translates SCM control events (`Stop`, `Shutdown`, `Interrogate`) into shutdown signals. Extracting it into a factory `make_event_handler(shutdown, status_handle, current_state)` makes it unit-testable without an actual SCM dispatcher.

To keep the factory testable without depending on `ServiceStatusHandle` (an opaque type owned by SCM), parameterize over a small trait the production path implements for `ServiceStatusHandle` and the test path implements for an in-memory recorder.

- [ ] **Step 1: Write failing tests**

Append to `crates/rimap-server/src/service/run.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod control_handler_tests {
    use std::sync::{Arc, Mutex};

    use windows_service::service::{ServiceControl, ServiceState};
    use windows_service::service_control_handler::ServiceControlHandlerResult;

    use super::{make_event_handler, StatusReporter};

    /// In-memory `StatusReporter` recording every state transition.
    #[derive(Default, Clone)]
    struct RecordingReporter {
        events: Arc<Mutex<Vec<ServiceState>>>,
    }

    impl StatusReporter for RecordingReporter {
        fn report(&self, state: ServiceState) {
            self.events.lock().unwrap().push(state);
        }
    }

    #[tokio::test]
    async fn stop_control_signals_shutdown_and_reports_stop_pending() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let waiter = {
            let n = Arc::clone(&shutdown);
            tokio::spawn(async move { n.notified().await })
        };
        let result = handler(ServiceControl::Stop);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        // Notified() was already pending when notify_waiters fires, so the
        // spawned task must complete promptly.
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("shutdown signal was not delivered")
            .expect("waiter join");
        assert_eq!(
            reporter.events.lock().unwrap().as_slice(),
            &[ServiceState::StopPending],
        );
    }

    #[tokio::test]
    async fn shutdown_control_signals_shutdown_and_reports_stop_pending() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let waiter = {
            let n = Arc::clone(&shutdown);
            tokio::spawn(async move { n.notified().await })
        };
        let result = handler(ServiceControl::Shutdown);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("shutdown signal was not delivered")
            .expect("waiter join");
        assert_eq!(
            reporter.events.lock().unwrap().as_slice(),
            &[ServiceState::StopPending],
        );
    }

    #[test]
    fn interrogate_returns_no_error_without_signalling_shutdown() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let result = handler(ServiceControl::Interrogate);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert!(reporter.events.lock().unwrap().is_empty());
    }

    #[test]
    fn unrecognised_control_returns_not_implemented() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        // ServiceControl is non-exhaustive; pick a control we don't handle.
        let result = handler(ServiceControl::ParamChange);
        assert!(matches!(
            result,
            ServiceControlHandlerResult::NotImplemented,
        ));
        assert!(reporter.events.lock().unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
# On Windows:
cargo test -p rimap-server --lib service::run::control_handler_tests 2>&1 | tail -10
```

Expected: FAIL with `cannot find function 'make_event_handler'` and `cannot find trait 'StatusReporter'`.

- [ ] **Step 3: Implement the factory**

Insert above the test module in `service/run.rs`:

```rust
use std::sync::Arc;

use tokio::sync::Notify;
use windows_service::service::{ServiceControl, ServiceState};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

/// Abstraction over the SCM `ServiceStatusHandle` so the control-handler
/// closure can be unit-tested without an actual dispatcher.
pub(crate) trait StatusReporter: Send + Sync + 'static {
    fn report(&self, state: ServiceState);
}

/// Production `StatusReporter` wrapping an SCM-provided `ServiceStatusHandle`.
#[derive(Clone)]
pub(crate) struct ScmReporter {
    handle: ServiceStatusHandle,
    /// Cached `ServiceType` value used in every status update.
    service_type: windows_service::service::ServiceType,
}

impl ScmReporter {
    pub(crate) fn new(
        handle: ServiceStatusHandle,
        service_type: windows_service::service::ServiceType,
    ) -> Self {
        Self {
            handle,
            service_type,
        }
    }
}

impl StatusReporter for ScmReporter {
    fn report(&self, state: ServiceState) {
        let status = windows_service::service::ServiceStatus {
            service_type: self.service_type,
            current_state: state,
            controls_accepted: match state {
                ServiceState::Running => {
                    windows_service::service::ServiceControlAccept::STOP
                        | windows_service::service::ServiceControlAccept::SHUTDOWN
                }
                _ => windows_service::service::ServiceControlAccept::empty(),
            },
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(5),
            process_id: None,
        };
        if let Err(e) = self.handle.set_service_status(status) {
            tracing::error!(error = %e, ?state, "set_service_status failed");
        }
    }
}

/// Build the closure SCM hands every control event. `Stop` and `Shutdown`
/// signal the daemon's shutdown `Notify` and report `StopPending` via
/// `reporter`. `Interrogate` returns `NoError` without changing state.
/// Any other control returns `NotImplemented`.
pub(crate) fn make_event_handler<R: StatusReporter + Clone>(
    shutdown: Arc<Notify>,
    reporter: R,
) -> impl Fn(ServiceControl) -> ServiceControlHandlerResult + Send + Sync + 'static {
    move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            reporter.report(ServiceState::StopPending);
            shutdown.notify_waiters();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Register `make_event_handler(shutdown, ScmReporter::new(…))` with SCM
/// for the given service name. Returned `ServiceStatusHandle` is the
/// production reporter's underlying handle.
pub(crate) fn register_handler(
    name: &str,
    shutdown: Arc<Notify>,
    service_type: windows_service::service::ServiceType,
) -> Result<(ScmReporter, ServiceStatusHandle), windows_service::Error> {
    // We register first, then build the reporter from the returned handle,
    // then install the closure. To do that with one registration call we
    // build a placeholder reporter, register, swap in the real reporter.
    // Simpler in practice: capture an Arc<OnceLock<ScmReporter>>.
    use std::sync::OnceLock;
    let cell: Arc<OnceLock<ScmReporter>> = Arc::new(OnceLock::new());

    #[derive(Clone)]
    struct DeferredReporter(Arc<OnceLock<ScmReporter>>);
    impl StatusReporter for DeferredReporter {
        fn report(&self, state: ServiceState) {
            if let Some(r) = self.0.get() {
                r.report(state);
            }
        }
    }

    let handler = make_event_handler(shutdown, DeferredReporter(Arc::clone(&cell)));
    let handle = service_control_handler::register(name, handler)?;
    let reporter = ScmReporter::new(handle, service_type);
    let _ = cell.set(reporter.clone());
    Ok((reporter, handle))
}
```

- [ ] **Step 4: Run tests**

```bash
# On Windows:
cargo test -p rimap-server --lib service::run::control_handler_tests 2>&1 | tail -10
```

Expected: PASS for all four tests.

- [ ] **Step 5: `cargo clippy ... -D warnings`**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/service/run.rs
git commit -m "feat(rimap-server): add SCM control-handler factory + reporter trait"
```

---

## Task 9: Implement `service::install::install`

**Files:**
- Modify: `crates/rimap-server/src/service/install.rs`

Build the User Service Template registration via `ServiceManager::create_service` plus `update_failure_actions`. Map `ERROR_ACCESS_DENIED` to a friendly elevated-shell hint.

- [ ] **Step 1: Write failing tests**

Add to `crates/rimap-server/src/service/install.rs`:

```rust
//! User Service Template install + idempotent uninstall via `windows-service`.

#![cfg(windows)]

use std::path::PathBuf;

use anyhow::Context as _;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::service::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME_DEFAULT};

/// Inputs to [`install`]. Captures the resolved service name, the absolute
/// binary path SCM should launch, and the absolute config path baked into
/// the registered command line.
#[derive(Debug)]
pub struct InstallInputs {
    /// Service name. Defaults to [`SERVICE_NAME_DEFAULT`] when `None`.
    pub name: Option<String>,
    /// Absolute path of the binary to register. Resolve via
    /// `std::env::current_exe` at the call site.
    pub binary_path: PathBuf,
    /// Absolute config path. Bake this into the SCM command line so the
    /// service does not depend on env-var inheritance.
    pub config_path: PathBuf,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn installinputs_defaults_to_constant_when_name_missing() {
        let i = InstallInputs {
            name: None,
            binary_path: PathBuf::from(r"C:\bin\rusty-imap-mcp.exe"),
            config_path: PathBuf::from(r"C:\rusty.toml"),
        };
        assert_eq!(resolved_name(&i), SERVICE_NAME_DEFAULT);
    }

    #[test]
    fn installinputs_uses_explicit_name() {
        let i = InstallInputs {
            name: Some("RustyImapMcpTest".to_owned()),
            binary_path: PathBuf::from(r"C:\bin\rusty-imap-mcp.exe"),
            config_path: PathBuf::from(r"C:\rusty.toml"),
        };
        assert_eq!(resolved_name(&i), "RustyImapMcpTest");
    }

    #[test]
    fn launch_arguments_include_run_subcommand_and_config_path() {
        let args = launch_arguments(&PathBuf::from(r"C:\rusty.toml"));
        assert_eq!(args, vec!["service", "run", "--config", r"C:\rusty.toml"]);
    }
}

/// Internal helper: resolve the effective service name.
fn resolved_name(inputs: &InstallInputs) -> &str {
    inputs.name.as_deref().unwrap_or(SERVICE_NAME_DEFAULT)
}

/// Internal helper: SCM command-line arguments stored alongside the binary.
fn launch_arguments(config_path: &std::path::Path) -> Vec<String> {
    vec![
        "service".to_owned(),
        "run".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ]
}
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
cargo test -p rimap-server --lib service::install::tests 2>&1 | tail -10
```

Expected on Windows: FAIL — `resolved_name` and `launch_arguments` not yet defined.

- [ ] **Step 3: Add `install` and the helper bodies**

Append to `crates/rimap-server/src/service/install.rs`, after the test module:

```rust
/// Register the daemon as a User Service Template via SCM. Requires
/// Administrator. Idempotent on a logically-equivalent existing
/// registration is **not** guaranteed — callers should `uninstall` first
/// if they need to update fields.
///
/// # Errors
/// Returns an error wrapping the underlying `windows-service` error.
/// The most common case is `ERROR_ACCESS_DENIED`, which we re-emit with
/// the hint to re-run from an elevated shell.
pub fn install(inputs: &InstallInputs) -> anyhow::Result<()> {
    let name = resolved_name(inputs);
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(map_access_denied)
    .context("opening Service Control Manager")?;

    let info = ServiceInfo {
        name: std::ffi::OsString::from(name),
        display_name: std::ffi::OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS
            | ServiceType::USER_SERVICE
            | ServiceType::USER_SERVICE_INSTANCE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: inputs.binary_path.clone(),
        launch_arguments: launch_arguments(&inputs.config_path)
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect(),
        // The spec calls for `["Tcpip"]`. The exact type the
        // `windows-service` crate uses for this field
        // (`Vec<ServiceDependency>` vs `Vec<String>`) is version-dependent;
        // adapt to whatever the pinned version exposes. If construction
        // requires a typed `ServiceDependency`, build it from
        // `ServiceDependency::Service("Tcpip".to_owned())` or the
        // version's equivalent constructor — do not invent unfamiliar
        // APIs.
        dependencies: vec![windows_service::service::ServiceDependency::Service(
            "Tcpip".to_owned(),
        )],
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(
            &info,
            ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(map_access_denied)
        .context("creating service registration")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(map_access_denied)
        .context("setting service description")?;

    apply_recovery_actions(&service)
        .context("setting service recovery (failure) actions")?;

    Ok(())
}

/// Apply restart-on-failure recovery: 30 s delay, twice, no-op on third
/// failure; reset failure counter after 1 hour clean run.
fn apply_recovery_actions(
    service: &windows_service::service::Service,
) -> Result<(), windows_service::Error> {
    use windows_service::service::{ServiceAction, ServiceActionType, ServiceFailureActions};
    let actions = vec![
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: std::time::Duration::from_secs(30),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: std::time::Duration::from_secs(30),
        },
        ServiceAction {
            action_type: ServiceActionType::None,
            delay: std::time::Duration::from_secs(0),
        },
    ];
    let failure = ServiceFailureActions {
        reset_period: windows_service::service::ServiceFailureResetPeriod::After(
            std::time::Duration::from_secs(3600),
        ),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    };
    service.update_failure_actions(failure)
}

/// Map `ERROR_ACCESS_DENIED` to a friendly hint; pass other errors through.
fn map_access_denied(e: windows_service::Error) -> anyhow::Error {
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(5) {
            return anyhow::anyhow!(
                "ERROR_ACCESS_DENIED — re-run this command from an elevated shell \
                 (Administrator). underlying error: {e}"
            );
        }
    }
    anyhow::Error::from(e)
}
```

The `windows-service` crate API surface evolves between versions; the `service::Service` type and field names above match the 0.7 generation. If `cargo check` flags missing fields or renamed types after the version pinned in Task 3, update the call sites against the version's actual `service.rs` module — do not invent fields.

- [ ] **Step 4: Run tests**

```bash
cargo test -p rimap-server --lib service::install::tests 2>&1 | tail -10
```

Expected on Windows: PASS for all three.

- [ ] **Step 5: `cargo clippy ... -D warnings`**

Expected: clean. If clippy flags `large_futures` or similar on the install path, escalate — don't suppress.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/service/install.rs
git commit -m "feat(rimap-server): implement service install via windows-service crate"
```

---

## Task 10: Implement `service::install::uninstall`

**Files:**
- Modify: `crates/rimap-server/src/service/install.rs`

Idempotent removal: open the service handle by name, call `delete()`. "Service does not exist" is success.

- [ ] **Step 1: Write failing tests**

Append to the existing test module in `crates/rimap-server/src/service/install.rs`:

```rust
    #[test]
    fn uninstall_inputs_default_to_constant_when_name_missing() {
        let inputs = UninstallInputs { name: None };
        assert_eq!(resolved_uninstall_name(&inputs), SERVICE_NAME_DEFAULT);
    }

    #[test]
    fn uninstall_inputs_use_explicit_name() {
        let inputs = UninstallInputs {
            name: Some("RustyImapMcpTest".to_owned()),
        };
        assert_eq!(resolved_uninstall_name(&inputs), "RustyImapMcpTest");
    }
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
cargo test -p rimap-server --lib service::install::tests::uninstall 2>&1 | tail -10
```

Expected: FAIL — `cannot find type 'UninstallInputs'`.

- [ ] **Step 3: Add `UninstallInputs` and `uninstall`**

Append to `crates/rimap-server/src/service/install.rs`:

```rust
/// Inputs to [`uninstall`].
#[derive(Debug)]
pub struct UninstallInputs {
    /// Service name. Defaults to [`SERVICE_NAME_DEFAULT`] when `None`.
    pub name: Option<String>,
}

fn resolved_uninstall_name(inputs: &UninstallInputs) -> &str {
    inputs.name.as_deref().unwrap_or(SERVICE_NAME_DEFAULT)
}

/// Remove the User Service Template registration. Idempotent: a missing
/// service is treated as success.
///
/// # Errors
/// Returns an error wrapping the underlying `windows-service` error,
/// except for "service does not exist" which is logged and swallowed.
/// `ERROR_ACCESS_DENIED` is re-emitted with the elevated-shell hint.
pub fn uninstall(inputs: &UninstallInputs) -> anyhow::Result<()> {
    let name = resolved_uninstall_name(inputs);
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .map_err(map_access_denied)
    .context("opening Service Control Manager")?;

    let service = match manager.open_service(name, ServiceAccess::DELETE) {
        Ok(s) => s,
        Err(e) => {
            // `windows_service::Error::Winapi(io)` with raw_os_error == 1060
            // (ERROR_SERVICE_DOES_NOT_EXIST) is the idempotent success case.
            if let windows_service::Error::Winapi(io) = &e {
                if io.raw_os_error() == Some(1060) {
                    tracing::info!(service = name, "service not registered; uninstall is a no-op");
                    return Ok(());
                }
            }
            return Err(map_access_denied(e)).context("opening service for delete");
        }
    };

    service
        .delete()
        .map_err(map_access_denied)
        .context("deleting service registration")?;
    tracing::info!(service = name, "service uninstalled");
    Ok(())
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p rimap-server --lib service::install::tests 2>&1 | tail -10
```

Expected on Windows: PASS for all five tests in the module (three from Task 9 + two from this task).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/service/install.rs
git commit -m "feat(rimap-server): implement idempotent service uninstall"
```

---

## Task 11: Windows install/uninstall integration test

**Files:**
- Create: `crates/rimap-server/tests/service_install_uninstall.rs`

Integration test that exercises the full install → query → uninstall round trip against a unique service name. Skipped cleanly when the test process lacks Administrator (so dev machines without elevation pass).

- [ ] **Step 1: Write the test**

Create `crates/rimap-server/tests/service_install_uninstall.rs`:

```rust
//! Integration test: round-trip install → query → uninstall against a
//! uniquely-named User Service Template. Requires Administrator;
//! skips cleanly when not elevated (raw_os_error 5 from
//! ServiceManager::local_computer with CREATE_SERVICE access).

#![cfg(windows)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::path::PathBuf;

use rimap_server::service::install::{install, uninstall, InstallInputs, UninstallInputs};
use windows_service::service::{ServiceAccess};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

fn unique_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("RustyImapMcpTest_{nanos:x}_{}", std::process::id())
}

/// Returns true if SCM access is denied (test process not elevated).
fn elevation_denied(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("ERROR_ACCESS_DENIED")
}

#[test]
fn install_query_uninstall_round_trip() {
    let name = unique_name();
    let inputs = InstallInputs {
        name: Some(name.clone()),
        binary_path: std::env::current_exe().unwrap(),
        config_path: PathBuf::from(r"C:\nonexistent-test-config.toml"),
    };

    match install(&inputs) {
        Ok(()) => {}
        Err(e) if elevation_denied(&e) => {
            eprintln!("SKIP: install requires Administrator; ran as standard user. Error: {e:#}");
            return;
        }
        Err(e) => panic!("install failed: {e:#}"),
    }

    // Confirm the registration is visible to a fresh ServiceManager handle.
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
    let _service = manager
        .open_service(&name, ServiceAccess::QUERY_STATUS)
        .expect("service should be queryable after install");

    // Uninstall — first call deletes it.
    uninstall(&UninstallInputs {
        name: Some(name.clone()),
    })
    .expect("uninstall");

    // Idempotent — second call against the same name succeeds.
    uninstall(&UninstallInputs { name: Some(name) }).expect("idempotent uninstall");
}
```

- [ ] **Step 2: Run the test**

```bash
# On a Windows host (CI or local). Skip on macOS/Linux:
cargo test -p rimap-server --test service_install_uninstall 2>&1 | tail -10
```

Expected on Windows-elevated: PASS. On Windows-non-elevated: PASS with `SKIP:` message. On non-Windows: not built (the file is `cfg(windows)`).

- [ ] **Step 3: `cargo check` cross-platform**

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/service_install_uninstall.rs
git commit -m "test(rimap-server): integration round-trip for service install/uninstall"
```

---

## Task 12: Implement the `service_main` body

**Files:**
- Modify: `crates/rimap-server/src/service/run.rs`

The SCM-facing function. Builds a current-thread tokio runtime, registers the control handler, runs the daemon body via `daemon::run::run_with_shutdown`, drives status transitions, opens the daemon log file, and reports the final `Stopped` state.

- [ ] **Step 1: Add the FFI service-main shim and the dispatcher entry**

Append to `crates/rimap-server/src/service/run.rs`:

```rust
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use windows_service::service::{ServiceExitCode as ScmExitCode, ServiceStatus, ServiceType};
use windows_service::service_dispatcher;

/// `windows_service::define_windows_service!` expands to the FFI-callable
/// shim SCM jumps to. The shim hands control to `service_main_impl`
/// (defined below) which carries the actual logic.
windows_service::define_windows_service!(ffi_service_main, service_main_impl);

/// Service type used in every status update.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Enter the SCM dispatcher. Called from the CLI handler for
/// `service run`. Returns when SCM disconnects (i.e. after `Stopped`
/// has been reported and `service_main` has returned).
///
/// # Errors
/// Returns an error if the dispatcher fails to start. The most common
/// case is `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when the verb is
/// run interactively rather than by SCM; we map that to a friendly
/// message at the CLI layer.
pub fn dispatch(name: &str) -> Result<(), windows_service::Error> {
    service_dispatcher::start(name, ffi_service_main)
}

fn service_main_impl(_args: Vec<OsString>) {
    if let Err(e) = run_service_main() {
        tracing::error!(error = %e, "service_main exited with error");
    }
}

fn run_service_main() -> anyhow::Result<()> {
    // Resolve the config path the install step baked into the SCM command
    // line. Falls back to the same env-var / platform-default chain
    // `daemon` uses when `--config` is omitted, so a misconfigured
    // registration still makes a best-effort start.
    let config_path = resolve_service_config_path()?;

    // Open the daemon log file BEFORE installing the tracing subscriber,
    // so the very first events land on disk. Stderr fallback when the
    // file cannot be created — under SCM that's lost unless the operator
    // configured `sc.exe failure` redirection, but the SCM exit code path
    // still surfaces the failure class.
    match crate::service::tracing_sink::open_log_file() {
        Ok(file) => {
            // tracing-subscriber's blanket MakeWriter impl covers
            // `Arc<Mutex<W>>` for any `W: io::Write`. The Arc is needed
            // because `init_to_writer` wants `Send + Sync + 'static`.
            let writer = std::sync::Arc::new(std::sync::Mutex::new(file));
            crate::boot::logging::init_to_writer(writer);
        }
        Err(e) => {
            crate::boot::logging::init();
            tracing::warn!(error = %e, "could not open daemon log file; falling back to stderr");
        }
    }

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let (reporter, _status_handle) = register_handler(
        crate::service::SERVICE_NAME_DEFAULT,
        std::sync::Arc::clone(&shutdown),
        SERVICE_TYPE,
    )
    .map_err(|e| anyhow::anyhow!("registering service control handler: {e}"))?;

    // StartPending while we boot the runtime + bind the listener.
    set_status(&reporter, ServiceState::StartPending, 0, Duration::from_secs(5));

    // Current-thread runtime so we don't need `run_with_shutdown`'s
    // returned future to be `Send`. `boot::registry::build` has a known
    // rustc HRTB rough edge that prevents `tokio::spawn`'ing this future
    // on a multi-thread runtime; driving it directly via `block_on` on a
    // current-thread runtime sidesteps the issue cleanly. See plan
    // commit history for the empirical verification.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("building tokio runtime: {e}"))?;

    let reporter_for_async = reporter.clone();
    let result: anyhow::Result<()> = runtime.block_on(async move {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let daemon_fut = crate::daemon::run::run_with_shutdown(
            config_path,
            shutdown,
            Some(started_tx),
        );
        tokio::pin!(daemon_fut);

        // Race the daemon future against the bind-ready signal and a
        // generous deadline. `biased` prevents an instant-error daemon
        // boot from being missed in favor of started_rx (which would
        // never fire in that case).
        let bind_outcome: BindResult = tokio::select! {
            biased;
            join = &mut daemon_fut => {
                // Daemon exited before firing started_tx — boot error.
                return join;
            }
            r = started_rx => match r {
                Ok(()) => BindResult::Ready,
                Err(_) => BindResult::SenderDropped,
            },
            () = tokio::time::sleep(Duration::from_secs(30)) => BindResult::Timeout,
        };

        if matches!(bind_outcome, BindResult::Ready) {
            // Listener is bound; report Running and let the daemon serve.
            set_status(
                &reporter_for_async,
                ServiceState::Running,
                0,
                Duration::from_secs(0),
            );
        }
        // SenderDropped / Timeout: still drive the daemon future to
        // completion so we can surface its actual error in `result`.
        // Ready: same path; we just also reported Running first.
        daemon_fut.await
    });

    let exit = match &result {
        Ok(()) => ScmExitCode::Win32(0),
        Err(e) => classify_boot_error(e),
    };
    report_stopped(&reporter, exit);

    Ok(())
}

/// Internal: emit a `ServiceStatus` snapshot via the reporter. Wraps the
/// repetitive `controls_accepted`/`exit_code` boilerplate the SCM API
/// requires for every transition.
fn set_status(
    reporter: &ScmReporter,
    state: ServiceState,
    checkpoint: u32,
    wait_hint: Duration,
) {
    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: match state {
            ServiceState::Running => {
                windows_service::service::ServiceControlAccept::STOP
                    | windows_service::service::ServiceControlAccept::SHUTDOWN
            }
            _ => windows_service::service::ServiceControlAccept::empty(),
        },
        exit_code: ScmExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    };
    if let Err(e) = reporter.handle.set_service_status(status) {
        tracing::error!(error = %e, ?state, "set_service_status failed");
    }
}

/// Internal: report `Stopped` with the supplied SCM exit code.
fn report_stopped(reporter: &ScmReporter, exit_code: ScmExitCode) {
    let status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: windows_service::service::ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    };
    if let Err(e) = reporter.handle.set_service_status(status) {
        tracing::error!(error = %e, "set_service_status(Stopped) failed");
    }
}

/// Outcome of awaiting the listener-bound signal.
#[derive(Debug)]
enum BindResult {
    /// `started_tx` fired — listener bound, ready to accept.
    Ready,
    /// `started_tx` was dropped without sending. The daemon future
    /// errored before reaching the bind step.
    SenderDropped,
    /// 30s deadline elapsed without the daemon firing `started_tx`.
    Timeout,
}

/// Inspect a daemon-future error and return the matching SCM exit code.
/// This is the boot-failure mapping the spec calls out.
fn classify_boot_error(e: &anyhow::Error) -> ScmExitCode {
    // Match by error chain context. `with_context(|| "loading config …")`
    // and similar contexts emitted by `run_with_shutdown` surface in
    // `format!("{e:#}")` — match substrings.
    let s = format!("{e:#}");
    if s.contains("loading config") {
        ScmExitCode::ServiceSpecific(ServiceExitCode::ConfigLoad as u32)
    } else if s.contains("opening audit log") {
        ScmExitCode::ServiceSpecific(ServiceExitCode::AuditOpen as u32)
    } else if s.contains("building account registry") {
        ScmExitCode::ServiceSpecific(ServiceExitCode::RegistryBuild as u32)
    } else if s.contains("creating named pipe") || s.contains("binding daemon socket") {
        ScmExitCode::ServiceSpecific(ServiceExitCode::ListenerBind as u32)
    } else {
        ScmExitCode::ServiceSpecific(ServiceExitCode::RuntimeFailure as u32)
    }
}

/// Resolve the config path the service should use. Mirrors the daemon
/// path's resolution but without taking a CLI override (SCM passes a
/// fully-baked command line so the override is the registered config).
fn resolve_service_config_path() -> anyhow::Result<PathBuf> {
    rimap_config::loader::resolve_config_path(None).ok_or_else(|| {
        anyhow::anyhow!(
            "no config path resolvable from env / platform default; \
             reinstall the service with `rusty-imap-mcp service install --config <path>`"
        )
    })
}
```

- [ ] **Step 2: Add a unit test for `classify_boot_error`**

Append to `service/run.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod classify_boot_error_tests {
    use super::*;

    #[test]
    fn config_load_error_maps_to_config_load_exit() {
        let err = anyhow::anyhow!("loading config /missing/path");
        match classify_boot_error(&err) {
            ScmExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::ConfigLoad as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }

    #[test]
    fn audit_open_error_maps_to_audit_open_exit() {
        let err = anyhow::anyhow!("opening audit log at /x");
        match classify_boot_error(&err) {
            ScmExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::AuditOpen as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }

    #[test]
    fn unknown_error_maps_to_runtime_failure_exit() {
        let err = anyhow::anyhow!("something we did not categorize");
        match classify_boot_error(&err) {
            ScmExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::RuntimeFailure as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }
}
```

- [ ] **Step 3: Run tests**

```bash
# On Windows:
cargo test -p rimap-server --lib service::run 2>&1 | tail -15
```

Expected on Windows: every test in `service::run::*` (control_handler_tests, exit_code_tests, classify_boot_error_tests) PASSES.

- [ ] **Step 4: Cross-platform `cargo check`**

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 5: `cargo clippy ... -D warnings`**

Expected: clean. If clippy flags `large_futures`, hoist offending allocations out of the future or `Box::pin` the `block_on` body — do not suppress. If it flags `await_holding_lock` (the `Arc<Mutex<File>>` writer), that's expected for a `MakeWriter` and the Mutex is `std::sync::Mutex`, not tokio's — should not trigger. Escalate if it does.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/service/run.rs
git commit -m "feat(rimap-server): implement ServiceMain body and SCM dispatcher entry"
```

---

## Task 13: Wire the new subcommands into `main.rs`

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

Three handlers: `Service { action: Install }` → `install(...)`, `Service { action: Uninstall }` → `uninstall(...)`, `Service { action: Run }` → defer logging init and call the SCM dispatcher.

- [ ] **Step 1: Add the dispatch arm**

In `crates/rimap-server/src/main.rs`'s `run` function (currently around line 44–111), add a new branch handling the Service command. Insert after the existing `Daemon` handler:

```rust
    #[cfg(windows)]
    if let Some(Command::Service { action }) = cli.command {
        return handle_service_action(action);
    }
```

Add the helper after `daemon_main`:

```rust
#[cfg(windows)]
fn handle_service_action(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    use rimap_server::service::install::{install, uninstall, InstallInputs, UninstallInputs};
    match action {
        crate::cli::ServiceAction::Install { name, config } => {
            let binary_path = std::env::current_exe()
                .context("resolving current binary path")?;
            let config_path = match config {
                Some(p) => p,
                None => resolve_or_default(None)?,
            };
            install(&InstallInputs {
                name,
                binary_path,
                config_path,
            })?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "service installed")?;
            Ok(())
        }
        crate::cli::ServiceAction::Uninstall { name } => {
            uninstall(&UninstallInputs { name })?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "service uninstalled")?;
            Ok(())
        }
        crate::cli::ServiceAction::Run => {
            rimap_server::service::run::dispatch(rimap_server::service::SERVICE_NAME_DEFAULT)
                .map_err(|e| {
                    if matches!(e, windows_service::Error::Winapi(ref io)
                        if io.raw_os_error() == Some(1063))
                    {
                        anyhow::anyhow!(
                            "this verb is for the Service Control Manager — \
                             see `rusty-imap-mcp daemon` for foreground use"
                        )
                    } else {
                        anyhow::Error::from(e)
                    }
                })
        }
    }
}
```

- [ ] **Step 2: Defer `logging::init` for `service run`**

Currently `main()` calls `logging::init()` unconditionally before parsing CLI (line 26). For the SCM service path the redirect must be selected before subscriber install. Change `main()` to:

```rust
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // The SCM service path installs its own subscriber pointed at the
    // daemon log file; everything else uses stderr.
    #[cfg(windows)]
    let defer_logging = matches!(
        cli.command,
        Some(Command::Service {
            action: crate::cli::ServiceAction::Run
        })
    );
    #[cfg(not(windows))]
    let defer_logging = false;

    if !defer_logging {
        logging::init();
    }

    if matches!(cli.command, Some(Command::Shim)) {
        return rimap_server::shim::run().await;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // If logging was deferred AND the dispatch returned without ever
            // initializing it (e.g. the dispatcher errored before
            // service_main_impl ran), fall back to a plain stderr write so
            // the operator sees the cause.
            if defer_logging {
                let _ = writeln!(std::io::stderr().lock(), "{e:#}");
            } else {
                tracing::error!("{e:#}");
            }
            ExitCode::FAILURE
        }
    }
}
```

The `tokio::main` macro builds a multi-threaded runtime that the SCM path never reaches the body of (`dispatch` blocks on its own `service_dispatcher::start` call, which spins up a fresh runtime inside `run_service_main`). The outer runtime is wasted in that path but harmless; eliminating it would require restructuring around an explicit runtime, which is out of scope.

- [ ] **Step 3: Run the existing CLI parser tests**

```bash
cargo test -p rimap-server --lib cli 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 4: Cross-platform `cargo check`**

```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 5: `cargo clippy ... -D warnings`**

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "feat(rimap-server): wire service install/uninstall/run subcommand handlers"
```

---

## Task 14: Delete `register-task.ps1`

**Files:**
- Delete: `scripts/packaging/register-task.ps1`

Replacing-not-deprecating per project rule. Operators upgrading should run `rusty-imap-mcp service install` from an elevated shell instead.

- [ ] **Step 1: Delete the file**

```bash
rm scripts/packaging/register-task.ps1
```

- [ ] **Step 2: Confirm no references remain**

```bash
rg -F register-task.ps1 . 2>&1 | tail -10
```

Expected: zero hits. If the README, CHANGELOG, or any doc references it, update those references in the same commit to point at `rusty-imap-mcp service install`.

- [ ] **Step 3: Commit**

```bash
git add -A scripts/packaging/
git commit -m "chore: remove v1 Task Scheduler script (replaced by service install)"
```

---

## Task 15: Manual smoke checklist

**Files:**
- Create: `docs/manual-tests/windows-service.md`

The manual step that gates a release including this change. Plain checklist — no scripting magic.

- [ ] **Step 1: Create the file**

```markdown
# Manual smoke checklist — Windows Service (issue #129)

Run on a Windows 10 (1703+) or Windows 11 host with a logged-in user.

## Setup

- Install the daemon binary at a stable path, e.g.
  `%LOCALAPPDATA%\Programs\rusty-imap-mcp\rusty-imap-mcp.exe`.
- Have a valid config file at a stable path, e.g.
  `%LOCALAPPDATA%\rusty-imap-mcp\config.toml`.
- Open an **elevated** PowerShell (Run as Administrator).

## Install

- [ ] `rusty-imap-mcp service install --config %LOCALAPPDATA%\rusty-imap-mcp\config.toml`
- [ ] `services.msc` shows **Rusty IMAP MCP** with status **Running** under
      the current user's account.
- [ ] `Get-Service RustyImapMcp | Format-List Name, Status, StartType` shows
      `Running` and `Automatic`.

## Lifecycle

- [ ] Connect a shim client; run a tool call. Confirm
      `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` contains tracing events
      and the audit log records a `tool_start` / `tool_end` pair.
- [ ] `sc.exe stop RustyImapMcp` returns with the service in **Stopped**
      state inside ~10 seconds.
- [ ] The audit log contains `session_end` for every active session
      and a final `process_end` record.

## Recovery

- [ ] Force a crash (kill the process from Task Manager). SCM restarts
      it within 30 s; `services.msc` returns to **Running**.

## Uninstall

- [ ] `rusty-imap-mcp service uninstall`
- [ ] `services.msc` no longer lists the service.
- [ ] `rusty-imap-mcp service uninstall` (idempotent) prints
      `service not registered; uninstall is a no-op` and exits 0.

## Cleanup

- [ ] Remove `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` and any test
      audit logs.

## Failure modes worth confirming once

- [ ] Run `rusty-imap-mcp service install` from a **non-elevated**
      shell. Expect a clear "ERROR_ACCESS_DENIED — re-run from an
      elevated shell" message.
- [ ] Run `rusty-imap-mcp service run` directly from an interactive
      shell. Expect "this verb is for the Service Control Manager — see
      `rusty-imap-mcp daemon` for foreground use" and a non-zero exit
      code.
```

- [ ] **Step 2: Commit**

```bash
git add docs/manual-tests/windows-service.md
git commit -m "docs: manual smoke checklist for Windows Service integration"
```

---

## Task 16: End-to-end CI verification

**Files:** none — verification only.

- [ ] **Step 1: Run the full local CI equivalent**

```bash
just ci 2>&1 | tail -30
```

Expected: PASS — formatting, clippy, unit tests, MSRV build, cargo-deny.

- [ ] **Step 2: Push and open a draft PR**

```bash
git push -u origin feat/issue-129-windows-service
gh pr create --draft --title "feat: Windows Service (SCM) integration (#129)" --body "$(cat <<'EOF'
## Summary
- Adds `service install` / `service uninstall` / `service run` subcommands (Windows-only).
- Replaces v1 Task Scheduler script with a User Service Template.
- Reuses existing daemon `Arc<Notify>` shutdown via `windows-service` crate.
- Workspace `unsafe_code = "forbid"` policy intact.

Closes #129. Spec: `docs/superpowers/specs/2026-05-02-issue-129-windows-service-design.md`. Plan: `docs/superpowers/plans/2026-05-02-issue-129-windows-service.md`. Follow-up Event Log integration: #213.

## Test plan
- [x] Cross-platform unit tests for `run_with_shutdown` signature and `init_to_writer`
- [x] Windows unit tests for control-handler closure, ServiceExitCode mapping, classify_boot_error
- [x] Windows integration round-trip test for install/uninstall (skips when not elevated)
- [ ] Manual smoke checklist (`docs/manual-tests/windows-service.md`) — gates release tag, not merge.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Verify CI status checks pass**

```bash
gh pr checks 2>&1 | tail -20
```

Expected: all required checks green (rustfmt, clippy, check macOS, test stable, test MSRV 1.88.0, cargo-deny, zizmor self-check, SonarQube). If any check fails, fix root cause — never merge with red.

- [ ] **Step 4: Mark PR ready for review**

```bash
gh pr ready
```

Halt here. Review feedback drives any follow-up commits.

---

## Self-review checklist (run by the implementer before requesting review)

Tick these against the spec, not from memory:

- [ ] Spec §"Decisions" items 1–7 each have a corresponding task.
- [ ] No task contains a placeholder, TBD, or "see Task N" reference without inlined detail.
- [ ] `unsafe_code = "forbid"` is unchanged in `Cargo.toml`.
- [ ] `cargo deny check` is clean.
- [ ] `windows-service` is gated to `cfg(windows)` consumers; non-Windows builds do not pull it.
- [ ] No behavior change on Linux or macOS (existing daemon test suites pass with the same counts).
- [ ] `scripts/packaging/register-task.ps1` is gone.
- [ ] `docs/manual-tests/windows-service.md` exists and the install/uninstall/lifecycle/recovery/error-mode boxes are concrete.
- [ ] Issue #213 is linked from the spec and appears in the PR body.
