# Polish PR 11 — Shim end-to-end test (#134)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new integration test `crates/rimap-server/tests/shim_happy_path.rs` that spawns the real `rusty-imap-mcp shim` binary as a subprocess and verifies it byte-pipes a minimal MCP `initialize` + `tools/list` exchange to a co-located test daemon. Closes the deferred Phase 5 item — the shim's "daemon present, frames flow" path is currently not covered end-to-end (the existing `shim_error_no_daemon.rs` covers only the absent-daemon failure path).

**Architecture:** Test-only. The daemon harness (`TestDaemon::spawn_bare`) already accepts a caller-supplied socket path. Construct the path the production resolver would produce under a tempdir-scoped `XDG_RUNTIME_DIR`, bind the daemon there, then spawn `rusty-imap-mcp shim` via `assert_cmd` with the same `XDG_RUNTIME_DIR` env. The shim's resolver lands on the same path and the byte pipe runs end-to-end. No production code changes.

**Tech Stack:** Rust, `assert_cmd` (already a dev-dep), `tempfile`, Tokio, `tokio::process` (or std `Command`).

---

## Why this is small and self-contained

The deferral lived only because the shim resolves its socket path independently from the harness's tempdir choice. The fix is to tell BOTH the daemon and the shim subprocess to use the same `XDG_RUNTIME_DIR`. The pattern is already used by `shim_error_no_daemon.rs` for the failure path; this PR is the happy-path companion.

No production code changes. The shim does NOT grow a `--socket-path` argument (option (b) from the issue body was rejected).

## Context the engineer must read first

Lesson 1 of `RESUME.md`: verify API assumptions before writing code blocks.

- `crates/rimap-server/tests/shim_error_no_daemon.rs` — full file (~65 lines). The `XDG_RUNTIME_DIR`-via-env pattern that the new test mirrors. Pay attention to:
  - The 0700 chmod on the tempdir (lines 24–25) — required because the resolver enforces freedesktop perms.
  - The `env_remove("TMPDIR")` (line 31) — keeps the resolver on the XDG branch on Linux.
  - The expected-path construction (lines 47–51) — verifies the resolver output deterministically.
- `crates/rimap-server/tests/common/daemon_harness.rs` — full file. `TestDaemon::spawn_bare` (line 117) takes a `socket_path: PathBuf` and binds it directly. Use this; the harness will NOT call the resolver itself.
- `crates/rimap-server/src/daemon/socket_path.rs` — confirm the resolver algorithm (Linux: `$XDG_RUNTIME_DIR/rusty-imap-mcp/daemon.sock`). The test reproduces the same `.join("rusty-imap-mcp").join("daemon.sock")` chain.
- `crates/rimap-server/src/shim/mod.rs` — read the shim's connect path (`UnixStream::connect(...)`) and `verify_socket_path(...)` (lines 27–58). Both must accept the test's socket: 0600 mode, owned by the test user. The bound listener inherits umask; if it lands at 0666 the shim will refuse — verify or chmod after bind.

## What "happy path" means here

The simplest meaningful exchange is `mcp/initialize` (client→server, with `"protocolVersion"` and `"capabilities"`), followed by the server's `initialize` response, then `tools/list` and its response. Anything beyond that bleeds into MCP-protocol surface coverage that other tests already handle.

The test asserts:
1. The shim subprocess exits 0 (or is killed cleanly after the exchange completes).
2. The server's `initialize` response is echoed on the shim's stdout — confirming bytes flowed both ways.
3. `tools/list` returns the two infrastructure tools (`use_account`, `list_accounts`) at minimum (the test daemon has an empty registry, so per-account tools won't appear).

## Files

- Create: `crates/rimap-server/tests/shim_happy_path.rs` — the new test.
- Optionally modify: `crates/rimap-server/tests/common/daemon_harness.rs` — add a small convenience helper if the test ends up needing one (Task 1 step 4).

No new dependencies. `assert_cmd`, `tempfile`, `tokio` are already in `[dev-dependencies]`.

## Task 1: Author the new integration test

**Files:**
- Create: `crates/rimap-server/tests/shim_happy_path.rs`

- [ ] **Step 1: Read the production resolver to confirm the path-construction algorithm**

```bash
sed -n '50,62p' crates/rimap-server/src/daemon/socket_path.rs
```

Verify: with `XDG_RUNTIME_DIR=<tempdir>`, the resolver returns `<tempdir>/rusty-imap-mcp/daemon.sock`. If the algorithm has changed since this plan was written (e.g., a different filename), update step 3's path-construction line to match.

- [ ] **Step 2: Confirm the listener binds at the resolver's path with 0600 mode**

The shim's `verify_socket_path` (in `crates/rimap-server/src/shim/mod.rs`) requires mode 0600. Confirm by running:

```bash
rg -n 'fn bind' crates/rimap-server/src/daemon/transport/unix.rs | head -3
```

Then read whatever `bind` does — if it sets 0600 on the bound socket file, no extra chmod is needed in the test. If not, the test must `chmod 0600` after bind. Check before writing the test body.

- [ ] **Step 3: Write the test**

Create `crates/rimap-server/tests/shim_happy_path.rs`:

```rust
//! Integration test: the shim byte-pipes a minimal MCP `initialize` +
//! `tools/list` exchange between stdin/stdout and the daemon socket.
//!
//! Closes #134 — the "daemon present, frames flow" path that was deferred
//! from Phase 5 of the multi-client-daemon plan.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;

use common::daemon_harness::{TestDaemon, test_daemon_state};

/// Build the socket path the production resolver would return when
/// `XDG_RUNTIME_DIR` is `runtime_dir` and `TMPDIR` is unset.
///
/// Mirrors `crates/rimap-server/src/daemon/socket_path.rs::resolve`.
/// Kept in sync by hand: if the resolver's algorithm changes, this
/// helper must change too. The companion test
/// `tests/shim_error_no_daemon.rs` does the same construction in
/// inline form.
fn resolved_socket_path(runtime_dir: &std::path::Path) -> PathBuf {
    runtime_dir.join("rusty-imap-mcp").join("daemon.sock")
}

#[tokio::test]
async fn shim_pipes_initialize_and_tools_list_through_real_binary() {
    // 1. Prepare a tempdir-scoped XDG_RUNTIME_DIR with the freedesktop
    //    contract (0700, owned by us).
    let runtime_dir = TempDir::new().expect("runtime dir");
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on runtime dir");

    // 2. Compute the path the shim's resolver will land on, then make
    //    sure its parent dir exists with mode 0700 so the listener
    //    can bind there.
    let socket_path = resolved_socket_path(runtime_dir.path());
    let socket_parent = socket_path.parent().expect("socket has a parent");
    std::fs::create_dir_all(socket_parent).expect("create socket parent dir");
    std::fs::set_permissions(socket_parent, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 on socket parent");

    // 3. Build a minimal DaemonState (empty registry — the test only
    //    exercises infrastructure tools).
    let audit_path = runtime_dir.path().join("audit.jsonl");
    let state = test_daemon_state(runtime_dir.path(), &audit_path);

    // 4. Spawn the daemon at the resolver's path. The TestDaemon owns
    //    the tempdir lifetime; we move it into the harness.
    let tempdir_clone = TempDir::new_in(runtime_dir.path()).expect("inner tempdir");
    let daemon = TestDaemon::spawn_bare(
        tempdir_clone,
        audit_path.clone(),
        socket_path.clone(),
        state,
    )
    .await;

    // 5. The bound socket file MUST be mode 0600 for the shim's
    //    verify_socket_path. If `UnixSocketListener::bind` already sets
    //    it (typical), this chmod is a no-op; otherwise it is required.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600 on bound socket");

    // 6. Spawn the real `rusty-imap-mcp shim` binary via assert_cmd's
    //    `cargo_bin` then handed to `tokio::process::Command` so the
    //    test can write/read async on the pipes. We avoid `assert_cmd`
    //    for the spawn itself because it's sync; we use it only to
    //    locate the binary path.
    let shim_bin =
        assert_cmd::cargo::cargo_bin("rusty-imap-mcp");
    let mut shim = Command::new(&shim_bin)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env_remove("TMPDIR") // force the XDG branch
        .arg("shim")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shim");

    let mut stdin = shim.stdin.take().expect("shim stdin");
    let stdout = shim.stdout.take().expect("shim stdout");
    let mut reader = BufReader::new(stdout).lines();

    // 7. Send `mcp/initialize` (id=1).
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "rimap-shim-e2e-test",
                "version": "0.0.1"
            }
        }
    });
    stdin
        .write_all(format!("{init_request}\n").as_bytes())
        .await
        .expect("write initialize");
    stdin.flush().await.expect("flush initialize");

    // 8. Read the initialize response with a 5s timeout — generous
    //    against CI scheduler jitter, well under the daemon's 5s drain
    //    bound so the test never sits idle longer than necessary.
    let init_resp = tokio::time::timeout(Duration::from_secs(5), reader.next_line())
        .await
        .expect("initialize response timeout")
        .expect("read initialize response")
        .expect("non-EOF initialize response");

    let init_resp_value: serde_json::Value =
        serde_json::from_str(&init_resp).expect("parse initialize response JSON");
    assert_eq!(init_resp_value["jsonrpc"], "2.0");
    assert_eq!(init_resp_value["id"], 1);
    assert!(
        init_resp_value["result"]["protocolVersion"].is_string(),
        "initialize response must carry a protocolVersion: {init_resp}",
    );

    // 9. Send `notifications/initialized` (per MCP spec).
    let initialized_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{initialized_notif}\n").as_bytes())
        .await
        .expect("write initialized notif");
    stdin.flush().await.expect("flush initialized notif");

    // 10. Send `tools/list` (id=2).
    let list_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    stdin
        .write_all(format!("{list_request}\n").as_bytes())
        .await
        .expect("write tools/list");
    stdin.flush().await.expect("flush tools/list");

    // 11. Read the tools/list response.
    let list_resp = tokio::time::timeout(Duration::from_secs(5), reader.next_line())
        .await
        .expect("tools/list timeout")
        .expect("read tools/list")
        .expect("non-EOF tools/list");

    let list_resp_value: serde_json::Value =
        serde_json::from_str(&list_resp).expect("parse tools/list response JSON");
    assert_eq!(list_resp_value["jsonrpc"], "2.0");
    assert_eq!(list_resp_value["id"], 2);

    let tools = list_resp_value["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools must be array");
    let tool_names: std::collections::BTreeSet<_> = tools
        .iter()
        .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        tool_names.contains("use_account"),
        "tools/list must include use_account; got: {tool_names:?}",
    );
    assert!(
        tool_names.contains("list_accounts"),
        "tools/list must include list_accounts; got: {tool_names:?}",
    );

    // 12. Close stdin so the shim sees EOF and exits, then collect.
    drop(stdin);
    let exit = tokio::time::timeout(Duration::from_secs(5), shim.wait())
        .await
        .expect("shim wait timeout")
        .expect("shim wait");
    assert!(
        exit.success(),
        "shim must exit 0 after EOF on stdin, got: {exit:?}",
    );

    // 13. Shutdown the daemon. The audit log will record session_start
    //    and session_end for the connection the shim made.
    let audit_log = daemon.shutdown().await;
    assert!(
        audit_log.contains(r#""kind":"session_start""#),
        "audit log must record the session; got:\n{audit_log}",
    );
    assert!(
        audit_log.contains(r#""kind":"session_end""#),
        "audit log must record the session_end; got:\n{audit_log}",
    );
}
```

- [ ] **Step 4: If `TestDaemon::spawn_bare` ends up not fitting the use case**

The plan above passes a separately-allocated inner `TempDir` into `spawn_bare` because the harness signature consumes a `TempDir` by value. If that creates ergonomic friction (e.g., the audit-path lifetime gets confusing), add a small `TestDaemon::spawn_bare_at` variant in `crates/rimap-server/tests/common/daemon_harness.rs` that takes the socket path AND the audit path AND the daemon state without consuming a tempdir (the caller manages tempdir lifetime). Only add this if the natural test code in step 3 doesn't work — do not pre-emptively expand the harness API.

- [ ] **Step 5: Run the test**

```bash
cargo test -p rimap-server --test shim_happy_path
```

Expected: pass.

If the test hangs at "initialize response timeout", check:
- Is the shim's stderr (`stderr(Stdio::piped())`) emitting an error? Capture and dump it on test failure for diagnostic purposes.
- Did the shim's `verify_socket_path` succeed? The bound socket might not be 0600.
- Is the daemon actually listening? Add a `tokio::time::sleep(Duration::from_millis(50)).await` between `spawn_bare` returning and the shim spawn to give the accept loop time to install the listener.

If the test fails at the `tools/list` assertion ("must include use_account"), the empty-registry fast-path may have a bug that #148's caching surfaces. That would be a Wave C / PR3 regression, not a PR11 issue — escalate.

- [ ] **Step 6: Run under `cargo nextest` to exercise the parallel-runner case**

The issue body explicitly required no flakiness under `cargo nextest run`. Verify:

```bash
cargo nextest run -p rimap-server --test shim_happy_path
```

If `cargo-nextest` is not installed, document that fact and SKIP this step rather than installing globally. The default `cargo test` exercise is sufficient for PR-time verification; `nextest` parity is a CI concern.

- [ ] **Step 7: Run clippy + fmt**

```bash
cargo clippy -p rimap-server --tests --all-features -- -D warnings
cargo fmt --check
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/tests/shim_happy_path.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): shim end-to-end happy-path integration test (#134)

Adds shim_happy_path.rs: spawns the real `rusty-imap-mcp shim` binary
under a tempdir-scoped XDG_RUNTIME_DIR, with the daemon harness
binding at the path the shim's resolver lands on. Sends mcp/initialize
+ notifications/initialized + tools/list and reads each response from
the shim's stdout, asserting the daemon's session_start/session_end
records also appear in the audit log.

Closes #134 — the deferred Phase 5 happy-path coverage. The harness
takes the resolver's path explicitly; no shim CLI surface change.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Full-workspace verification

**Files:** none — green-gate task.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Full workspace test suite**

Run: `cargo test --workspace`
Expected: every test passes including the new `shim_happy_path` plus the pre-existing `shim_error_no_daemon`.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. No new deps.

- [ ] **Step 5: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- The test mirrors the env-var approach used by `shim_error_no_daemon.rs` — there's a clear precedent and the harness pattern is established.
- No production code changes. The shim does NOT grow a `--socket-path` argument. The plan rejected option (b) from the issue body because adding a CLI surface for a test-only need bleeds into the agent-native API contract.
- Timeouts are explicit (5s) on every blocking read so a hung shim fails the test fast.
- Three assertions on the wire format: initialize echo, tools/list shape, audit log records — all three failure modes (broken pipe, wrong tool list, audit dropouts) get distinct error messages.
- `kill_on_drop(true)` on the shim subprocess prevents zombie processes if the test panics mid-exchange.

## Out of scope

- **`tools/call` end-to-end through the shim.** The test daemon has an empty registry, so no account-scoped call would succeed. Adding a real registry pulls in either the live-IMAP fixture (PR12) or extensive mocking. Defer.
- **Multi-frame batched requests.** The current MCP integration uses one request per line; the shim is not specified to batch differently. If batching becomes a feature, write a separate test.
- **Shim reconnect after daemon restart.** That's PR12 (Dovecot suite, scenario 5).
- **Anything in `daemon/run.rs`, `boot/registry.rs`, or `mcp/server.rs`.** No production code is touched.

If you find yourself editing anything outside `tests/shim_happy_path.rs` (and optionally `tests/common/daemon_harness.rs` per Task 1 step 4), stop and re-read this plan.
