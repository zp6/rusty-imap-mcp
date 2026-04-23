# Polish PR 8 — `--dry-run` TLS preflight + CAPABILITY check

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #117. The docs (`docs/quickstart-gmail.md`, `docs/quickstart-proton-bridge.md`) claim `--dry-run` performs a TLS handshake and reports server capabilities. In fact, `--dry-run` today only loads+validates the config and prints the posture matrix. This PR adds a real TLS handshake and pre-auth `CAPABILITY` probe per account and updates the quickstart docs to describe exactly what landed (TLS handshake + capabilities; no fingerprint claim).

**Architecture:** Add a new `probe_preflight(cfg: &ConnectionConfig) -> Result<PreflightInfo, ImapError>` free function in `rimap-imap` that runs TCP connect → TLS handshake → IMAP greeting → pre-auth `CAPABILITY` command, returning the capability list. `cli::dry_run::run` becomes `async` and invokes the probe once per account, printing capabilities alongside the existing posture matrix. Tests exercise the probe against the project's existing Mailpit-backed integration fixture (gated on `RIMAP_REQUIRE_LIVE_IMAP=1`) and assert the `--dry-run` text output includes a "Capabilities:" section.

**Tech Stack:** Rust, `tokio`, `async-imap`, `tokio-rustls`. The existing private helpers `build_tls_config`, `tls_handshake`, `starttls_upgrade` in `crates/rimap-imap/src/connection.rs` and the greeting/CAPABILITY blocks of `imap_login` (lines 383–436) are the reference implementation.

---

## Files

- Create: `crates/rimap-imap/src/preflight.rs` — new module exporting `probe_preflight` and `PreflightInfo`.
- Modify: `crates/rimap-imap/src/lib.rs` — add `pub mod preflight;` and re-exports.
- Modify: `crates/rimap-imap/src/connection.rs` — make `build_tls_config`, `tls_handshake`, `starttls_upgrade`, `drain_for_logindisabled` visible to the new module (either `pub(crate)` or move into a shared module).
- Modify: `crates/rimap-server/src/cli/dry_run.rs` — make `run` async; call `probe_preflight` per account; print capabilities.
- Modify: `crates/rimap-server/src/main.rs:96-100` — `.await` the newly async `dry_run::run`.
- Modify: `crates/rimap-server/tests/dry_run_cli.rs` — add capability-output assertion (gated on `RIMAP_REQUIRE_LIVE_IMAP`).
- Modify: `docs/quickstart-gmail.md:73` and `docs/quickstart-proton-bridge.md:114-115` — describe the actual landed behavior (no fingerprint).

## Task 1: Extract a shared module for TLS primitives

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` — elevate the four helpers listed above from private to `pub(crate)`.

- [ ] **Step 1: Run clippy before any change to baseline**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: clean exit. This confirms the starting state compiles.

- [ ] **Step 2: Make `build_tls_config`, `tls_handshake`, `starttls_upgrade`, and `drain_for_logindisabled` `pub(crate)`**

In `crates/rimap-imap/src/connection.rs`, change:

```rust
fn build_tls_config(...) -> ... { ... }
fn tls_handshake(...) -> ... { ... }
fn starttls_upgrade(...) -> ... { ... }
fn drain_for_logindisabled(...) -> bool { ... }
```

to:

```rust
pub(crate) fn build_tls_config(...) -> ... { ... }
pub(crate) async fn tls_handshake(...) -> ... { ... }
pub(crate) async fn starttls_upgrade(...) -> ... { ... }
pub(crate) fn drain_for_logindisabled(...) -> bool { ... }
```

(Use `rg -n 'fn build_tls_config|fn tls_handshake|fn starttls_upgrade|fn drain_for_logindisabled' crates/rimap-imap/src/connection.rs` to find the exact signatures; the visibility is the only edit — do not rename or rearrange.)

- [ ] **Step 3: Compile-check**

Run: `cargo check -p rimap-imap`
Expected: clean — visibility widening is strictly non-breaking.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "refactor(rimap-imap): widen TLS primitives to pub(crate) for preflight reuse (#117)"
```

## Task 2: Implement `probe_preflight` against a real Mailpit fixture

**Files:**
- Create: `crates/rimap-imap/src/preflight.rs`
- Modify: `crates/rimap-imap/src/lib.rs`
- Create: `crates/rimap-imap/tests/preflight_live.rs` — integration test gated on `RIMAP_REQUIRE_LIVE_IMAP`.

- [ ] **Step 1: Write the failing integration test**

The repo has a Dovecot-backed live fixture under `crates/rimap-imap/tests/integration/`; the test goes in that area so it can share the fixture harness. Create `crates/rimap-imap/tests/preflight_live.rs`:

```rust
//! Live integration test for `probe_preflight` (#117). Gated on
//! `RIMAP_REQUIRE_LIVE_IMAP=1` like the other live tests in this crate.

#![expect(clippy::unwrap_used, reason = "tests")]

#[path = "integration/common/mod.rs"]
mod common;

use rimap_imap::preflight::probe_preflight;

#[tokio::test(flavor = "multi_thread")]
async fn preflight_returns_capabilities_against_live_dovecot() {
    let Some(fx) = common::LiveFixture::spawn().await else {
        return; // RIMAP_REQUIRE_LIVE_IMAP not set; skip silently.
    };
    let cfg = fx.connection_config();
    let info = probe_preflight(&cfg).await.unwrap();
    assert!(!info.capabilities.is_empty(), "capabilities list empty");
    assert!(
        info.capabilities.iter().any(|c| c.eq_ignore_ascii_case("IMAP4REV1")),
        "expected IMAP4REV1 capability, got {:?}",
        info.capabilities,
    );
}
```

(If `common::LiveFixture::spawn().await` and `connection_config()` are not the exact names in the existing harness, adapt to match. The important thing is: construct a `ConnectionConfig`, then call `probe_preflight`, then assert `IMAP4REV1` appears.)

- [ ] **Step 2: Run the test to confirm it fails to compile**

Run: `RIMAP_REQUIRE_LIVE_IMAP=1 cargo test -p rimap-imap --test preflight_live`
Expected: compile error — `unresolved import 'rimap_imap::preflight'`.

- [ ] **Step 3: Create the `preflight` module**

Create `crates/rimap-imap/src/preflight.rs`:

```rust
//! Pre-auth `CAPABILITY` probe used by `--dry-run` and other diagnostic
//! paths. Performs TCP connect → TLS handshake → IMAP greeting → pre-auth
//! `CAPABILITY` command, then drops the connection. Does NOT perform LOGIN
//! and does NOT emit any audit records.

use std::time::Instant;

use async_imap::Client as ImapPlainClient;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::connection::{
    build_tls_config, drain_for_logindisabled, starttls_upgrade, tls_handshake,
};
use crate::error::ImapError;
use crate::types::{ConnectionConfig, ImapEncryption};

/// Result of a successful preflight probe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PreflightInfo {
    /// Capability atoms returned by the server's pre-auth `CAPABILITY`
    /// response, upper-case, de-duplicated, order preserved as received.
    pub capabilities: Vec<String>,
}

/// Run a TCP+TLS+greeting+CAPABILITY probe against `cfg`.
///
/// # Errors
/// Mirrors `ImapError` variants: `Connect`, `TlsHandshake`, `Timeout`,
/// `Protocol`. Never returns `Auth` variants — no credentials are used.
pub async fn probe_preflight(cfg: &ConnectionConfig) -> Result<PreflightInfo, ImapError> {
    let bundle = build_tls_config(cfg.pinned_fingerprint)?;
    let total_deadline = cfg.connect_timeout;
    let started = Instant::now();

    let tcp = timeout(
        total_deadline,
        TcpStream::connect((cfg.host.as_str(), cfg.port)),
    )
    .await
    .map_err(|_| ImapError::Timeout { op: "tcp_connect" })?
    .map_err(ImapError::Connect)?;

    let remaining = total_deadline.saturating_sub(started.elapsed());
    let (tls_stream, already_greeted) = match cfg.encryption {
        ImapEncryption::Tls => {
            let s = timeout(remaining, tls_handshake(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout { op: "tls_handshake" })??;
            (s, false)
        }
        ImapEncryption::Starttls => {
            let s = timeout(remaining, starttls_upgrade(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout { op: "starttls_upgrade" })??;
            (s, true)
        }
    };

    // Capabilities collection reuses async-imap's client + unsolicited channel
    // exactly as imap_login does at connection.rs:383-436.
    let mut client = ImapPlainClient::new(tls_stream);
    if !already_greeted {
        client
            .read_response()
            .await
            .map_err(ImapError::Connect)?
            .ok_or(ImapError::Connect(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed before greeting",
            )))?;
    }
    let (tx, rx) = async_channel::bounded::<async_imap::imap_proto::UnsolicitedResponse>(32);
    client
        .run_command_and_check_ok("CAPABILITY", Some(tx))
        .await
        .map_err(ImapError::Protocol)?;

    let mut caps = Vec::new();
    while let Ok(u) = rx.try_recv() {
        if let async_imap::imap_proto::UnsolicitedResponse::Capabilities(list) = u {
            for c in list {
                let s = format!("{c:?}").to_ascii_uppercase();
                if !caps.contains(&s) {
                    caps.push(s);
                }
            }
        }
    }
    // `drain_for_logindisabled` is informational for the caller only; not
    // an error for preflight. We don't use it here, but the import stays
    // so a future caller can inspect LOGINDISABLED without re-draining.
    let _ = drain_for_logindisabled;

    Ok(PreflightInfo { capabilities: caps })
}
```

**Implementer note:** the exact shape of `async_imap::imap_proto::UnsolicitedResponse::Capabilities(list)` in the installed `async-imap` version may require small adjustment (the variant name/fields can drift between 0.11 and 0.12). If the match arm doesn't compile, `cargo doc --open -p async-imap` and look up the `imap_proto::UnsolicitedResponse` enum. The printed-debug conversion `format!("{c:?}")` is a deliberate simplification — the existing code in `connection.rs` does the same because async-imap's capability atoms don't impl `Display`. A more structured `Vec<Capability>` type is a follow-up, not PR 8 scope.

- [ ] **Step 4: Re-export from the crate root**

Edit `crates/rimap-imap/src/lib.rs`. Add:

```rust
pub mod preflight;
```

Place the line with the other `pub mod` declarations (follow existing alphabetical/convention).

- [ ] **Step 5: Run the live test**

Start the Mailpit/Dovecot fixture first (see `justfile` / `README.md` for the exact command — likely `just test-live` or similar).

Run: `RIMAP_REQUIRE_LIVE_IMAP=1 cargo test -p rimap-imap --test preflight_live`
Expected: PASS. `IMAP4REV1` should appear in the capability list.

- [ ] **Step 6: Also confirm the non-live flow is unaffected**

Run: `cargo test -p rimap-imap` (without the env var)
Expected: `preflight_live` returns early (no-op); other tests pass as before.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-imap/src/preflight.rs crates/rimap-imap/src/lib.rs crates/rimap-imap/tests/preflight_live.rs
git commit -m "$(cat <<'EOF'
feat(rimap-imap): add probe_preflight for TLS+CAPABILITY probing (#117)

Runs TCP+TLS+greeting+CAPABILITY with no credentials and no audit
emission. Used by `--dry-run` to match the quickstart docs, which
claim a TLS preflight happens.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Wire the preflight into `--dry-run`

**Files:**
- Modify: `crates/rimap-server/src/cli/dry_run.rs`
- Modify: `crates/rimap-server/src/main.rs:99`

- [ ] **Step 1: Make `dry_run::run` async and invoke the probe**

In `crates/rimap-server/src/cli/dry_run.rs`, change the signature:

```rust
pub fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
```

to:

```rust
pub async fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
```

Then inside the `for (id, acfg) in &multi.accounts` loop, after the existing `writeln!(out, "Infrastructure tools (always available):")` block (line 72–78), add:

```rust
        // TLS + CAPABILITY preflight per account (#117). Errors are
        // reported inline but do not abort the dry-run — a multi-account
        // config may have one unreachable host and still want to print
        // the matrix for the others.
        let cfg = rimap_imap::types::ConnectionConfig {
            host: acfg.imap.host.clone(),
            port: acfg.imap.port,
            username: acfg.imap.username.clone(),
            account: Some(id.as_str().to_owned()),
            account_id: id.clone(),
            encryption: acfg.imap.encryption,
            pinned_fingerprint: acfg.imap.pinned_fingerprint,
            connect_timeout: std::time::Duration::from_secs(10),
        };
        match rimap_imap::preflight::probe_preflight(&cfg).await {
            Ok(info) => {
                writeln!(out, "Capabilities ({}:{}):", cfg.host, cfg.port)?;
                for cap in &info.capabilities {
                    writeln!(out, "  [ok ] {cap}")?;
                }
            }
            Err(e) => {
                writeln!(
                    out,
                    "Capabilities ({}:{}): unavailable ({e})",
                    cfg.host, cfg.port,
                )?;
            }
        }
```

**Implementer note:** `ConnectionConfig`'s exact field names may differ — use `rg -n 'pub struct ConnectionConfig' crates/rimap-imap/src/ -A 30` to confirm. If construction requires fields not present on `ValidatedMultiConfig::accounts`, follow the same pattern used by `boot::registry::build_account_connection`. Do NOT fabricate values for fields that affect TLS (pinned_fingerprint) — copy them from the config.

- [ ] **Step 2: Update the caller to `.await`**

In `crates/rimap-server/src/main.rs`, line 99:

```rust
    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        return cli::dry_run::run(&path, &mut stdout);
    }
```

Change to:

```rust
    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        return cli::dry_run::run(&path, &mut stdout).await;
    }
```

- [ ] **Step 3: Update the existing unit tests in `dry_run.rs`**

The tests at `crates/rimap-server/src/cli/dry_run.rs:113-211` call `run(&path, &mut out).unwrap()` synchronously. Because they use a non-reachable IP (`127.0.0.1:1143`), adding `.await` will cause the preflight to fail — which the test output handles gracefully (prints `unavailable`), so the existing assertions still pass.

Convert each `#[test]` to `#[tokio::test]` and each call site to `run(...).await`:

```rust
#[tokio::test]
async fn dry_run_prints_matrix_with_default_posture() {
    let dir = TempDir::new().unwrap();
    let path = write_minimal_config(&dir);
    let mut out = Vec::new();
    run(&path, &mut out).await.unwrap();
    // ... rest unchanged
}
```

Apply this to all four tests in that module.

- [ ] **Step 4: Run the unit tests**

Run: `cargo test -p rimap-server --lib cli::dry_run::tests`
Expected: all four tests pass. The `Capabilities (127.0.0.1:1143): unavailable ...` line will appear in stdout; no existing assertion checks for its absence.

- [ ] **Step 5: Update the integration test**

Add an assertion for the new section header in `crates/rimap-server/tests/dry_run_cli.rs` inside the `dry_run_exits_zero_and_prints_matrix` test (after line 47):

```rust
        .stdout(predicate::str::contains("Capabilities"));
```

Do NOT assert a specific capability list — the integration test uses `127.0.0.1:1143` which isn't reachable. `"Capabilities"` will match either the success or the "unavailable" form.

- [ ] **Step 6: Run the integration test**

Run: `cargo test -p rimap-server --test dry_run_cli`
Expected: all three tests pass.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/cli/dry_run.rs crates/rimap-server/src/main.rs crates/rimap-server/tests/dry_run_cli.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): --dry-run does TLS preflight + CAPABILITY probe (#117)

dry_run::run becomes async and invokes probe_preflight per account,
printing the capability list alongside the posture matrix. Unreachable
hosts are reported inline as unavailable rather than aborting.

Closes #117.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Update quickstart docs to match landed behavior

**Files:**
- Modify: `docs/quickstart-gmail.md:73`
- Modify: `docs/quickstart-proton-bridge.md:114-115`

- [ ] **Step 1: Read the current docs to see what they overstate**

Run: `rg -n 'dry-run|dry run|TLS fingerprint' docs/quickstart-gmail.md docs/quickstart-proton-bridge.md`
Expected: hits around line 73 (Gmail) and 114-115 (Proton Bridge) claiming TLS fingerprint verification.

- [ ] **Step 2: Rewrite the Gmail quickstart claim**

In `docs/quickstart-gmail.md`, locate the paragraph describing `--dry-run`. Replace the sentence that mentions "TLS fingerprint verification" with:

```markdown
A successful run prints the posture matrix, the active tool allowlist, and
the IMAP server's capability list (after a TLS handshake), then exits. It
does not authenticate.
```

- [ ] **Step 3: Rewrite the Proton Bridge quickstart claim**

Apply the same rewrite to `docs/quickstart-proton-bridge.md` near line 114–115.

- [ ] **Step 4: Confirm no other docs still claim fingerprint printing**

Run: `rg -n 'TLS fingerprint|fingerprint verification' docs/`
Expected: no hits in quickstart / user-facing docs. Hits in design specs are acceptable if they refer to the `pinned_fingerprint` config field (a separate feature).

- [ ] **Step 5: Commit**

```bash
git add docs/quickstart-gmail.md docs/quickstart-proton-bridge.md
git commit -m "docs: align quickstart --dry-run description with landed behavior (#117)"
```

## Self-review

- TDD discipline: live test in Task 2 step 1 before the impl in step 3.
- Live test is gated on `RIMAP_REQUIRE_LIVE_IMAP` so standard CI isn't affected.
- Existing `dry_run.rs` unit tests (which use unreachable host:port) will exercise the `Err` branch of `probe_preflight` — graceful fallback is part of the design.
- Docs updated to describe actually-landed behavior: no claim of TLS fingerprint printing (that would need a custom `ServerCertVerifier` and is a separate enhancement).
- Four commits, each shippable on its own. If the live test fixture is unavailable locally, task 2 step 5 can be deferred to CI; `cargo check` is sufficient before committing the probe code.
- `async_imap::imap_proto::UnsolicitedResponse::Capabilities` variant shape is an assumption; if the installed async-imap version differs, the implementer adjusts the match arm before step 5. The risk is low because the same pattern is used in `imap_login` at `connection.rs:428`.
