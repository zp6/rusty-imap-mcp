# MCP Wire-Shape Conformance Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust integration test that spawns `rusty-imap-mcp`, drives MCP JSON-RPC over stdio, and validates every response against vendored MCP spec schemas — a permanent regression net for the bug classes in #261 and `fix/tool-input-schema-object-type`.

**Architecture:** A `Harness` helper spawns the production binary with a tempdir config and zero accounts, pipes stdio, writes newline-delimited JSON-RPC requests, and reads single-line responses under per-call timeouts. Each test compiles a `jsonschema::Validator` against a specific fragment of the vendored MCP `schema.json` (pinned to `2025-11-25`) and asserts every response payload validates. A weekly CI workflow diffs the vendored schema against upstream and opens a tracking issue on drift.

**Tech Stack:** Rust (workspace edition 2024, MSRV 1.88.0), `rmcp 1.5`, `tokio::process::Command` (already in workspace), `jsonschema 0.46`, `assert_cmd` (existing dev-dep), `tempfile` (existing dev-dep), bash + curl + jq for the refresh script, GitHub Actions for drift detection.

**Spec:** `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`.

**Issue:** #263.

---

## File structure

| Path | Action | Purpose |
| --- | --- | --- |
| `Cargo.toml` | modify | Add `jsonschema` to `[workspace.dependencies]` |
| `crates/rimap-server/Cargo.toml` | modify | Add `jsonschema` to `[dev-dependencies]` |
| `crates/rimap-config/src/validate/mod.rs` | modify | Remove the `accounts.is_empty()` rejection |
| `crates/rimap-config/src/error.rs` | modify | Remove the now-unused `NoAccounts` variant |
| `crates/rimap-server/tests/fixtures/mcp-spec/README.md` | create | Vendoring rationale + refresh procedure |
| `crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json` | create | Vendored MCP spec (downloaded) |
| `crates/rimap-server/tests/mcp_wire_conformance.rs` | create | The harness + 8 test cases |
| `scripts/refresh-mcp-spec.sh` | create | Refresh / drift-check the vendored schema |
| `.github/workflows/mcp-spec-drift.yml` | create | Weekly drift detector |
| `CHANGELOG.md` | modify | Document the new test + behavior change |

---

## Task 1: Lift the empty-accounts restriction

The issue's design requires `rusty-imap-mcp` to boot with zero accounts so the harness can probe `initialize` / `tools/list` / `resources/list` without standing up an IMAP fixture. Today `validate_multi()` rejects this with `ConfigError::NoAccounts`. `build_registry()` already handles an empty account map (the loop body never executes), so removing the validator gate is the only change needed in production code.

**Files:**
- Modify: `crates/rimap-config/src/validate/mod.rs` (the `if config.accounts.is_empty()` block near line 72)
- Modify: `crates/rimap-config/src/error.rs` (remove the `NoAccounts` variant near line 166)
- Test: existing tests in `crates/rimap-config/src/validate/mod.rs` and `crates/rimap-config/tests/` may reference `NoAccounts`

- [ ] **Step 1: Find every reference to `NoAccounts` so the removal is complete**

Run:
```bash
rg -n "NoAccounts|no accounts defined" crates/
```
Expected: one definition in `error.rs`, one match in `validate/mod.rs` (the check), plus zero or more test references. Record the test paths.

- [ ] **Step 2: Write the failing test for empty-accounts acceptance**

Add to `crates/rimap-config/src/validate/mod.rs` inside the existing `#[cfg(test)] mod tests { ... }` block (place it next to the other `validate_*` tests):

```rust
#[test]
fn empty_accounts_array_validates_for_infrastructure_only_boot() {
    // Before: the server refused to boot with zero accounts. This
    // blocked the MCP wire-conformance harness (#263) from probing
    // initialize / tools/list / resources/list without standing up
    // an IMAP fixture. Empty accounts now validates cleanly; the
    // resulting AccountRegistry is empty and list_accounts returns
    // [], which is the correct infrastructure-only behavior.
    let audit_dir = TempDir::new().unwrap();
    let cfg = MultiAccountConfig {
        defaults: DefaultsConfig::default(),
        accounts: Vec::new(),
        audit: AuditConfig {
            path: audit_dir.path().join("audit.jsonl"),
            allowed_base_dir: Some(audit_dir.path().to_path_buf()),
            ..AuditConfig::default()
        },
        attachments: AttachmentsConfig::default(),
    };
    let validated = validate_multi(cfg).expect("empty accounts must validate");
    assert!(validated.accounts.is_empty());
}
```

If `AuditConfig` does not implement `Default`, use the helper that other tests in the file already use to build a base audit config (search for `fn base_config` or similar in the same module and reuse it; do not invent a new helper).

- [ ] **Step 3: Run the test and confirm it fails**

Run:
```bash
cargo test -p rimap-config empty_accounts_array_validates_for_infrastructure_only_boot
```
Expected: FAIL with `Err(NoAccounts)` or similar — the validator still rejects.

- [ ] **Step 4: Remove the empty-accounts gate**

In `crates/rimap-config/src/validate/mod.rs`, find and delete:
```rust
    if config.accounts.is_empty() {
        return Err(ConfigError::NoAccounts);
    }
```

- [ ] **Step 5: Delete the `NoAccounts` error variant**

In `crates/rimap-config/src/error.rs`, find and delete:
```rust
    /// Multi-account config has an empty `[[accounts]]` array.
    #[error("no accounts defined in [[accounts]] array")]
    NoAccounts,
```

- [ ] **Step 6: Remove or update tests that asserted `NoAccounts` was returned**

For each test that grep found in step 1 (other than the new test added in step 2): delete it if its sole purpose was to assert the rejection, or update it to use a different invalid config if it was testing a broader codepath.

- [ ] **Step 7: Run the full config test suite**

Run:
```bash
cargo test -p rimap-config
```
Expected: all tests pass, including the new `empty_accounts_array_validates_for_infrastructure_only_boot`.

- [ ] **Step 8: Verify the workspace still compiles end-to-end**

Run:
```bash
cargo check --workspace --all-targets
```
Expected: clean compile, no references to the removed `NoAccounts` variant.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-config/src/validate/mod.rs crates/rimap-config/src/error.rs
git commit -m "$(cat <<'EOF'
feat(config): allow empty accounts array for infrastructure-only boot

Removes the validate_multi() gate that rejected `accounts = []` with
ConfigError::NoAccounts. The server already coped with an empty
AccountRegistry (build_registry's loop body simply does not run); the
gate was the only thing forcing at least one account to be declared.

Unblocks the MCP wire-conformance harness (#263), which spawns the
binary against a tempdir config with zero accounts to probe initialize
/ tools/list / resources/list without needing an IMAP fixture.

EOF
)"
```

---

## Task 2: Add `jsonschema` to workspace + rimap-server dev-deps

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]` block)
- Modify: `crates/rimap-server/Cargo.toml` (`[dev-dependencies]` block)

- [ ] **Step 1: Add the workspace dependency entry**

In `Cargo.toml`, inside `[workspace.dependencies]`, alongside other test-related deps (look for `assert_cmd`, `predicates`, `mail-parser`), add:

```toml
# JSON Schema validator used only by integration tests
# (crates/rimap-server/tests/mcp_wire_conformance.rs) to validate MCP
# JSON-RPC envelopes against the vendored MCP spec schemas. Pure-Rust,
# Draft 2020-12 capable. Reviewed for supply-chain risk per
# SC-PROC-01 on plan execution date.
jsonschema = { version = "0.46", default-features = false }
```

- [ ] **Step 2: Add the dev-dependency in rimap-server**

In `crates/rimap-server/Cargo.toml`, inside `[dev-dependencies]`, add:

```toml
jsonschema = { workspace = true }
```

- [ ] **Step 3: Verify the workspace resolves**

Run:
```bash
cargo update -p jsonschema && cargo check -p rimap-server --tests
```
Expected: jsonschema downloads, no compile errors. Note the resolved version printed by cargo for the commit message.

- [ ] **Step 4: Verify cargo-deny is still clean**

Run:
```bash
cargo deny check advisories licenses bans sources 2>&1 | tail -20
```
Expected: 0 errors. If a new transitive dep trips a license check, address it before continuing (most likely outcome: clean).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
deps(test): add jsonschema 0.46 to dev-dependencies (#263)

Used by the MCP wire-conformance harness to validate JSON-RPC
envelopes against vendored MCP spec schemas. default-features = false
keeps the build lean — only the validator surface is needed.

EOF
)"
```

---

## Task 3: Vendor the MCP spec schema + write the fixtures README

**Files:**
- Create: `crates/rimap-server/tests/fixtures/mcp-spec/README.md`
- Create: `crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json`

- [ ] **Step 1: Create the fixtures directory**

Run:
```bash
mkdir -p crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25
```

- [ ] **Step 2: Download the pinned schema**

Run:
```bash
curl --fail --show-error --silent --location \
  "https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.json" \
  -o crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json
```
Expected: file downloaded, non-empty, valid JSON.

- [ ] **Step 3: Verify it parses as JSON and identify the definitions key**

Run:
```bash
jq -r 'keys[]' crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json
```
Expected output includes either `definitions` or `$defs`. Record which one is used — the harness code in Task 5 references it by name.

- [ ] **Step 4: Verify the four definitions the harness will validate against exist**

Run (substitute `definitions` or `$defs` based on Step 3):
```bash
jq -r '.definitions | keys[]' crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json \
  | grep -E '^(InitializeResult|ListToolsResult|ListResourcesResult|JSONRPCError|JSONRPCResponse)$'
```
Expected: at minimum `InitializeResult`, `ListToolsResult`, `ListResourcesResult`, `JSONRPCError`. If any name is missing, search for an equivalent (`Result` may be appended/stripped differently in newer specs); record the exact names and use them in Task 5.

- [ ] **Step 5: Write the fixtures README**

Create `crates/rimap-server/tests/fixtures/mcp-spec/README.md`:

```markdown
# Vendored MCP Specification Schemas

This directory holds verbatim copies of the JSON Schema documents
published by the [Model Context Protocol specification][spec-repo].
They are consumed exclusively by the wire-conformance test
(`crates/rimap-server/tests/mcp_wire_conformance.rs`, issue #263).

## Pinned version

`2025-11-25/schema.json` — fetched from

    https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.json

This matches `rmcp::model::ProtocolVersion::LATEST` for `rmcp 1.5`,
which is what `rusty-imap-mcp` advertises by default during the
`initialize` handshake.

## Refresh / drift workflow

- `scripts/refresh-mcp-spec.sh <version>` overwrites the vendored
  copy with the current upstream contents.
- `scripts/refresh-mcp-spec.sh --check <version>` exits non-zero if
  the vendored copy differs from upstream.
- `.github/workflows/mcp-spec-drift.yml` runs the check weekly and
  opens (or updates) a tracking issue when drift is detected.

## Local diffs

None. The vendored copy is byte-for-byte verbatim; if a future
rmcp / spec mismatch forces us to relax a strict constraint (e.g. a
fragment with `additionalProperties: false` that rmcp violates),
document the diff here and link the rationale.

[spec-repo]: https://github.com/modelcontextprotocol/modelcontextprotocol
```

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/fixtures/mcp-spec/
git commit -m "$(cat <<'EOF'
test(mcp): vendor MCP spec schema 2025-11-25 (#263)

Verbatim copy of upstream schema.json. Matches
ProtocolVersion::LATEST in rmcp 1.5. Consumed by the wire-
conformance harness added in a follow-up commit.

EOF
)"
```

---

## Task 4: Write the schema refresh / drift-check script

**Files:**
- Create: `scripts/refresh-mcp-spec.sh`

- [ ] **Step 1: Create the script**

Create `scripts/refresh-mcp-spec.sh`:

```bash
#!/usr/bin/env bash
#
# Refresh (or drift-check) the vendored MCP spec schema used by the
# wire-conformance harness in crates/rimap-server/tests/. See
# docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md
# §3.4 and §3.5.
#
# Usage:
#   scripts/refresh-mcp-spec.sh <version>           # overwrite vendored copy
#   scripts/refresh-mcp-spec.sh --check <version>   # exit non-zero on drift

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures_dir="${repo_root}/crates/rimap-server/tests/fixtures/mcp-spec"
upstream_base="https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema"

mode="refresh"
if [[ "${1:-}" == "--check" ]]; then
  mode="check"
  shift
fi

version="${1:-}"
if [[ -z "${version}" ]]; then
  echo "usage: $0 [--check] <version>" >&2
  exit 64
fi

local_path="${fixtures_dir}/${version}/schema.json"
upstream_url="${upstream_base}/${version}/schema.json"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

curl --fail --show-error --silent --location "${upstream_url}" -o "${tmp}"

if ! jq empty "${tmp}" >/dev/null 2>&1; then
  echo "fetched payload is not valid JSON: ${upstream_url}" >&2
  exit 65
fi

case "${mode}" in
  refresh)
    mkdir -p "$(dirname "${local_path}")"
    mv "${tmp}" "${local_path}"
    trap - EXIT
    echo "refreshed ${local_path}"
    ;;
  check)
    if [[ ! -f "${local_path}" ]]; then
      echo "vendored copy missing: ${local_path}" >&2
      exit 1
    fi
    if ! diff -u "${local_path}" "${tmp}" >&2; then
      echo "DRIFT: vendored ${version}/schema.json differs from upstream" >&2
      exit 1
    fi
    echo "no drift: ${local_path}"
    ;;
esac
```

- [ ] **Step 2: Make it executable**

Run:
```bash
chmod +x scripts/refresh-mcp-spec.sh
```

- [ ] **Step 3: Lint with shellcheck and shfmt**

Run:
```bash
shellcheck scripts/refresh-mcp-spec.sh
shfmt -i 2 -d scripts/refresh-mcp-spec.sh
```
Expected: both clean. If shfmt suggests changes, apply with `shfmt -i 2 -w scripts/refresh-mcp-spec.sh`.

- [ ] **Step 4: Smoke-test refresh mode (should be a no-op since we just downloaded)**

Run:
```bash
./scripts/refresh-mcp-spec.sh 2025-11-25
git status crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json
```
Expected: no diff in `git status` (the file is identical).

- [ ] **Step 5: Smoke-test check mode**

Run:
```bash
./scripts/refresh-mcp-spec.sh --check 2025-11-25
```
Expected: prints `no drift: ...` and exits 0.

- [ ] **Step 6: Verify check-mode catches drift**

Run:
```bash
echo '{"junk": true}' > crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json
./scripts/refresh-mcp-spec.sh --check 2025-11-25 || echo "exited non-zero as expected"
git checkout -- crates/rimap-server/tests/fixtures/mcp-spec/2025-11-25/schema.json
```
Expected: script prints `DRIFT: ...`, exits non-zero, and the `git checkout` restores the file.

- [ ] **Step 7: Commit**

```bash
git add scripts/refresh-mcp-spec.sh
git commit -m "$(cat <<'EOF'
scripts: add refresh-mcp-spec.sh for vendored MCP schemas (#263)

Two modes:
- refresh: overwrite the vendored copy with current upstream
- --check: exit non-zero on drift (used by mcp-spec-drift workflow)

POSIX bash, set -euo pipefail, shellcheck/shfmt clean.

EOF
)"
```

---

## Task 5: Build the test harness skeleton + first smoke test

This task delivers `mcp_wire_conformance.rs` with the `Harness` helper and one passing test that proves the harness can boot the binary, complete `initialize`, and parse a valid JSON-RPC response. Subsequent tasks layer additional `#[tokio::test]` functions onto the same harness.

**Files:**
- Create: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Verify the binary names match `cargo_bin!`**

Run:
```bash
grep -n "^name = " crates/rimap-server/Cargo.toml | head -5
```
Expected: confirm the `[[bin]]` name is `rusty-imap-mcp`. The harness passes this string to `cargo_bin`.

- [ ] **Step 2: Write the harness module + the smoke test (failing scaffold)**

Create `crates/rimap-server/tests/mcp_wire_conformance.rs`:

```rust
//! MCP wire-shape conformance harness (issue #263, Phase 1).
//!
//! Spawns the production `rusty-imap-mcp` binary with a tempdir
//! config that has zero accounts, drives a deterministic JSON-RPC
//! sequence over its stdio, and validates every response against
//! the vendored MCP spec schemas under
//! `tests/fixtures/mcp-spec/2025-11-25/`.
//!
//! Permanent regression net for two real wire-shape bugs:
//!  - #261: `initialize.result.capabilities` was serialized as `{}`.
//!  - `fix/tool-input-schema-object-type`: tools advertised
//!    `inputSchema: {}` with no `type` field.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::unwrap_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]
#![expect(clippy::missing_panics_doc, reason = "test helpers")]

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// MCP protocol version pinned by this harness. Matches the
/// directory under `tests/fixtures/mcp-spec/` and the `LATEST` value
/// in `rmcp 1.5`. Update both when bumping.
const PINNED_PROTOCOL_VERSION: &str = "2025-11-25";

/// Vendored MCP spec schema, compiled in at build time so tests run
/// hermetically (no network, no filesystem dependency beyond the
/// crate source).
const MCP_SCHEMA_JSON: &str = include_str!(
    "fixtures/mcp-spec/2025-11-25/schema.json"
);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Owns the spawned child plus its piped stdio.
struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    // Hold the tempdir until the harness drops so the audit log path
    // remains valid for the lifetime of the spawned process.
    _tempdir: TempDir,
}

impl Harness {
    /// Spawn the binary with a zero-account tempdir config.
    async fn spawn() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();

        let config = format!(
            r#"
[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = timeout(SPAWN_TIMEOUT, async { cmd.spawn() })
            .await
            .expect("spawn within timeout")
            .expect("spawn");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));

        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            _tempdir: tempdir,
        }
    }

    /// Send a JSON-RPC request and return the parsed response value.
    /// Panics on timeout, EOF before a response arrives, or
    /// non-JSON output.
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");

        let mut buf = String::new();
        let read = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf))
            .await
            .expect("response within timeout")
            .expect("read response");
        assert!(read > 0, "stdout closed before responding to {method}");
        let response: Value =
            serde_json::from_str(buf.trim_end()).expect("parse response JSON");
        assert_eq!(response["id"], json!(id), "response id must match request");
        response
    }

    /// Send a JSON-RPC notification (no `id`, no response expected).
    async fn notify(&mut self, method: &str, params: Value) {
        let envelope = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write notification");
        self.stdin.flush().await.expect("flush notification");
    }

    /// Assert no bytes arrive on stdout for the given duration.
    async fn assert_no_response_within(&mut self, dur: Duration) {
        let mut buf = String::new();
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Err(_) => {} // timeout → no response, as expected
            Ok(Ok(0)) => panic!("stdout closed unexpectedly"),
            Ok(Ok(_)) => panic!("expected no response within {dur:?}, got: {buf:?}"),
            Ok(Err(e)) => panic!("read error: {e}"),
        }
    }

    /// Send an MCP `initialize` request with the pinned protocol
    /// version and return the response.
    async fn initialize_handshake(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": PINNED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-conformance-harness",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
        .await
    }

    /// Send `notifications/initialized` after the handshake.
    async fn send_initialized(&mut self) {
        self.notify("notifications/initialized", json!({})).await;
    }

    /// Close stdin, await the child, and return its exit status.
    async fn shutdown_and_wait(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        timeout(SHUTDOWN_TIMEOUT, self.child.wait())
            .await
            .expect("clean exit within timeout")
            .expect("wait")
    }
}

/// Compile (once) and return a validator for a top-level definition in
/// the vendored MCP schema. `fragment` is the key under
/// `definitions` / `$defs` (e.g. "InitializeResult"). Returns an
/// `Arc` so multiple parallel tests can share the compiled validator
/// without lifetime gymnastics.
fn validator_for(fragment: &'static str) -> Arc<jsonschema::Validator> {
    type Cache = Mutex<HashMap<&'static str, Arc<jsonschema::Validator>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap();
    if let Some(v) = guard.get(fragment) {
        return Arc::clone(v);
    }

    // Detect which key the spec uses for nested definitions. Newer
    // JSON Schema dialects use `$defs`; older specs use `definitions`.
    let full: Value =
        serde_json::from_str(MCP_SCHEMA_JSON).expect("parse vendored MCP schema");
    let defs_key = if full.get("$defs").is_some() {
        "$defs"
    } else {
        "definitions"
    };

    // Build a wrapper schema that $refs into the requested fragment.
    let wrapper = json!({
        "$ref": format!("#/{defs_key}/{fragment}"),
        defs_key: full.get(defs_key).cloned().unwrap_or(json!({})),
    });
    let v = Arc::new(
        jsonschema::validator_for(&wrapper).expect("compile fragment validator"),
    );
    guard.insert(fragment, Arc::clone(&v));
    v
}

/// Validate a value against a vendored fragment, panicking with the
/// list of errors on failure.
fn assert_valid(value: &Value, fragment: &'static str) {
    let v = validator_for(fragment);
    if !v.is_valid(value) {
        let errors: Vec<String> = v.iter_errors(value).map(|e| e.to_string()).collect();
        panic!(
            "schema validation failed for fragment {fragment}:\n  {}",
            errors.join("\n  ")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_smoke_initialize_returns_valid_envelope() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(response["jsonrpc"], json!("2.0"));
    assert!(
        response["result"].is_object(),
        "initialize response must have a result object, got {response}"
    );
}
```

- [ ] **Step 3: Run the smoke test and confirm it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_smoke_initialize_returns_valid_envelope -- --nocapture
```
Expected: PASS. If FAIL, common causes:
- `cargo_bin` cannot find the binary → run `cargo build -p rimap-server --bin rusty-imap-mcp` first.
- Binary writes to stdout before JSON-RPC → check `crates/rimap-server/src/boot/logging.rs` to confirm logging goes to stderr only.
- Schema fragment key mismatch → adjust `defs_key` detection.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "$(cat <<'EOF'
test(mcp): wire-conformance harness scaffold + initialize smoke (#263)

Spawns rusty-imap-mcp with a zero-account tempdir config, drives
newline-delimited JSON-RPC over stdio with per-call timeouts, and
parses one initialize response. Schema validation + remaining test
cases land in follow-up commits.

EOF
)"
```

---

## Task 6: Test case 1 — `initialize` advertises tools capability

Adds a full validation pass on top of the smoke test, including the regression net for #261.

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialize_advertises_tools_capability() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;

    let result = &response["result"];
    assert_valid(result, "InitializeResult");

    assert_eq!(
        result["protocolVersion"],
        json!(PINNED_PROTOCOL_VERSION),
        "server must echo the pinned protocol version",
    );

    // Regression net for #261: the capabilities object must contain
    // a `tools` key on the wire. Permissive clients ignore the
    // absence; spec-strict clients (e.g. bobshell) refuse to call
    // tools/list.
    let capabilities = &result["capabilities"];
    assert!(
        capabilities.is_object(),
        "capabilities must be an object, got {capabilities}",
    );
    assert!(
        capabilities.get("tools").is_some(),
        "capabilities.tools must be present on the wire; got {capabilities}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_initialize_advertises_tools_capability -- --nocapture
```
Expected: PASS. If schema validation fails, inspect the error list — most likely a fragment-name mismatch (try `InitializeResult` vs. the exact key from Task 3 Step 4).

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert initialize advertises tools capability (#263, #261)"
```

---

## Task 7: Test case 8 — protocol-version negotiation matches vendored schema

This test is sequenced before the larger cases because if it fails (rmcp bumped LATEST), the other tests will mis-validate. Failing first means a single clear signal: "refresh the vendored schema."

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_protocol_version_negotiation_matches_vendored_schema() {
    // Sends an initialize request with the LATEST version known to
    // the test, asks the server to echo it back. rmcp negotiates
    // min(client, server), so when the server bumps to a newer
    // LATEST this still succeeds — but if the server somehow
    // negotiates to an older version (e.g. the pinned string is
    // wrong) this test catches it. The fragment-validation tests
    // depend on this invariant.
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(
        response["result"]["protocolVersion"],
        json!(PINNED_PROTOCOL_VERSION),
        "harness pinned to {PINNED_PROTOCOL_VERSION} but server returned a \
         different value; either update PINNED_PROTOCOL_VERSION + the \
         tests/fixtures/mcp-spec/<version>/ directory, or fix the rmcp \
         negotiation regression. Full response: {response}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_protocol_version_negotiation_matches_vendored_schema -- --nocapture
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert negotiated protocolVersion matches vendored schema (#263)"
```

---

## Task 8: Test case 2 — `notifications/initialized` elicits no response

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialized_notification_elicits_no_response() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
        .assert_no_response_within(Duration::from_millis(200))
        .await;
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_initialized_notification_elicits_no_response -- --nocapture
```
Expected: PASS within ~200 ms.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert notifications/initialized is silent (#263)"
```

---

## Task 9: Test case 3 — `tools/list` returns object-typed input schemas

This is the regression net for `fix/tool-input-schema-object-type`.

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_list_returns_object_schemas() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("tools/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListToolsResult");

    let tools = result["tools"]
        .as_array()
        .expect("tools must be an array");
    assert!(!tools.is_empty(), "tools/list must return at least the infrastructure tools");

    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"list_accounts"),
        "list_accounts must be advertised; got names {names:?}",
    );
    assert!(
        names.contains(&"use_account"),
        "use_account must be advertised; got names {names:?}",
    );

    // Regression net for fix/tool-input-schema-object-type: every
    // tool advertised on the wire must declare an object inputSchema.
    // Permissive MCP clients tolerate the absence; Zod-based clients
    // reject the tool.
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("<missing-name>");
        let schema = &tool["inputSchema"];
        assert!(
            schema.is_object(),
            "tool {name}: inputSchema must be an object, got {schema}",
        );
        assert_eq!(
            schema["type"],
            json!("object"),
            "tool {name}: inputSchema.type must be \"object\" (issue #263 regression net), got {schema}",
        );
    }
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_tools_list_returns_object_schemas -- --nocapture
```
Expected: PASS. (This test would have caught the bug fixed in `fix/tool-input-schema-object-type`.)

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert every tools/list inputSchema.type is object (#263)"
```

---

## Task 10: Test case 4 — `resources/list` is empty for zero accounts

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_resources_list_is_empty_for_no_accounts() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("resources/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListResourcesResult");

    let resources = result["resources"]
        .as_array()
        .expect("resources must be an array");
    assert!(
        resources.is_empty(),
        "zero accounts must produce zero resources, got {resources:?}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_resources_list_is_empty_for_no_accounts -- --nocapture
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert resources/list empty with zero accounts (#263)"
```

---

## Task 11: Test case 5 — `tools/call` with unknown tool returns INVALID_PARAMS

`rmcp 1.5`'s router emits `ErrorData::invalid_params("tool not found", None)` for unknown tool names — confirmed in `rmcp-1.5.0/src/handler/server/router/tool.rs:415`. Code is `-32602`.

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_call_unknown_tool_returns_error_envelope() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "this_tool_does_not_exist",
                "arguments": {}
            }),
        )
        .await;

    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    // rmcp 1.5 emits INVALID_PARAMS (-32602) with message "tool not found"
    // for unknown tool names; see rmcp-1.5.0/src/handler/server/router/tool.rs.
    // If this code ever changes, update the assertion and document why
    // — silent drift in rmcp's error mapping is exactly what this test
    // is meant to surface.
    assert_eq!(
        response["error"]["code"],
        json!(-32602),
        "expected -32602 INVALID_PARAMS, got {response}",
    );
    assert!(
        response["error"]["message"].is_string(),
        "error.message must be a string, got {response}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_tools_call_unknown_tool_returns_error_envelope -- --nocapture
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert tools/call unknown name returns INVALID_PARAMS (#263)"
```

---

## Task 12: Test case 6 — unknown method returns -32601

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_unknown_method_returns_minus_32601() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("rimap/no_such_method", json!({})).await;
    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    assert_eq!(
        response["error"]["code"],
        json!(-32601),
        "JSON-RPC method-not-found code, got {response}",
    );
    assert!(
        response["error"]["message"].as_str().is_some_and(|s| !s.is_empty()),
        "error.message must be non-empty, got {response}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_unknown_method_returns_minus_32601 -- --nocapture
```
Expected: PASS. If FAIL with a different code (e.g. -32600), note rmcp's actual mapping and adjust the assertion + comment to match. The test should reflect what the server actually does, not aspiration.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert unknown method returns -32601 (#263)"
```

---

## Task 13: Test case 7 — clean EOF shutdown exits zero

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Append the test**

Add to the bottom of `mcp_wire_conformance.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_clean_eof_shutdown_exits_zero() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let status = harness.shutdown_and_wait().await;
    assert!(
        status.success(),
        "server must exit 0 on clean stdin EOF, got {status:?}",
    );
}
```

- [ ] **Step 2: Run and verify it passes**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance wire_clean_eof_shutdown_exits_zero -- --nocapture
```
Expected: PASS within 1 s.

- [ ] **Step 3: Run the entire conformance test file end-to-end**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance -- --nocapture
```
Expected: all 8 tests pass. Total runtime should be well under 30 s; if any test takes more than 5 s investigate before continuing.

- [ ] **Step 4: Run the full workspace test suite to catch any cross-crate regression**

Run:
```bash
cargo test --workspace
```
Expected: all tests pass. If anything fails, especially in rimap-config tests touching `NoAccounts`, revisit Task 1.

- [ ] **Step 5: Run clippy with workspace deny-warnings**

Run:
```bash
cargo clippy --all-targets --all-features -- -D warnings
```
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "test(mcp): assert clean stdin EOF exits zero (#263)"
```

---

## Task 14: Add the CI drift-detection workflow

**Files:**
- Create: `.github/workflows/mcp-spec-drift.yml`

- [ ] **Step 1: Look up the current pinned SHAs for actions used by the workflow**

The project's existing workflows pin every action to a 40-char SHA with a version comment. To stay consistent, capture the latest stable SHA for `actions/checkout` from another workflow in this repo:

```bash
grep -rh "actions/checkout@" .github/workflows/ | head -5
```

Record the SHA + version comment. Use the same pinning style below.

- [ ] **Step 2: Create the workflow**

Create `.github/workflows/mcp-spec-drift.yml` (substitute the SHA captured above where indicated):

```yaml
# Weekly drift detector for the vendored MCP spec schemas consumed by
# crates/rimap-server/tests/mcp_wire_conformance.rs. See
# docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md §3.5.

name: mcp-spec-drift

on:
  schedule:
    # Mondays 12:00 UTC. Cron is best-effort on GitHub Actions but
    # weekly cadence is fine here — we only need eventual notice.
    - cron: '0 12 * * 1'
  workflow_dispatch:

permissions:
  contents: read
  issues: write

concurrency:
  group: mcp-spec-drift
  cancel-in-progress: false

jobs:
  check-drift:
    runs-on: ubuntu-latest
    env:
      PINNED_VERSION: '2025-11-25'
    steps:
      - name: Checkout
        uses: actions/checkout@<SHA-FROM-STEP-1>  # vX.Y.Z
        with:
          persist-credentials: false

      - name: Run drift check
        id: check
        run: |
          set -euo pipefail
          if ./scripts/refresh-mcp-spec.sh --check "${PINNED_VERSION}"; then
            echo "drift=false" >> "${GITHUB_OUTPUT}"
          else
            echo "drift=true" >> "${GITHUB_OUTPUT}"
            # Capture the diff for the issue body. The script wrote
            # the diff to stderr — re-run and capture both streams.
            ./scripts/refresh-mcp-spec.sh --check "${PINNED_VERSION}" \
              > drift-diff.txt 2>&1 || true
          fi

      - name: Open or update tracking issue on drift
        if: steps.check.outputs.drift == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          title="MCP spec drift: ${PINNED_VERSION}/schema.json"
          body_file="$(mktemp)"
          {
            echo "Weekly drift check found differences between the vendored"
            echo "MCP spec at \`crates/rimap-server/tests/fixtures/mcp-spec/${PINNED_VERSION}/schema.json\`"
            echo "and upstream \`modelcontextprotocol/modelcontextprotocol@main\`."
            echo ""
            echo "Run \`scripts/refresh-mcp-spec.sh ${PINNED_VERSION}\` to update the vendored copy"
            echo "and re-run \`cargo test -p rimap-server --test mcp_wire_conformance\` to confirm"
            echo "the harness still validates."
            echo ""
            echo "<details><summary>diff</summary>"
            echo ""
            echo '```diff'
            cat drift-diff.txt
            echo '```'
            echo ""
            echo "</details>"
          } > "${body_file}"
          existing="$(gh issue list --label mcp-spec-drift --state open --search "${title} in:title" --json number --jq '.[0].number // empty')"
          if [[ -n "${existing}" ]]; then
            gh issue comment "${existing}" --body-file "${body_file}"
          else
            gh issue create --title "${title}" --label mcp-spec-drift --body-file "${body_file}"
          fi
          # Fail the run so the Actions tab badge reflects drift even
          # if the issue mechanism somehow no-ops.
          exit 1
```

- [ ] **Step 3: Lint with actionlint + zizmor**

Run:
```bash
actionlint .github/workflows/mcp-spec-drift.yml
zizmor .github/workflows/mcp-spec-drift.yml
```
Expected: both clean. Fix any findings before committing — common ones are missing `persist-credentials: false` (already set above) or unpinned actions.

- [ ] **Step 4: Ensure the `mcp-spec-drift` label exists**

Run:
```bash
gh label list --search mcp-spec-drift
```

If it does not exist, create it:
```bash
gh label create mcp-spec-drift \
  --color "B60205" \
  --description "Vendored MCP spec schema has drifted from upstream"
```

- [ ] **Step 5: Manually trigger the workflow once to verify it runs**

After the PR merges (the workflow is not runnable from the branch unless `workflow_dispatch` is on `main`), trigger it via:
```bash
gh workflow run mcp-spec-drift.yml
```

This is a post-merge verification — note it for the PR description.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/mcp-spec-drift.yml
git commit -m "$(cat <<'EOF'
ci: add mcp-spec-drift weekly check (#263)

Runs scripts/refresh-mcp-spec.sh --check against the vendored MCP
schema. On drift, opens or comments on a tracking issue with the
diff and fails the run for badge visibility.

EOF
)"
```

---

## Task 15: CHANGELOG + cross-link the spec

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current top of CHANGELOG.md to match the existing style**

Run:
```bash
sed -n '1,40p' CHANGELOG.md
```

Note the header pattern (likely `## [Unreleased]` with sub-sections like `### Added`, `### Changed`).

- [ ] **Step 2: Add entries under Unreleased**

Edit `CHANGELOG.md` and add under `## [Unreleased]`:

```markdown
### Added

- MCP wire-shape conformance test
  (`crates/rimap-server/tests/mcp_wire_conformance.rs`) — spawns the
  binary, drives JSON-RPC over stdio, and validates every response
  against the vendored MCP spec schema. Permanent regression net for
  #261 (empty capabilities) and `fix/tool-input-schema-object-type`
  (empty inputSchema). Issue #263.
- `scripts/refresh-mcp-spec.sh` to refresh or drift-check the vendored
  MCP spec schema.
- `.github/workflows/mcp-spec-drift.yml` — weekly check that opens a
  tracking issue when the vendored MCP schema differs from upstream.

### Changed

- `rimap-config` now accepts configs with `accounts = []`. The server
  boots in infrastructure-only mode (only `list_accounts` / `use_account`
  are functionally useful). Unblocks the wire-conformance harness.
  Removes `ConfigError::NoAccounts`.
```

If the existing format differs, adapt to match.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record MCP wire-conformance harness landing (#263)"
```

---

## Task 16: Pre-PR verification gate

- [ ] **Step 1: Run the full workspace verification chain**

Run each in sequence and confirm clean output:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
prek run --all-files
```

Expected: every command exits 0. Any failure must be addressed before opening the PR — do not bypass.

- [ ] **Step 2: Confirm the new test file's specific test list**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_conformance -- --list
```

Expected: lists exactly these tests:
- `wire_smoke_initialize_returns_valid_envelope`
- `wire_initialize_advertises_tools_capability`
- `wire_protocol_version_negotiation_matches_vendored_schema`
- `wire_initialized_notification_elicits_no_response`
- `wire_tools_list_returns_object_schemas`
- `wire_resources_list_is_empty_for_no_accounts`
- `wire_tools_call_unknown_tool_returns_error_envelope`
- `wire_unknown_method_returns_minus_32601`
- `wire_clean_eof_shutdown_exits_zero`

That's 9 tests (8 from the spec + 1 smoke). If any are missing, return to the corresponding task before opening the PR.

- [ ] **Step 3: Confirm the spec → plan → code chain is intact**

Run:
```bash
git log --oneline origin/main..HEAD
```

Expected: a sequence of one commit per task, in order, attributable to the spec and issue. Tidy up via interactive rebase only if explicitly requested by the reviewer — by default, leave the commit-per-task structure as the audit trail.

- [ ] **Step 4: Open the PR**

```bash
git push -u origin HEAD
gh pr create --title "test(mcp): Phase 1 wire-shape conformance harness (#263)" --body "$(cat <<'EOF'
## Summary

- Spawns rusty-imap-mcp with a zero-account tempdir config and drives MCP JSON-RPC over stdio.
- Validates every response against the vendored MCP spec schema (`2025-11-25`).
- Permanent regression nets for #261 (empty capabilities) and `fix/tool-input-schema-object-type` (empty inputSchema).
- Lifts `ConfigError::NoAccounts` to allow infrastructure-only boot.
- Adds a refresh script and weekly CI drift detector for the vendored schema.

Closes #263.

## Test plan

- [ ] `cargo test -p rimap-server --test mcp_wire_conformance` — 9 tests, all green.
- [ ] `cargo test --workspace` — full suite green.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- [ ] `cargo deny check` — clean.
- [ ] `actionlint` + `zizmor` against the new workflow — clean.
- [ ] Post-merge: `gh workflow run mcp-spec-drift.yml` once to confirm the drift workflow executes.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of scope (Phase 2–4, separate issues)

- Node SDK strict-client validation — issue #264.
- Behavioral conformance against Dovecot fixture — issue #265.
- Protocol fuzzing / negative-path coverage — issue #266.

If any task here surfaces a bug that fits one of those scopes, capture it as a comment on the corresponding issue, not in this PR.
