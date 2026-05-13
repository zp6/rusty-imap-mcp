# MCP Wire-Conformance — Codex Adversarial Review Fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the three findings from Codex's adversarial review of PR #270: restore the production `accounts = []` rejection while keeping the harness functional through a test-support entrypoint, validate full JSON-RPC envelopes on every harness response, and tie the pinned MCP protocol version to `rmcp::ProtocolVersion::LATEST` so version skew fails loudly.

**Architecture:** Production code re-instates `ConfigError::NoAccounts`. A new `validate_multi_allowing_empty()` and `load_and_validate_allowing_empty()` live behind the existing `test-support` feature in `rimap-config`. The `rusty-imap-mcp` binary gains a `#[cfg(feature = "test-support")] --allow-empty-accounts` CLI flag that routes through the relaxed validator. The harness passes the flag and otherwise behaves identically. Envelope validation is folded into `Harness::request` so every test gets it. The pinned schema version is sourced from `rmcp::model::ProtocolVersion::LATEST.as_str()` at runtime, with assertions that the constant, the LATEST value, and the vendored fixture directory all agree.

**Tech Stack:** Rust (workspace edition 2024, MSRV 1.88.0), `rmcp 1.5`, existing `test-support` feature flags on `rimap-config` and `rimap-server`, `jsonschema 0.46`, `tokio::process`.

**Source review:** `https://github.com/randomparity/rusty-imap-mcp/pull/270` Codex adversarial review (2026-05-12).
**Parent plan:** `docs/superpowers/plans/2026-05-12-mcp-wire-conformance.md`.

---

## File structure

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/rimap-config/src/error.rs` | modify | Re-add `ConfigError::NoAccounts` variant |
| `crates/rimap-config/src/validate/mod.rs` | modify | Reinstate empty-accounts rejection in `validate_multi`; add `validate_multi_allowing_empty` (test-support gated); move the empty-OK test to that path; add a test asserting production rejection |
| `crates/rimap-config/src/loader.rs` | modify | Add `load_and_validate_allowing_empty` (test-support gated) that mirrors `load_and_validate` but routes the multi branch through the relaxed validator |
| `crates/rimap-server/src/cli/mod.rs` | modify | Add `#[cfg(feature = "test-support")] --allow-empty-accounts` CLI flag, `hide = true` |
| `crates/rimap-server/src/main.rs` | modify | Dispatch to `load_and_validate_allowing_empty` when the flag is set |
| `crates/rimap-server/tests/mcp_wire_conformance.rs` | modify | Pass `--allow-empty-accounts` from the harness; bake envelope validation into `Harness::request`; switch pinned version to `rmcp::ProtocolVersion::LATEST`; assert PINNED == LATEST and the fixture dir matches |

---

## Task 1: Restore production `NoAccounts` rejection

This task only touches production code. It will break the conformance harness (which still spawns the binary without `--allow-empty-accounts`); Task 3 + 4 will repair the harness path before the branch ships green.

**Files:**
- Modify: `crates/rimap-config/src/error.rs`
- Modify: `crates/rimap-config/src/validate/mod.rs`

- [ ] **Step 1: Re-add the `NoAccounts` error variant**

In `crates/rimap-config/src/error.rs`, find the end of the `ConfigError` enum (just before the closing `}`) and add:

```rust
    /// Multi-account config has an empty `[[accounts]]` array.
    ///
    /// Codex adversarial review (PR #270, 2026-05-12) flagged that
    /// silently accepting empty-accounts configs in production makes
    /// broken deployments look identical to healthy zero-data servers.
    /// The check stays in production; tests opt in via
    /// [`crate::validate::validate_multi_allowing_empty`] behind the
    /// `test-support` feature.
    #[error("no accounts defined in [[accounts]] array")]
    NoAccounts,
```

- [ ] **Step 2: Write the failing test asserting `validate_multi` rejects empty accounts**

Open `crates/rimap-config/src/validate/mod.rs`. The previous task removed the rejection-side test and added an acceptance-side test (`empty_accounts_array_validates_for_infrastructure_only_boot`). Replace that acceptance test with a rejection test in the same location:

```rust
#[test]
fn empty_accounts_array_rejected_by_production_validator() {
    // Production must fail-fast on `accounts = []` so operators
    // immediately see a broken deployment instead of a healthy
    // zero-data server (Codex adversarial review on PR #270).
    let dir = TempDir::new().unwrap();
    let cfg = base_multi_config(dir.path(), vec![]);
    let err = validate_multi(cfg).unwrap_err();
    assert!(
        matches!(err, ConfigError::NoAccounts),
        "expected ConfigError::NoAccounts, got {err:?}",
    );
}
```

- [ ] **Step 3: Run the test and verify it fails**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo test -p rimap-config empty_accounts_array_rejected_by_production_validator
```
Expected: FAIL — the validator currently accepts empty accounts.

- [ ] **Step 4: Reinstate the rejection inside `validate_multi`**

In `crates/rimap-config/src/validate/mod.rs`, at the top of `validate_multi` (line 71 area), add the gate back as the first check:

```rust
pub fn validate_multi(config: MultiAccountConfig) -> Result<ValidatedMultiConfig, ConfigError> {
    if config.accounts.is_empty() {
        return Err(ConfigError::NoAccounts);
    }

    // ...existing body...
}
```

(Insert before the `let mut accounts = BTreeMap::new();` that opens the existing function body.)

- [ ] **Step 5: Run the test and verify it passes**

```bash
cargo test -p rimap-config empty_accounts_array_rejected_by_production_validator
```
Expected: PASS.

- [ ] **Step 6: Run the full crate test suite (some tests may need updates if they depended on the old behavior)**

```bash
cargo test -p rimap-config
```
Expected: PASS for everything. If a test fails because it relied on the lifted gate, capture the test name — Task 2 will rewire it through the new test-support function.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-config/src/error.rs crates/rimap-config/src/validate/mod.rs
git commit -m "$(cat <<'EOF'
fix(config): restore NoAccounts rejection in production validator

Codex adversarial review on PR #270 flagged that silently accepting
`accounts = []` in production made a broken deployment indistinguishable
from a healthy zero-data server. Restores the rejection in
validate_multi(); the wire-conformance harness will route through a
test-support-gated relaxed validator added in a follow-up commit.

EOF
)"
```

---

## Task 2: Add test-support entrypoints for empty-accounts boot

This task adds the relaxed validator + relaxed loader behind `#[cfg(feature = "test-support")]`. It also updates the test that asserts empty accounts validates so it points at the new function.

**Files:**
- Modify: `crates/rimap-config/src/validate/mod.rs`
- Modify: `crates/rimap-config/src/loader.rs`
- Modify: `crates/rimap-config/src/lib.rs` (re-export new symbols)

- [ ] **Step 1: Add `validate_multi_allowing_empty` to the validate module**

In `crates/rimap-config/src/validate/mod.rs`, immediately after the `validate_multi` function, add:

```rust
/// Variant of [`validate_multi`] that skips the empty-accounts
/// rejection. Used exclusively by the wire-conformance harness so the
/// production server can fail-fast on `accounts = []` while tests
/// still spawn an infrastructure-only binary. Gated behind the
/// `test-support` feature.
#[cfg(feature = "test-support")]
pub fn validate_multi_allowing_empty(
    config: MultiAccountConfig,
) -> Result<ValidatedMultiConfig, ConfigError> {
    let mut accounts = BTreeMap::new();
    for raw in config.accounts {
        let id = AccountId::new(&raw.name)?;
        if accounts.contains_key(&id) {
            return Err(ConfigError::DuplicateAccountName { name: raw.name });
        }

        let security = raw
            .security
            .unwrap_or_else(|| config.defaults.security.clone());
        let limits = raw.limits.unwrap_or_else(|| config.defaults.limits.clone());
        let fallback_mode = raw
            .credentials
            .map_or(config.defaults.credentials.fallback, |c| c.fallback);

        accounts.insert(
            id.clone(),
            validated_account_for(id, &raw, security, limits, fallback_mode)?,
        );
    }

    enforce_audit_containment(&config.audit)?;

    Ok(ValidatedMultiConfig {
        defaults: config.defaults,
        accounts,
        audit: config.audit,
        attachments: config.attachments,
    })
}
```

**IMPORTANT:** The body above must mirror the post-empty-check portion of `validate_multi`. Before writing, open `validate_multi` and copy its body starting from the line AFTER the `if config.accounts.is_empty()` check. The snippet above is a representative shape; adapt it to match the current `validate_multi` body verbatim (helper-function names, field names, etc.) by reading the source. If `validate_multi`'s body is longer than 20 lines and would diverge, factor a private `fn validate_multi_inner(cfg) -> ...` and call it from both `validate_multi` (after the empty check) and `validate_multi_allowing_empty`.

- [ ] **Step 2: Write the failing test for `validate_multi_allowing_empty`**

In the same file, inside the existing `#[cfg(test)] mod tests` block, add a new test next to the rejection test from Task 1:

```rust
#[cfg(feature = "test-support")]
#[test]
fn empty_accounts_array_validates_under_test_support() {
    // Mirror of the previous task's intent, now routed through the
    // test-only relaxed validator. The wire-conformance harness
    // depends on this path to spawn the binary with `accounts = []`
    // (Codex review on PR #270).
    let dir = TempDir::new().unwrap();
    let cfg = base_multi_config(dir.path(), vec![]);
    let validated = validate_multi_allowing_empty(cfg).unwrap();
    assert!(validated.accounts.is_empty());
}
```

- [ ] **Step 3: Run the test (should fail to compile until Step 1 lands, then pass)**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo test -p rimap-config --features test-support empty_accounts_array_validates_under_test_support
```
Expected: PASS. If you get an "unresolved import" error, double-check Step 4 (re-export).

- [ ] **Step 4: Re-export `validate_multi_allowing_empty` from `rimap-config`'s lib.rs**

Open `crates/rimap-config/src/lib.rs`. Find the existing re-export line that exposes `validate_multi`:

```rust
pub use validate::{
    ValidatedAccountConfig, ValidatedMultiConfig, validate_legacy_as_multi, validate_multi,
};
```

Add a second cfg-gated re-export immediately after:

```rust
#[cfg(feature = "test-support")]
pub use validate::validate_multi_allowing_empty;
```

- [ ] **Step 5: Add `load_and_validate_allowing_empty` to the loader**

In `crates/rimap-config/src/loader.rs`, immediately after `load_and_validate`, add:

```rust
/// Variant of [`load_and_validate`] that, for multi-account format,
/// invokes [`crate::validate::validate_multi_allowing_empty`] so the
/// wire-conformance harness can spawn the binary with `accounts = []`.
/// Gated behind the `test-support` feature.
///
/// # Errors
/// Same surface as [`load_and_validate`], minus `ConfigError::NoAccounts`
/// for empty multi-account configs.
#[cfg(feature = "test-support")]
pub fn load_and_validate_allowing_empty(
    path: &Path,
) -> Result<ValidatedMultiConfig, ConfigError> {
    // The format-detection branch reads the file once and dispatches
    // to validate_legacy_as_multi or validate_multi based on which
    // top-level table is present. We need to inline that detection
    // here so the multi branch routes through the relaxed validator.
    // KEEP IN SYNC with load_and_validate above.
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let toml_value: toml::Value =
        toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let has_multi = toml_value.get("accounts").is_some();
    let has_legacy = toml_value.get("imap").is_some();
    match (has_multi, has_legacy) {
        (true, true) => Err(ConfigError::MixedFormat {
            path: path.to_path_buf(),
        }),
        (true, false) => {
            let cfg: MultiAccountConfig =
                toml::from_str(&raw).map_err(|source| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
            crate::validate::validate_multi_allowing_empty(cfg)
        }
        (false, _) => {
            let cfg: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
            crate::validate::validate_legacy_as_multi(cfg)
        }
    }
}
```

**IMPORTANT:** Open the current `load_and_validate` and verify the format-detection logic matches the snippet above (same TOML keys, same error variants). The function above is a faithful adaptation but the project's actual loader may use named imports, different error variants for parse failures, etc. — adjust to match the surrounding code exactly. If `load_and_validate`'s body is non-trivial, factor a private `fn classify_format(path: &Path) -> Result<Format, ConfigError>` returning an enum and call it from both functions.

- [ ] **Step 6: Re-export `load_and_validate_allowing_empty` from lib.rs**

In `crates/rimap-config/src/lib.rs`, if there is a re-export of `loader::load_and_validate`, add a cfg-gated re-export of the new function alongside. Otherwise add one:

```rust
#[cfg(feature = "test-support")]
pub use loader::load_and_validate_allowing_empty;
```

(Skip if the codebase only ever calls `rimap_config::loader::...` directly.)

- [ ] **Step 7: Run the full config test suite under test-support**

```bash
cargo test -p rimap-config --features test-support
```
Expected: all tests pass, including both the production-rejection test from Task 1 and the new acceptance test from Step 2.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-config/src/validate/mod.rs crates/rimap-config/src/loader.rs crates/rimap-config/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(config): test-support entrypoint for empty-accounts boot

Adds validate_multi_allowing_empty and load_and_validate_allowing_empty
behind the existing test-support feature. The wire-conformance harness
will route through these so the production validator can still
fail-fast on `accounts = []` (Codex adversarial review on PR #270).

EOF
)"
```

---

## Task 3: Wire `--allow-empty-accounts` through the `rusty-imap-mcp` CLI

**Files:**
- Modify: `crates/rimap-server/src/cli/mod.rs`
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Add the cfg-gated CLI flag**

Open `crates/rimap-server/src/cli/mod.rs` and locate the `pub struct Cli` definition. After the existing `pub dry_run: bool` field (and before the subcommand), add:

```rust
    /// Skip the empty-accounts rejection in `rimap_config::validate_multi`.
    /// Used by the wire-conformance harness (#263) so the binary can
    /// boot with `accounts = []`. Hidden from `--help` because it is a
    /// test-only knob; compiled out entirely when the `test-support`
    /// feature is off.
    #[cfg(feature = "test-support")]
    #[arg(long, hide = true)]
    pub allow_empty_accounts: bool,
```

- [ ] **Step 2: Route through the relaxed loader when the flag is set**

Open `crates/rimap-server/src/main.rs`. Find the existing call to `load_and_validate(&config_path)` (search for `load_and_validate`). It currently looks something like:

```rust
    let config_path = resolve_cli_config_path(&cli)?;
    let multi = load_and_validate(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
```

Replace that snippet with:

```rust
    let config_path = resolve_cli_config_path(&cli)?;

    // `--allow-empty-accounts` is a #[cfg(feature = "test-support")]
    // CLI flag (#263 Codex adversarial review). In production builds
    // the field does not exist and we always hit the strict loader.
    #[cfg(feature = "test-support")]
    let multi = if cli.allow_empty_accounts {
        rimap_config::loader::load_and_validate_allowing_empty(&config_path)
    } else {
        load_and_validate(&config_path)
    }
    .with_context(|| format!("loading config {}", config_path.display()))?;

    #[cfg(not(feature = "test-support"))]
    let multi = load_and_validate(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
```

If `rimap_config::loader::load_and_validate_allowing_empty` doesn't resolve, use whatever path Task 2 made it available at (e.g. `rimap_config::load_and_validate_allowing_empty` if it was re-exported at the crate root).

- [ ] **Step 3: Confirm the binary still compiles in both cfg modes**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo check -p rimap-server
cargo check -p rimap-server --features test-support
```
Both must be clean.

- [ ] **Step 4: Confirm clippy is clean for both feature combinations**

```bash
cargo clippy -p rimap-server -- -D warnings
cargo clippy -p rimap-server --features test-support -- -D warnings
```
Both must be clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/cli/mod.rs crates/rimap-server/src/main.rs
git commit -m "$(cat <<'EOF'
feat(server): --allow-empty-accounts CLI flag (test-support gated)

Routes through rimap_config::loader::load_and_validate_allowing_empty
when set. The flag is compiled out entirely in production builds.
Used by the wire-conformance harness (#263) so the binary can boot
with `accounts = []` (Codex adversarial review on PR #270).

EOF
)"
```

---

## Task 4: Pass `--allow-empty-accounts` from the harness + verify all 9 tests still pass

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Add the flag to the spawned command in `Harness::spawn`**

Open `crates/rimap-server/tests/mcp_wire_conformance.rs`. Find the `Command::new(cargo_bin("rusty-imap-mcp"))` setup in `Harness::spawn`. Add `.arg("--allow-empty-accounts")` between `.arg("--config")` / `.arg(&config_path)` and the `.stdin(...)` chain:

```rust
        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            // Production rejects `accounts = []`. The harness opts in
            // to infrastructure-only boot via this test-support flag
            // (Codex adversarial review on PR #270).
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
```

- [ ] **Step 2: Run the full conformance suite to confirm the wiring works**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo test -p rimap-server --test mcp_wire_conformance -- --nocapture
```
Expected: all 9 tests pass. If a test fails with the binary exiting before any JSON-RPC reply, the flag did not take effect — confirm Tasks 2/3 landed correctly.

- [ ] **Step 3: Confirm the production binary STILL refuses empty-accounts**

The whole point of this rework is that production builds reject `accounts = []`. Verify directly:

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo build -p rimap-server --bin rusty-imap-mcp --release
TMP=$(mktemp -d)
cat > "$TMP/config.toml" <<TOML
accounts = []

[audit]
path = "$TMP/audit.jsonl"
allowed_base_dir = "$TMP"
TOML
./target/release/rusty-imap-mcp --config "$TMP/config.toml" --dry-run ; echo "exit=$?"
./target/release/rusty-imap-mcp --config "$TMP/config.toml" --allow-empty-accounts --dry-run 2>&1 | head -3
rm -rf "$TMP"
```

Expected:
- The release build dry-run with `accounts = []` and no flag prints something like `loading config ...: no accounts defined in [[accounts]] array` and exits non-zero.
- The release build does NOT accept `--allow-empty-accounts` (the flag is cfg-gated out in release builds without the `test-support` feature). It should print an "unknown argument" error from clap.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "$(cat <<'EOF'
test(mcp): harness opts into empty-accounts boot via --allow-empty-accounts

Production now rejects `accounts = []`; the conformance harness passes
the test-support-gated flag so the binary still boots in
infrastructure-only mode. Verified that release builds without the
test-support feature do not accept the flag (Codex adversarial review
on PR #270).

EOF
)"
```

---

## Task 5: Bake full envelope validation into `Harness::request`

This addresses Codex finding #2 — the negative-path tests asserted only that `response["error"]` is an object and the code/message were right. They didn't validate the envelope itself.

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Add a helper that picks the right envelope fragment**

Locate `assert_valid` in `mcp_wire_conformance.rs`. Add immediately below it:

```rust
/// Validate the FULL JSON-RPC envelope returned by `Harness::request`.
/// Success responses validate against `JSONRPCResultResponse`; error
/// responses validate against `JSONRPCErrorResponse`. Asserts the
/// `jsonrpc` version field on both paths. Codex adversarial review
/// finding #2 (PR #270): the previous negative-path tests checked only
/// `code` and `message` and would have missed a regression that
/// stripped `jsonrpc` or otherwise mangled the envelope.
fn assert_envelope_valid(response: &Value) {
    assert_eq!(
        response["jsonrpc"],
        json!("2.0"),
        "envelope must declare jsonrpc=\"2.0\"; got {response}",
    );

    let has_result = response.get("result").is_some();
    let has_error = response.get("error").is_some();
    match (has_result, has_error) {
        (true, false) => assert_valid(response, "JSONRPCResultResponse"),
        (false, true) => assert_valid(response, "JSONRPCErrorResponse"),
        (true, true) => panic!(
            "envelope must not contain both `result` and `error`; got {response}",
        ),
        (false, false) => panic!(
            "envelope must contain either `result` or `error`; got {response}",
        ),
    }
}
```

- [ ] **Step 2: Call it from `Harness::request`**

Inside `Harness::request`, after the line that parses and asserts the response id (`assert_eq!(response["id"], json!(id), ...)`), insert one line that hands the parsed response off to the envelope validator BEFORE the function returns:

```rust
        let response: Value =
            serde_json::from_str(buf.trim_end()).expect("parse response JSON");
        assert_eq!(response["id"], json!(id), "response id must match request");
        assert_envelope_valid(&response);
        response
```

(Insert the `assert_envelope_valid(&response);` line between the existing id assertion and the bare `response` return expression.)

- [ ] **Step 3: Run the suite — every test should still pass and now validate the full envelope**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo test -p rimap-server --test mcp_wire_conformance -- --nocapture
```
Expected: 9 passed.

If a test fails with a fragment-not-found error like `compile fragment validator: ... JSONRPCErrorResponse ...`, the schema fragment name may differ — check `crates/rimap-server/tests/fixtures/mcp-spec/README.md`'s naming notes section and adjust the names in `assert_envelope_valid` to match the actual `$defs` keys.

- [ ] **Step 4: Drop redundant per-test envelope assertions if they exist**

The smoke test (`wire_smoke_initialize_returns_valid_envelope`) has its own `assert_eq!(response["jsonrpc"], json!("2.0"))` plus an `assert!(response["result"].is_object(), ...)`. With `assert_envelope_valid` baked in, both checks are now redundant. Keep them — they are belt-and-suspenders and clarify the smoke test's intent — but do NOT add any new redundant checks elsewhere.

The negative-path tests (`wire_tools_call_unknown_tool_returns_error_envelope`, `wire_unknown_method_returns_minus_32601`) already assert that `response["error"]` is an object — those assertions are now subsumed by the envelope validator but are still informative; leave them in.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "$(cat <<'EOF'
test(mcp): validate full JSON-RPC envelope on every harness response

Adds assert_envelope_valid that picks JSONRPCResultResponse or
JSONRPCErrorResponse based on which member is present, asserts
jsonrpc=2.0, and rejects malformed envelopes that contain both or
neither. Invoked from Harness::request so every test gets full
envelope coverage — including negative-path tests, which Codex's
adversarial review (PR #270, finding #2) noted were only checking
code/message.

EOF
)"
```

---

## Task 6: Tie pinned version to `rmcp::ProtocolVersion::LATEST`

This addresses Codex finding #1 — the hardcoded `PINNED_PROTOCOL_VERSION` could silently lag behind rmcp's `LATEST`.

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

- [ ] **Step 1: Import `rmcp::model::ProtocolVersion`**

At the top of `mcp_wire_conformance.rs`, alongside the other `use` statements, add:

```rust
use rmcp::model::ProtocolVersion;
```

- [ ] **Step 2: Replace the hard-coded `PINNED_PROTOCOL_VERSION` initialize value with `LATEST`**

Find `Harness::initialize_handshake`. The current body sends `PINNED_PROTOCOL_VERSION` as the request's `protocolVersion`. Replace with `ProtocolVersion::LATEST.as_str()`:

```rust
    async fn initialize_handshake(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": ProtocolVersion::LATEST.as_str(),
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-conformance-harness",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
        .await
    }
```

Keep `PINNED_PROTOCOL_VERSION` as a constant — it remains the source of truth for which fixture directory the validators load from. The constant just stops being the value SENT during handshake.

- [ ] **Step 3: Rewrite `wire_protocol_version_negotiation_matches_vendored_schema` to detect drift in three places**

Replace the existing body of `wire_protocol_version_negotiation_matches_vendored_schema` with:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_protocol_version_negotiation_matches_vendored_schema() {
    // Three-way drift check (Codex adversarial review finding #1):
    //
    //   1. rmcp::ProtocolVersion::LATEST.as_str()
    //   2. PINNED_PROTOCOL_VERSION (the constant in this file)
    //   3. crates/rimap-server/tests/fixtures/mcp-spec/<version>/
    //
    // All three MUST agree. If any one drifts (rmcp bumps LATEST, the
    // pinned constant goes stale, or someone deletes the fixture
    // directory) this test fails first with a precise diagnostic
    // before any fragment-validation test mis-validates against an
    // outdated schema.

    let rmcp_latest = ProtocolVersion::LATEST.as_str();
    assert_eq!(
        rmcp_latest, PINNED_PROTOCOL_VERSION,
        "rmcp::ProtocolVersion::LATEST ({rmcp_latest}) drifted from \
         PINNED_PROTOCOL_VERSION ({PINNED_PROTOCOL_VERSION}). Run \
         `scripts/refresh-mcp-spec.sh {rmcp_latest}` to vendor the new \
         schema, update PINNED_PROTOCOL_VERSION + MCP_SCHEMA_JSON in \
         this file, and update the README under \
         tests/fixtures/mcp-spec/.",
    );

    // The fixture directory must exist on disk under the pinned name.
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp-spec")
        .join(PINNED_PROTOCOL_VERSION);
    assert!(
        fixture_dir.is_dir(),
        "expected vendored fixture directory at {} for pinned version \
         {PINNED_PROTOCOL_VERSION}; refresh script may not have run",
        fixture_dir.display(),
    );

    // And rmcp must echo whatever the harness sends as the negotiated
    // version, which the harness now derives from LATEST.
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(
        response["result"]["protocolVersion"],
        json!(rmcp_latest),
        "server must echo the rmcp LATEST version sent by the harness; \
         got {response}",
    );
}
```

- [ ] **Step 4: Run the suite — all 9 tests must still pass**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo test -p rimap-server --test mcp_wire_conformance -- --nocapture
```
Expected: 9 passed.

If `wire_protocol_version_negotiation_matches_vendored_schema` fails with the "rmcp drifted" message, that means rmcp's LATEST and our PINNED_PROTOCOL_VERSION disagree right now — investigate before continuing. (They should both be `2025-11-25` per the earlier Task 3 work.)

- [ ] **Step 5: Run 3x for flake stability**

```bash
for i in 1 2 3; do
  cargo test -p rimap-server --test mcp_wire_conformance --quiet 2>&1 | tail -3
done
```
All three runs must show `9 passed; 0 failed`.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "$(cat <<'EOF'
test(mcp): drive protocolVersion from rmcp::ProtocolVersion::LATEST

The harness sent the hardcoded PINNED_PROTOCOL_VERSION ('2025-11-25')
during initialize. If rmcp bumped LATEST but still supported the
pinned value, real strict clients could negotiate the newer protocol
while this harness kept validating the old schema and stayed green
(Codex adversarial review on PR #270, finding #1).

Now the harness sends ProtocolVersion::LATEST.as_str() and the
version-negotiation test asserts a three-way agreement:
  - rmcp::ProtocolVersion::LATEST
  - PINNED_PROTOCOL_VERSION
  - the vendored fixture directory
A drift in any one fails the test first with a precise diagnostic.

EOF
)"
```

---

## Task 7: Final verification + push the Codex-review fixes

**Files:** none — verification-only.

- [ ] **Step 1: Run the full verification chain**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
prek run --all-files
```

Every command must exit zero. If anything fails, STOP and investigate — do NOT push a broken state to a branch that already has an open PR.

- [ ] **Step 2: Confirm the conformance test list is still 9**

```bash
cargo test -p rimap-server --test mcp_wire_conformance -- --list
```
Expected: still 9 tests, same names.

- [ ] **Step 3: Confirm production-build behavior on `accounts = []`**

This re-runs the Task 4 Step 3 production check, but as part of the final gate. Crucial: it proves the no-flag-no-feature-no-flag-accepted invariant holds end-to-end.

```bash
cargo build -p rimap-server --bin rusty-imap-mcp --release
TMP=$(mktemp -d)
cat > "$TMP/config.toml" <<TOML
accounts = []

[audit]
path = "$TMP/audit.jsonl"
allowed_base_dir = "$TMP"
TOML
./target/release/rusty-imap-mcp --config "$TMP/config.toml" --dry-run 2>&1 | grep -i "no accounts" || echo "FAIL: production binary did not reject empty accounts"
./target/release/rusty-imap-mcp --config "$TMP/config.toml" --allow-empty-accounts --dry-run 2>&1 | grep -i "unknown\|unexpected\|unrecognized" || echo "FAIL: production binary accepted --allow-empty-accounts"
rm -rf "$TMP"
```

Both invocations must print the expected error message (not the "FAIL:" line). If either prints "FAIL:", the cfg gating is wrong.

- [ ] **Step 4: Push to the existing PR branch**

```bash
git log --oneline origin/test/mcp-wire-conformance..HEAD
```

Confirm the new commits look reasonable (~7 new commits on top of `2734925`, each referencing the Codex review). Then:

```bash
git push origin HEAD
```

The push updates PR #270 automatically — no new `gh pr create`.

- [ ] **Step 5: Comment on PR #270 documenting the new commits**

```bash
gh pr comment 270 --body "$(cat <<'EOF'
Addressed Codex adversarial review findings:

- **High** (harness pinned version → silent rmcp drift): harness now derives the requested `protocolVersion` from `rmcp::model::ProtocolVersion::LATEST.as_str()`. `wire_protocol_version_negotiation_matches_vendored_schema` asserts three-way agreement between rmcp LATEST, `PINNED_PROTOCOL_VERSION`, and the vendored fixture directory.
- **Medium** (error envelopes not schema-validated): `Harness::request` now calls `assert_envelope_valid` on every response, picking `JSONRPCResultResponse` or `JSONRPCErrorResponse` and asserting `jsonrpc=2.0`. Every test gets full envelope coverage.
- **Medium** (empty-accounts boot weakens production): production validator restored to reject `accounts = []` with `ConfigError::NoAccounts`. New `validate_multi_allowing_empty` / `load_and_validate_allowing_empty` live behind the existing `test-support` feature. The binary exposes `--allow-empty-accounts` only when compiled with `--features test-support`; the harness passes it. Release builds reject both the empty config AND the flag.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Risks & non-goals

- **Risk: `validate_multi_inner` factor / loader-format-detect dedup could be skipped** in Task 2 if the current bodies are short enough to duplicate cleanly. The plan permits either approach; whichever lands, the post-condition is "the relaxed validator's body stays in sync with the strict validator's post-empty-check body." If the bodies diverge in the future, the test in Task 2 Step 2 will not detect it — that's why a follow-up factor is preferable when the body grows.
- **Non-goal:** changing the production behavior of zero-account servers beyond restoring rejection. If a real operator use case for infrastructure-only boot ever materializes (e.g. a docs/quickstart probe), it should be a separate spec with its own opt-in surface (named TOML key, audit-log signal, telemetry) — not a CLI flag.
- **Non-goal:** validating non-envelope fragments more strictly than the existing `assert_valid` does. Method-level fragment checks (e.g. `ListToolsResult`) stay opt-in per test. The baked envelope validation is the universal floor.
