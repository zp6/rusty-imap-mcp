# Polish PR 10 — Config-path DRY (`resolve_or_default`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the repeated `override.or_else(|| resolve_config_path(None)).ok_or_else(...)` pattern into a single helper used by both `daemon_main` and `resolve_cli_config_path` in `crates/rimap-server/src/main.rs`.

**Architecture:** Pure mechanical refactor. One private helper, two call sites rewritten to call it. No behavior change.

**Tech Stack:** Rust, `anyhow`, `rimap-config::loader::resolve_config_path`.

---

## Files

- Modify: `crates/rimap-server/src/main.rs` (add helper; update `daemon_main` @ line 131; update `resolve_cli_config_path` @ line 217)

## Task 1: Add the helper and unit-test it

**Files:**
- Modify: `crates/rimap-server/src/main.rs` — add `resolve_or_default` helper, plus a `#[cfg(test)]` unit test section.

- [ ] **Step 1: Add a failing unit test**

Append this module to the end of `crates/rimap-server/src/main.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod resolve_or_default_tests {
    use super::resolve_or_default;
    use std::path::PathBuf;

    #[test]
    fn override_path_wins_over_env() {
        let explicit = PathBuf::from("/tmp/custom.toml");
        let got = resolve_or_default(Some(explicit.clone())).unwrap();
        assert_eq!(got, explicit);
    }

    #[test]
    fn no_override_and_no_env_is_error() {
        // SAFETY: test is single-threaded in this file; we clear the var
        // for just this scope. If the env var is set, honour it by skipping.
        let had = std::env::var_os("RUSTY_IMAP_MCP_CONFIG");
        unsafe { std::env::remove_var("RUSTY_IMAP_MCP_CONFIG"); }
        let err = resolve_or_default(None).unwrap_err();
        assert!(err.to_string().contains("no config path"));
        if let Some(v) = had {
            unsafe { std::env::set_var("RUSTY_IMAP_MCP_CONFIG", v); }
        }
    }
}
```

- [ ] **Step 2: Run the test to confirm it fails to compile**

Run: `cargo test -p rimap-server --lib resolve_or_default_tests`
Expected: compile error — `cannot find function 'resolve_or_default'`.

- [ ] **Step 3: Add the helper**

Insert this function immediately above `fn resolve_cli_config_path` at `crates/rimap-server/src/main.rs:217`:

```rust
/// Resolve a config-file path from an explicit `--config` override, falling
/// back to the `RUSTY_IMAP_MCP_CONFIG` environment variable via
/// [`resolve_config_path`]. Errors with the same "no config path" message
/// used by the previous inline implementations.
fn resolve_or_default(override_: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    override_
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}
```

- [ ] **Step 4: Run the test to confirm it passes**

Run: `cargo test -p rimap-server --lib resolve_or_default_tests`
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "refactor(rimap-server): add resolve_or_default config-path helper (#138)"
```

## Task 2: Replace both call sites with the helper

**Files:**
- Modify: `crates/rimap-server/src/main.rs` — `daemon_main` (lines 131–135) and `resolve_cli_config_path` (lines 217–224).

- [ ] **Step 1: Update `daemon_main` to use the helper**

In `crates/rimap-server/src/main.rs`, replace:

```rust
    let config_path = config_override
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })?;
```

with:

```rust
    let config_path = resolve_or_default(config_override)?;
```

- [ ] **Step 2: Update `resolve_cli_config_path` to use the helper**

Replace:

```rust
/// Resolve the config file path from `--config` or the
/// `RUSTY_IMAP_MCP_CONFIG` environment variable, erroring if neither is set.
fn resolve_cli_config_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    cli.config
        .clone()
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}
```

with:

```rust
/// Resolve the config file path from `--config` or the
/// `RUSTY_IMAP_MCP_CONFIG` environment variable, erroring if neither is set.
fn resolve_cli_config_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    resolve_or_default(cli.config.clone())
}
```

- [ ] **Step 3: Verify `resolve_config_path` is still imported but no longer called directly**

Run: `rg -n 'resolve_config_path' crates/rimap-server/src/main.rs`

Expected: one hit on the `use rimap_config::loader::{load_and_validate, resolve_config_path};` line (used inside `resolve_or_default`). If the grep shows more hits, repeat step 1 or 2 on the remaining call site.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test -p rimap-server`
Expected: all tests pass, including the existing `dry_run_cli` tests which exercise the `resolve_cli_config_path` path end-to-end.

- [ ] **Step 5: Run clippy with the project's zero-warnings policy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean exit.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-server): route daemon_main through resolve_or_default (#138)

Closes #138. Both daemon_main and resolve_cli_config_path now share the
same one-line helper. Behaviour unchanged; the error message matches the
original wording.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Self-review

- Every step has concrete code, not a prose description.
- Tests added before the helper (TDD), runs-and-fails step included.
- Both call sites rewritten; `rg` check in task 2 step 3 confirms coverage.
- `clippy -D warnings` gate before the second commit catches any stray warnings.
