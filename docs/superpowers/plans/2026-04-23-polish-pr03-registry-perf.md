# Polish PR 3 — Registry perf (#144 + #148)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two coupled perf changes inside `crates/rimap-server/src/boot/registry.rs` and `crates/rimap-server/src/mcp/server.rs`. (1) Parallelize `AccountRegistry::build`'s per-account loop so that N independent IMAP `LIST` round trips issue concurrently instead of serially (#144). (2) Cache the `tools/list` result on `AccountRegistry` so the per-call `Vec<Tool>` rebuild + per-tool `format!` work happens once at boot instead of on every MCP `tools/list` request (#148).

**Architecture:** For #144, swap the `for (id, acfg) in &multi.accounts` body into a closure inside `futures::stream::iter(...).map(...).buffer_unordered(N).try_collect()`. Borrowed inputs (`audit`, `credentials`, `download_dir`) are already `&` references or `Arc<T>`, so capture-by-clone of the `Arc`s lets the futures be `Send + 'static` for the buffered stream. For #148, populate `OnceLock<Arc<Vec<Tool>>>` lazily in `AccountRegistry::list_tools_cached`; the rmcp `ListToolsResult::with_all_items` API still wants `Vec<Tool>` by value, so we clone the inner Vec at the boundary — but the per-tool `format!` and `Tool::clone` work disappears.

**Tech Stack:** Rust, `futures::stream` (already a workspace dep via `futures-util`), `std::sync::OnceLock`, Tokio.

---

## Context the engineer must read first

Lesson 1 of `RESUME.md`: verify API assumptions before writing code blocks.

- `crates/rimap-server/src/boot/registry.rs` — full file. Most-relevant sections:
  - `AccountState` struct (lines 55–77) — the per-account bundle that the parallel build must produce N of.
  - `AccountRegistry` struct (lines 91–102) and `AccountRegistry::new` (lines 105–114) — `OnceLock<Arc<Vec<Tool>>>` lands as a new field initialized empty in `new`.
  - `build` function (lines 220–286) — the serial loop being parallelized. Inputs: `multi: &ValidatedMultiConfig`, `audit: &AuditWriter`, `credentials: &Arc<dyn CredentialStore>`, `download_dir: &Arc<Path>`. The shared `auth_sink: Arc<dyn AuthEventSink>` is built once before the loop (line 238) and cloned per iteration; preserve that.
  - `build_account_guard`, `build_account_connection`, `build_smtp_client` — pure helpers, used unchanged.
- `crates/rimap-server/src/boot/discovery.rs` — `resolve_special_use(&imap)` is the per-account network round trip. Its `&Connection` borrow shape determines what the parallel future captures.
- `crates/rimap-server/src/mcp/server.rs:262-306` — current `list_tools` impl. The plan keeps the dispatch logic identical; the cache wraps it.
- `crates/rimap-server/src/mcp/tool_catalog.rs` — `TOOL_DEFS` source. Used inside `list_tools` and stays the same.
- `Cargo.toml` workspace deps — `futures-util = "0.3"` is already declared (line 54). `rimap-server`'s `Cargo.toml` does NOT yet pull it; Task 1 adds the inheritance.

## Dependency note

`futures-util` is already a workspace dep but is not currently a direct dep of `rimap-server`. Task 1 adds `futures-util = { workspace = true }` to `rimap-server/Cargo.toml`. No new workspace-level entry, no new third-party crate.

---

## Files

- Modify: `crates/rimap-server/Cargo.toml` — add `futures-util = { workspace = true }`.
- Modify: `crates/rimap-server/src/boot/registry.rs` — parallelize `build`; add `OnceLock<Arc<Vec<Tool>>>` field + `list_tools_cached` method on `AccountRegistry`.
- Modify: `crates/rimap-server/src/mcp/server.rs` — `ServerHandler::list_tools` reads the cache; the dispatch logic moves to a private `compute_advertised_tools` (also lives on `AccountRegistry` so the cache can populate it).

## Task 1: Add `futures-util` to `rimap-server`

**Files:**
- Modify: `crates/rimap-server/Cargo.toml`

- [ ] **Step 1: Add the dep**

In `crates/rimap-server/Cargo.toml`, add this line at the end of the `[dependencies]` table (alphabetical ordering — after `clap`, before `governor`):

```toml
futures-util = { workspace = true }
```

- [ ] **Step 2: Verify resolution**

Run: `cargo tree -p rimap-server -i futures-util 2>&1 | head -3`
Expected: a tree rooted at `futures-util vX.Y.Z` with `rimap-server` as a parent edge.

- [ ] **Step 3: Run `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. `futures-util` is already in the graph (transitively via other crates), so no new license/advisory surface.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/Cargo.toml Cargo.lock
git commit -m "$(cat <<'EOF'
chore(deps): add futures-util to rimap-server (#144)

Required for the upcoming parallel AccountRegistry::build loop using
futures::stream::FuturesUnordered. futures-util is already a workspace
dep used transitively; this PR adds the direct edge.

Refs #144.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Parallelize `AccountRegistry::build` (#144)

**Files:**
- Modify: `crates/rimap-server/src/boot/registry.rs`

- [ ] **Step 1: Read the current loop body to confirm capture set**

```bash
sed -n '230,290p' crates/rimap-server/src/boot/registry.rs
```

Confirm the per-iteration body uses ONLY:
- `id: &AccountId` (loop key)
- `acfg: &ValidatedAccountConfig` (loop value)
- `auth_sink: Arc<dyn AuthEventSink>` (built once before loop, cloned)
- `credentials: &Arc<dyn CredentialStore>` (cloned into the resolver)
- `download_dir: &Arc<Path>` (cloned into AccountState)

If anything else is captured, abandon the parallelization plan and STOP — the assumed independence does not hold.

- [ ] **Step 2: Rewrite the body as a `try_collect` over a buffered stream**

Replace the `build` function body (lines 236–286). Keep the function signature and doc comment identical:

```rust
pub async fn build(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> anyhow::Result<AccountRegistry> {
    use futures_util::stream::{self, StreamExt as _, TryStreamExt as _};

    /// Cap the number of in-flight per-account setups. The work per
    /// account is one IMAP `LIST` round trip; `4` is a conservative
    /// bound that gives parallelism speedup for typical 1–5-account
    /// configs without flooding the system with sockets when an
    /// operator deploys with 50 accounts. Tuning beyond this is a
    /// separate concern (see #128 IMAP connection pool depth).
    const PARALLEL_BUILD_CONCURRENCY: usize = 4;

    let auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());

    // Build per-account `(AccountId, AccountState)` futures. Each future
    // owns a clone of `auth_sink`, `credentials`, and `download_dir`,
    // and borrows nothing from `multi` so that the buffer can hold
    // them as `Send + 'static`.
    let account_iter = multi.accounts.iter().map(|(id, acfg)| {
        let id = id.clone();
        let acfg = acfg.clone();
        let auth_sink = Arc::clone(&auth_sink);
        let credentials = Arc::clone(credentials);
        let download_dir = Arc::clone(download_dir);
        async move { build_one_account(id, acfg, auth_sink, credentials, download_dir).await }
    });

    let states: Vec<(AccountId, AccountState)> = stream::iter(account_iter)
        .buffer_unordered(PARALLEL_BUILD_CONCURRENCY)
        .try_collect()
        .await?;

    let account_states: BTreeMap<AccountId, AccountState> = states.into_iter().collect();
    Ok(AccountRegistry::new(account_states))
}

/// Single-account setup: build the dispatch guard, IMAP connection, run
/// special-use discovery, and assemble the `AccountState`.
///
/// Owns the `Arc`s passed in so the resulting future is `Send + 'static`
/// for `buffer_unordered` consumption.
async fn build_one_account(
    id: AccountId,
    acfg: ValidatedAccountConfig,
    auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink>,
    credentials: Arc<dyn CredentialStore>,
    download_dir: Arc<std::path::Path>,
) -> anyhow::Result<(AccountId, AccountState)> {
    let guard = build_account_guard(&acfg).context("building dispatch guard")?;
    let conn_cfg = build_account_connection(&id, &acfg);
    let resolver: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            Arc::clone(&credentials),
            acfg.fallback_mode,
        ));
    let imap = Connection::new(conn_cfg, auth_sink, resolver);

    let special_use = crate::boot::discovery::resolve_special_use(&imap)
        .await
        .with_context(|| format!("resolving special-use folders for account {}", id.as_str()))?;

    // Expand the config-supplied protected-folders list with any
    // server-declared RFC 6154 names (e.g. Gmail's `[Gmail]/Sent Mail`).
    // The merge is case-insensitive so user-configured literals
    // (`"Sent"`) are not duplicated when the server also reports
    // `"Sent"` on the same mailbox.
    let mut protected = acfg.security.protected_folders.clone();
    for discovered in special_use.all_discovered() {
        if !protected
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&discovered))
        {
            protected.push(discovered);
        }
    }

    let smtp = build_smtp_client(&acfg, &credentials)?;

    let folder_guard = FolderGuard::new(&protected, &acfg.security.expunge_folders);

    let state = AccountState {
        id: id.clone(),
        imap,
        smtp,
        guard,
        folder_guard,
        download_dir,
        special_use,
    };
    Ok((id, state))
}
```

`build_smtp_client`'s current signature is `fn(acfg: &ValidatedAccountConfig, credentials: &Arc<dyn CredentialStore>) -> ...`. Keep that signature; the new `build_one_account` borrows `&acfg` and `&credentials` for the duration of the call.

`ValidatedAccountConfig`'s `Clone` impl: confirm it derives or implements `Clone` before assuming `acfg.clone()` works:

```bash
rg -n 'pub struct ValidatedAccountConfig|derive\(.*Clone' crates/rimap-config/src/validate/mod.rs | head -5
```

If `ValidatedAccountConfig` is NOT `Clone`, the closure must move `&acfg` into a fresh `Arc<ValidatedAccountConfig>` instead. Check before writing the closure body — DO NOT guess. If clone is unavailable and `Arc<ValidatedAccountConfig>` is the path, update the `build_one_account` parameter to `Arc<ValidatedAccountConfig>` and dereference inside the function.

- [ ] **Step 3: Compile check**

Run: `cargo check -p rimap-server`
Expected: clean. Any "future is not `Send`" diagnostic means a non-Send field slipped into the closure capture; trace which one (often a `dyn Trait` without `+ Send + Sync`).

If `auth_sink` triggers a `Send + Sync` requirement, confirm `dyn AuthEventSink` is bound `Send + Sync`. Look at `rimap_core::auth_sink::AuthEventSink`'s definition — if it has supertraits `Send + Sync`, the compiled trait object satisfies them; otherwise the bound is required at the use site (`Arc<dyn AuthEventSink + Send + Sync>`). Check:

```bash
rg -n 'pub trait AuthEventSink' crates/rimap-core/src/auth_sink.rs
```

If the trait isn't `Send + Sync`-bounded, that's a separate concern; add the bounds to the `Arc<dyn ...>` declarations in `registry.rs` and `build_one_account`.

- [ ] **Step 4: Run the existing build tests**

Run: `cargo test -p rimap-server --lib boot::registry`
Expected: pre-existing tests pass. If the file has no in-line tests, integration tests at the workspace level cover the path; run those instead.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 5: Confirm parallelism with a tracing observation (manual)**

This step is OPTIONAL. If `RUST_LOG=trace` is enabled and the test fixture has ≥2 accounts, observe in stdout that `resolve_special_use` spans for distinct accounts overlap in time. If your local test setup doesn't have ≥2 accounts, skip — the unit-test path proves correctness even if it doesn't prove parallelism.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/boot/registry.rs
git commit -m "$(cat <<'EOF'
perf(rimap-server): parallelize AccountRegistry::build per-account setup (#144)

Each account's setup does one IMAP LIST round trip in
resolve_special_use; the previous serial loop paid N x RTT cold-start
cost. Move the per-account body into build_one_account and consume it
through futures::stream::iter(...).buffer_unordered(4).try_collect()
so up to four account setups are in flight at once.

Output BTreeMap is built from the (AccountId, AccountState) pairs
returned by the futures, preserving the same ordering and
membership as the old serial loop.

PARALLEL_BUILD_CONCURRENCY is capped at 4 — enough parallelism for
the typical 1-5-account config, conservative against deployments
with dozens of accounts. Tunable per #128 if operators care.

Closes #144.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Cache `list_tools` on `AccountRegistry` (#148)

**Files:**
- Modify: `crates/rimap-server/src/boot/registry.rs`
- Modify: `crates/rimap-server/src/mcp/server.rs`

- [ ] **Step 1: Write the failing cache-coherence test**

Append a unit test to `crates/rimap-server/src/boot/registry.rs` (in a fresh `#[cfg(test)] mod list_tools_cache_tests` if there is no `tests` module yet):

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod list_tools_cache_tests {
    use super::AccountRegistry;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn list_tools_cached_returns_same_arc_across_calls() {
        // Pin the cache contract: list_tools_cached returns the same
        // Arc<Vec<Tool>> on every call within a registry generation.
        // If a future refactor reverts to "build fresh on every call",
        // this assertion catches the regression — Arc::ptr_eq checks
        // identity, not equality.
        let reg = AccountRegistry::new(BTreeMap::new());
        let a = reg.list_tools_cached();
        let b = reg.list_tools_cached();
        assert!(
            Arc::ptr_eq(&a, &b),
            "list_tools_cached must return the same Arc on repeat calls",
        );
    }

    #[test]
    fn list_tools_cached_includes_use_account_and_list_accounts_for_empty_registry() {
        // Empty registry still advertises the two infrastructure tools
        // (use_account, list_accounts). The cached Vec should contain
        // both, and only those, when no accounts are configured.
        let reg = AccountRegistry::new(BTreeMap::new());
        let tools = reg.list_tools_cached();
        let names: std::collections::BTreeSet<_> =
            tools.iter().map(|t| t.name.to_string()).collect();
        assert!(names.contains("use_account"), "tools = {names:?}");
        assert!(names.contains("list_accounts"), "tools = {names:?}");
        assert_eq!(
            tools.len(),
            2,
            "empty registry should advertise exactly 2 tools, got {tools:?}",
        );
    }
}
```

Run: `cargo test -p rimap-server --lib list_tools_cache_tests`
Expected: compile error — `cannot find method 'list_tools_cached'`.

- [ ] **Step 2: Add the cache field on `AccountRegistry`**

In `crates/rimap-server/src/boot/registry.rs`, replace the `AccountRegistry` struct (lines ~91–102):

```rust
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    /// Process-wide rate limiter for infrastructure tools
    /// (`use_account`, `list_accounts`). ...
    infrastructure_limiter: InfrastructureLimiter,
    /// Clock used by the infrastructure limiter; ...
    clock: DefaultClock,
}
```

with:

```rust
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    /// Process-wide rate limiter for infrastructure tools
    /// (`use_account`, `list_accounts`). Prevents an injected prompt
    /// from flip-flopping the active account faster than a human
    /// would. 5 req/sec sustained, burst of 10.
    infrastructure_limiter: InfrastructureLimiter,
    /// Clock used by the infrastructure limiter; stored so that
    /// `wait_time_from` can format retry hints.
    clock: DefaultClock,
    /// Lazily-populated `tools/list` result. Built once per
    /// `AccountRegistry` instance from the registered accounts'
    /// posture matrices and the static tool catalog; the rmcp
    /// `ListToolsResult` API requires `Vec<Tool>` by value, so callers
    /// clone the inner vec at the boundary, but the per-tool
    /// `format!` and `Tool::clone` work happens once. See #148.
    list_tools_cache: std::sync::OnceLock<Arc<Vec<rmcp::model::Tool>>>,
}
```

Update `AccountRegistry::new` to initialize the cache as empty:

```rust
    pub fn new(accounts: BTreeMap<AccountId, AccountState>) -> Self {
        let quota = Quota::per_second(INFRA_RATE_PER_SEC).allow_burst(INFRA_BURST);
        Self {
            accounts,
            infrastructure_limiter: RateLimiter::direct(quota),
            clock: DefaultClock::default(),
            list_tools_cache: std::sync::OnceLock::new(),
        }
    }
```

- [ ] **Step 3: Add `list_tools_cached` and `compute_advertised_tools`**

Append these methods to the `impl AccountRegistry` block:

```rust
    /// Return the cached `tools/list` result. Populated lazily on first
    /// call from the registered accounts' posture matrices and the
    /// static tool catalog; subsequent calls return the same `Arc<Vec>`.
    ///
    /// The `Arc` clone is `O(1)`. The rmcp `ListToolsResult` API takes
    /// `Vec<Tool>` by value, so the call site clones the inner Vec at
    /// the rmcp boundary — but the per-tool `format!` /
    /// `Tool::clone` work no longer runs per request. See #148.
    #[must_use]
    pub fn list_tools_cached(&self) -> Arc<Vec<rmcp::model::Tool>> {
        Arc::clone(self.list_tools_cache.get_or_init(|| {
            Arc::new(self.compute_advertised_tools())
        }))
    }

    /// Build the advertised tool list from registered accounts. Mirrors
    /// the dispatch logic that previously lived inside
    /// `ServerHandler::list_tools`; centralized here so the cache
    /// builds it once.
    fn compute_advertised_tools(&self) -> Vec<rmcp::model::Tool> {
        use crate::mcp::tool_catalog::TOOL_DEFS;
        use crate::mcp::tool_name::is_legacy_single_account;

        let mut tools: Vec<rmcp::model::Tool> = Vec::new();

        // Infrastructure tools — always advertised, never namespaced.
        for name in [rimap_core::tool::ToolName::UseAccount, rimap_core::tool::ToolName::ListAccounts] {
            if let Some(def) = TOOL_DEFS.get(&name) {
                tools.push(def.clone());
            }
        }

        let use_bare_names = is_legacy_single_account(&self.accounts);

        for (id, state) in &self.accounts {
            for &tn in &state.guard.matrix().advertised() {
                let Some(base_def) = TOOL_DEFS.get(&tn) else {
                    continue;
                };
                let tool_name = if use_bare_names {
                    base_def.name.clone()
                } else {
                    format!("{}.{}", id.as_str(), base_def.name).into()
                };
                let description = if use_bare_names {
                    base_def.description.clone()
                } else {
                    Some(
                        format!(
                            "[account: {}, posture: {}] {}",
                            id.as_str(),
                            state.guard.matrix().posture().as_str(),
                            base_def.description.as_deref().unwrap_or(""),
                        )
                        .into(),
                    )
                };
                let mut def = base_def.clone();
                def.name = tool_name;
                def.description = description;
                tools.push(def);
            }
        }

        tools
    }
```

The call to `is_legacy_single_account` was previously inside `ServerHandler::list_tools` and took `&BTreeMap<AccountId, AccountState>` by reference — confirm its current signature with `rg -n 'fn is_legacy_single_account' crates/rimap-server/src/mcp/tool_name.rs` before pasting.

- [ ] **Step 4: Run the unit tests to confirm they pass**

Run: `cargo test -p rimap-server --lib list_tools_cache_tests`
Expected: 2 passes.

- [ ] **Step 5: Replace `ServerHandler::list_tools` with a cache-hit**

In `crates/rimap-server/src/mcp/server.rs`, replace the `list_tools` body (lines 262–306):

```rust
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools: Vec<Tool> = Vec::new();

        // Infrastructure tools — always advertised, never namespaced.
        for name in [ToolName::UseAccount, ToolName::ListAccounts] {
            if let Some(def) = TOOL_DEFS.get(&name) {
                tools.push(def.clone());
            }
        }

        let accounts = self.registry().accounts();
        let use_bare_names = is_legacy_single_account(accounts);

        for (id, state) in accounts {
            for &tn in &state.guard.matrix().advertised() {
                let Some(base_def) = TOOL_DEFS.get(&tn) else {
                    continue;
                };
                let tool_name = if use_bare_names {
                    base_def.name.clone()
                } else {
                    format!("{}.{}", id.as_str(), base_def.name).into()
                };
                let description = if use_bare_names {
                    base_def.description.clone()
                } else {
                    Some(
                        format!(
                            "[account: {}, posture: {}] {}",
                            id.as_str(),
                            state.guard.matrix().posture().as_str(),
                            base_def.description.as_deref().unwrap_or(""),
                        )
                        .into(),
                    )
                };
                let mut def = base_def.clone();
                def.name = tool_name;
                def.description = description;
                tools.push(def);
            }
        }

        Ok(ListToolsResult::with_all_items(tools))
    }
```

with:

```rust
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Cached on AccountRegistry — same Vec contents as the prior
        // inline build, just computed once per registry generation.
        // The rmcp boundary still wants `Vec<Tool>` by value, so we
        // clone the inner vec; the per-tool format!/clone hot path
        // no longer runs per request. See #148.
        let cached = self.registry().list_tools_cached();
        Ok(ListToolsResult::with_all_items((*cached).clone()))
    }
```

If imports `is_legacy_single_account` and `TOOL_DEFS` become unused in `server.rs` after this swap, prune them. Run `cargo clippy -p rimap-server -- -D warnings` to surface any unused-import warnings.

- [ ] **Step 6: Behavioural test — `list_tools` output unchanged**

The byte-for-byte output of `list_tools` must be identical pre- and post-cache. Verify by running the existing `list_tools`-touching tests:

Run: `cargo test -p rimap-server`
Expected: all pre-existing tests pass.

If any test fails on a tool-name string mismatch, the `compute_advertised_tools` migration dropped a step. Trace by diffing the old `list_tools` body with the new `compute_advertised_tools` body line by line.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/boot/registry.rs \
        crates/rimap-server/src/mcp/server.rs
git commit -m "$(cat <<'EOF'
perf(rimap-server): cache list_tools result on AccountRegistry (#148)

Add an OnceLock<Arc<Vec<Tool>>> on AccountRegistry. First call to
list_tools_cached builds the Vec (per-tool format! and Tool::clone
work); every subsequent call returns the same Arc. ServerHandler::
list_tools now does cached.clone() — the rmcp ListToolsResult API
still requires Vec<Tool> by value, but the per-tool work happens
once per registry generation instead of per request.

Output bytes are identical to the pre-cache path; pre-existing
list_tools tests pass without modification. Two new unit tests pin
Arc identity (regression guard) and the empty-registry baseline.

Closes #148.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Full-workspace verification

**Files:** none — green-gate task.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Full workspace test suite**

Run: `cargo test --workspace`
Expected: all tests pass. The two test areas to monitor:
- `boot::registry` — parallel build path correctness
- `mcp::list_tools` (`tools_*` integration tests) — cached output matches pre-cache

If a pre-existing TMPDIR-race flake fires (`socket_path` vs `socket_setup`), retry once. Don't try to fix it here.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean.

- [ ] **Step 5: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- `build_one_account` captures only `Send + 'static` types (Arc-wrapped or owned). The `buffer_unordered(N)` stream requires this — confirm with `cargo check`.
- The output `BTreeMap` keying is preserved (still sorted by `AccountId`); test fixtures and consumers don't notice the parallel build.
- `PARALLEL_BUILD_CONCURRENCY = 4` is documented as a deliberate cap, not a "small enough to be safe" hand-wave.
- `list_tools_cache` is `OnceLock`, NOT `RwLock<Option<Arc<...>>>` — the cache is write-once for a registry generation, so `OnceLock` is the right primitive.
- `compute_advertised_tools` lives on `AccountRegistry` (where `accounts` lives), not on `ImapMcpServer` — the cache is daemon-wide, not per-session.
- Two unit tests prove the cache contract: identity (`Arc::ptr_eq`) AND content baseline (empty registry has the two infrastructure tools).
- Three commits land in order: dep, parallelize, cache. Each is independently buildable and clippy-clean.

## Out of scope

- **Configurable `PARALLEL_BUILD_CONCURRENCY`.** A user-tunable bound is one config setting, but operators with 50+ accounts is a separate workload (#128 IMAP connection pool depth tracks it). Defer.
- **`list_tools` invalidation on `tools/list_changed`.** The cache is daemon-lifetime; `notifications/tools/list_changed` is fired after `use_account` (which doesn't change the registry). If a future feature adds dynamic account add/remove at runtime, the cache will need a generation counter — out of scope here.
- **Replacing `BTreeMap` with `IndexMap` for the parallel build.** Build order doesn't matter at runtime; preserve the sorted-iteration contract that `BTreeMap` gives.
- **Anything in `daemon/run.rs`.** That's PR2 (#137 + #142).
- **Test infra for live IMAP.** That's PR12 (#136).

If you find yourself editing anything outside the Files list, stop and re-read this plan.
