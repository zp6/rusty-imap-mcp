# MCP Dispatch Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two MCP dispatch hygiene issues as one sweep — reject bare tool names in `call_tool` when the server is in multi-account mode (#73), and emit `notifications/tools/list_changed` when `handle_use_account` successfully changes the active account (#80).

**Architecture:** Issue #73 adds one validation check at the top of the `call_tool` dispatch in `crates/rimap-server/src/mcp/server.rs`: after `split_tool_name` classifies the name, if we're not in legacy single-account mode AND the name came back as a bare simple name (no `.`), reject with `ErrorData::invalid_params`. Sub-capability dotted names (`search.advanced_query`, `fetch_message.include_html`) and infrastructure tools (`use_account`, `list_accounts`) remain valid bare forms. Issue #80 threads the rmcp `RequestContext<RoleServer>::peer` into the `UseAccount` dispatch arm: after `handle_use_account` returns successfully, call `context.peer.notify_tool_list_changed(...).await` and log any transport failure at `warn!`. No changes to `handle_use_account`'s signature — the notification emission lives in the dispatch layer, which already owns the context.

**Tech Stack:** Rust (stable), existing `rmcp` server API (`Peer<RoleServer>::notify_tool_list_changed`), existing `ImapMcpServer::call_tool` dispatch, existing `handle_use_account` handler.

---

## Prior-Art Context

`crates/rimap-server/src/mcp/tool_name.rs::is_legacy_single_account` (lines 18–26) returns `true` iff the registry has exactly one account named `"default"`. Already used by `list_tools` to gate bare tool names in the advertised tool list (if legacy, tools are advertised bare; else they're advertised as `<account>.<tool>`).

`split_tool_name(raw: &str) -> (Option<&str>, &str)` (tool_name.rs:83–95) classifies a raw tool name:
- If `ToolName::from_str(raw)` succeeds (including dotted sub-capability variants like `search.advanced_query`), returns `(None, raw)` — treated as bare.
- Otherwise splits on `.`; if the prefix passes `is_valid_account_prefix`, returns `(Some(prefix), rest)`.

`call_tool` in `crates/rimap-server/src/mcp/server.rs:210–248` dispatches:
1. `let (account_prefix, bare_name) = split_tool_name(raw);` (line 215)
2. `let tool_name = ToolName::from_str(bare_name)?` (lines 217–218)
3. Infrastructure tools (`UseAccount`, `ListAccounts`) explicitly reject a non-`None` `account_prefix` with an error (lines 240–246).
4. Other tools resolve the account either from `account_prefix` or (in legacy mode) the default.

No existing check rejects bare *non-infrastructure* simple names in multi-account mode — that's the #73 gap.

`handle_use_account` in `crates/rimap-server/src/tools/admin/accounts.rs:54-67` validates the account name, calls `registry.set_active(account)`, returns `ToolResponse::meta_only(UseAccountMeta { account, previous })`. No notification emission today.

rmcp 1.4.0's `Peer<RoleServer>::notify_tool_list_changed` method is generated via the `method!(peer_not notify_tool_list_changed ToolListChangedNotification)` macro in `rmcp/src/service/server.rs`. `RequestContext<RoleServer>::peer` (already received by `call_tool` at line 213) exposes it.

---

## File Structure

### Modified files

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-server/src/mcp/tool_name.rs` | Helper `is_bare_simple_tool_name(raw: &str) -> bool` — used by the multi-account check. |
| Modify | `crates/rimap-server/src/mcp/server.rs` | (#73) Reject bare simple names in `call_tool` when not in legacy mode. (#80) Emit `tools/list_changed` after a successful `UseAccount` dispatch. |

### Unchanged

- `crates/rimap-server/src/tools/admin/accounts.rs::handle_use_account` — stays pure; dispatch layer does the notification.

---

## Task 1: Reject bare tool names in multi-account mode (#73)

**Issue:** #73 — MCP dispatch contract: advertised tool list is namespaced in multi-account mode but `call_tool` silently accepts bare names, letting clients that hardcoded bare names from a prior session bypass the contract.

**Files:**
- Modify: `crates/rimap-server/src/mcp/tool_name.rs` (new helper).
- Modify: `crates/rimap-server/src/mcp/server.rs` (guard in `call_tool`).

### Approach

Add a pure predicate `is_bare_simple_tool_name(raw: &str) -> bool` that returns `true` iff the raw string:
1. Does NOT contain `.` (so sub-capability dotted names like `search.advanced_query` return `false`)
2. Parses as a valid `ToolName`
3. Is NOT an infrastructure tool (`UseAccount` / `ListAccounts`)

In `call_tool`, after the existing `split_tool_name` call, if `!is_legacy_single_account(...)` AND `is_bare_simple_tool_name(raw)`, return `ErrorData::invalid_params("tool name must be namespaced in multi-account mode: <account>.<tool>")`.

- [ ] **Step 1: Write failing tests**

In `crates/rimap-server/src/mcp/tool_name.rs` (tests block):

```rust
    #[test]
    fn is_bare_simple_tool_name_rejects_namespaced() {
        assert!(!is_bare_simple_tool_name("work.send_email"));
        assert!(!is_bare_simple_tool_name("personal.list_folders"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_sub_capability_dotted() {
        // Sub-capability tools parse as ToolName directly (dot is part of
        // the name). They must remain valid bare forms in multi-account
        // mode — this predicate returns false for them.
        assert!(!is_bare_simple_tool_name("search.advanced_query"));
        assert!(!is_bare_simple_tool_name("fetch_message.include_html"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_infrastructure_tools() {
        assert!(!is_bare_simple_tool_name("use_account"));
        assert!(!is_bare_simple_tool_name("list_accounts"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_unknown_names() {
        // Unknown names are not valid ToolName — predicate returns false
        // because the ToolName::from_str check fails.
        assert!(!is_bare_simple_tool_name("nuke_inbox"));
    }

    #[test]
    fn is_bare_simple_tool_name_accepts_bare_simple_tool_names() {
        for name in ["send_email", "list_folders", "search", "mark_read"] {
            assert!(
                is_bare_simple_tool_name(name),
                "expected bare simple: {name}",
            );
        }
    }
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `cd /home/dave/src/rusty-imap-mcp-mcp-dispatch && cargo test -p rimap-server --lib mcp::tool_name::tests::is_bare_simple_tool_name`
Expected: FAIL — helper undefined.

- [ ] **Step 3: Add the helper**

In `crates/rimap-server/src/mcp/tool_name.rs`, add near the other predicates:

```rust
/// Whether `raw` is a bare simple (undotted) tool name for a non-infrastructure
/// tool. Used by `call_tool` to reject bare forms in multi-account mode
/// where the advertised contract is `<account>.<tool>` (#73).
///
/// Returns `true` only if ALL of:
/// - `raw` contains no `.` (so sub-capability dotted tools like
///   `search.advanced_query` return `false` — they must remain valid bare).
/// - `raw` parses as a known `ToolName`.
/// - The resolved tool is NOT `UseAccount` / `ListAccounts` (infrastructure
///   tools are always addressed bare regardless of account mode).
#[must_use]
pub(crate) fn is_bare_simple_tool_name(raw: &str) -> bool {
    use std::str::FromStr;
    if raw.contains('.') {
        return false;
    }
    let Ok(tool) = rimap_core::tool::ToolName::from_str(raw) else {
        return false;
    };
    !matches!(
        tool,
        rimap_core::tool::ToolName::UseAccount | rimap_core::tool::ToolName::ListAccounts,
    )
}
```

Adapt the module-path of `ToolName::from_str` to whatever the existing code uses (grep `ToolName::from_str` in `tool_name.rs` for the current import pattern).

- [ ] **Step 4: Run tests — expect PASS**

Run: `cd /home/dave/src/rusty-imap-mcp-mcp-dispatch && cargo test -p rimap-server --lib mcp::tool_name::tests::is_bare_simple_tool_name`
Expected: 5 tests pass.

- [ ] **Step 5: Wire the guard into `call_tool`**

In `crates/rimap-server/src/mcp/server.rs::call_tool` (around line 215, after `split_tool_name` and `ToolName::from_str` have run but BEFORE the account-prefix dispatch logic):

```rust
        // Multi-account contract: bare simple tool names are only valid
        // in legacy single-account mode. In multi-account mode, clients
        // must use the advertised <account>.<tool> form. Sub-capability
        // dotted tools (e.g. search.advanced_query) and infrastructure
        // tools (use_account, list_accounts) remain valid bare forms
        // regardless. (#73)
        let accounts = self.registry.accounts();
        if !crate::mcp::tool_name::is_legacy_single_account(accounts)
            && crate::mcp::tool_name::is_bare_simple_tool_name(raw)
        {
            return Err(ErrorData::invalid_params(
                format!(
                    "tool name must be namespaced in multi-account mode: \
                     <account>.{raw}"
                ),
                None,
            ));
        }
```

Adjust the exact position in the dispatch body to match where `raw` is still in scope but before the account prefix is used for routing. `raw` is the original tool name the client sent (before `split_tool_name`).

- [ ] **Step 6: Write integration-style dispatch test**

Add to `crates/rimap-server/src/mcp/dispatch.rs` tests or `server.rs` tests (follow existing pattern — search for `dispatch_infrastructure` tests or `call_tool` tests):

```rust
    #[tokio::test]
    async fn call_tool_rejects_bare_name_in_multi_account_mode() {
        // Build a registry with TWO accounts — neither named "default".
        let server = build_server_with_accounts(&["work", "personal"]).await;

        let mut cx = test_request_context();
        let req = CallToolRequestParam {
            name: "send_email".into(),  // bare simple name — should reject
            arguments: serde_json::Map::new().into(),
        };

        let err = server.call_tool(req, cx).await.unwrap_err();
        // ErrorData::invalid_params maps to a specific ErrorCode — verify
        // the error message mentions namespacing.
        assert!(
            err.message.contains("namespaced"),
            "expected namespacing error, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn call_tool_accepts_sub_capability_dotted_in_multi_account_mode() {
        let server = build_server_with_accounts(&["work", "personal"]).await;
        let mut cx = test_request_context();
        let req = CallToolRequestParam {
            name: "search.advanced_query".into(),  // sub-capability — valid bare
            arguments: /* minimal valid search args */.into(),
        };

        // We don't assert success (the actual call may fail at registry
        // resolution or lower layers without a live IMAP); we assert the
        // error is NOT the namespacing error.
        match server.call_tool(req, cx).await {
            Err(err) if err.message.contains("namespaced") => {
                panic!("sub-capability wrongly rejected as needing namespace: {err:?}");
            }
            _ => {} // success or any other failure is fine
        }
    }

    #[tokio::test]
    async fn call_tool_accepts_bare_in_legacy_single_account_mode() {
        let server = build_server_with_accounts(&["default"]).await;  // legacy
        let mut cx = test_request_context();
        let req = CallToolRequestParam {
            name: "send_email".into(),
            arguments: serde_json::Map::new().into(),
        };

        match server.call_tool(req, cx).await {
            Err(err) if err.message.contains("namespaced") => {
                panic!("legacy mode should accept bare names: {err:?}");
            }
            _ => {}
        }
    }
```

The `build_server_with_accounts` and `test_request_context` helpers may need to be added to the test module if they don't exist — check `crates/rimap-server/src/mcp/dispatch.rs` tests for the existing fixture pattern (survey found `dispatch_infrastructure` tests constructing a mock `ImapMcpServer`). Mirror that.

If the existing test fixture doesn't support multiple accounts, simplify: unit-test the `is_bare_simple_tool_name` predicate (already covered in Step 1) and ADD a focused unit test that constructs a minimal `call_tool` input and just checks the error path without going through full dispatch — e.g., extract the guard into a pub(crate) helper and unit-test it directly.

- [ ] **Step 7: Run workspace tests + clippy**

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS and clean.

- [ ] **Step 8: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
git add crates/rimap-server/src/mcp/tool_name.rs crates/rimap-server/src/mcp/server.rs
# Plus any dispatch.rs test fixture additions
git commit -m "server: reject bare tool names in multi-account mode (#73)

call_tool now rejects bare simple tool names (e.g. 'send_email')
when the server is not in legacy single-account mode. The
advertised contract in multi-account deployments is
<account>.<tool>, and clients that hardcode bare names from a
prior session would otherwise silently target whatever the session
default account is.

Sub-capability dotted tools (search.advanced_query,
fetch_message.include_html) remain valid bare forms — the dot is
part of the tool name, not an account prefix. Infrastructure tools
(use_account, list_accounts) also stay bare regardless of account
mode. The new is_bare_simple_tool_name helper encodes these
exceptions."
```

---

## Task 2: Emit `notifications/tools/list_changed` on `use_account` (#80)

**Issue:** #80 — MCP clients cache `list_tools` output; after `use_account` changes the session default, the EFFECTIVE tool set for bare / defaulted calls changes. An explicit notification keeps clients in sync.

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs` (emit after successful `UseAccount` dispatch).

### Approach

`call_tool` already owns the `context: RequestContext<RoleServer>` which exposes `context.peer` — the rmcp handle used to send notifications. After the `UseAccount` tool returns successfully, call `context.peer.notify_tool_list_changed(...).await` and log any transport failure at `warn!` (do NOT convert to a tool error — the `use_account` call succeeded; failing to notify is a best-effort signal, not a correctness issue).

This keeps `handle_use_account`'s signature pure — the handler knows nothing about rmcp or notifications.

- [ ] **Step 1: Inspect rmcp's notification signature**

Verify the exact method on `Peer<RoleServer>`:

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
grep -rn "notify_tool_list_changed\|ToolListChangedNotification" ~/.cargo/registry/src/index.crates.io-*/rmcp-*/src/ | head -5
```

Expected: a method like `pub async fn notify_tool_list_changed(&self, params: ToolListChangedNotification) -> Result<(), _>` or (more likely) `pub async fn notify_tool_list_changed(&self) -> Result<(), _>` with an empty-params convenience.

If the signature takes a `ToolListChangedNotification` struct, construct it with `Default::default()` or whatever shape matches the rmcp-provided defaults.

- [ ] **Step 2: Wire the emission into `call_tool`'s `UseAccount` arm**

In `crates/rimap-server/src/mcp/server.rs`, find the dispatch match arm for `ToolName::UseAccount` (or wherever `handle_use_account` is invoked). Current shape:

```rust
    ToolName::UseAccount => {
        let input = parse_input(args)?;
        handle_use_account(&self.registry, input).await?
    }
```

Change to:

```rust
    ToolName::UseAccount => {
        let input = parse_input(args)?;
        let response = handle_use_account(&self.registry, input).await?;
        // Notify subscribed clients that the EFFECTIVE tool list for bare
        // / defaulted calls has changed (session default account flipped).
        // Best-effort: transport failures here do not fail the tool call.
        // (#80)
        if let Err(e) = context
            .peer
            .notify_tool_list_changed(Default::default())
            .await
        {
            tracing::warn!(
                error = %e,
                "failed to emit notifications/tools/list_changed after use_account",
            );
        }
        response
    }
```

Adapt the exact method signature and arg shape to what rmcp 1.4.0 exposes. If `notify_tool_list_changed` takes no arguments, drop `Default::default()`.

- [ ] **Step 3: Write a test for the notification emission**

Testing rmcp notification emission typically requires a fake `Peer` that captures sent notifications. Search the codebase for any existing test infrastructure:

```bash
grep -rn "fake_peer\|mock_peer\|FakeTransport\|TestTransport\|ServerHandler" crates/rimap-server/src/ crates/rimap-server/tests/
```

If a fixture exists, use it. The test shape:

```rust
    #[tokio::test]
    async fn use_account_emits_tools_list_changed() {
        let (server, peer_recorder) = build_server_with_recorder(&["work", "personal"]).await;
        let cx = test_request_context_with_peer(&peer_recorder);

        let req = CallToolRequestParam {
            name: "use_account".into(),
            arguments: serde_json::json!({"account": "personal"}).as_object().unwrap().clone().into(),
        };

        server.call_tool(req, cx).await.unwrap();

        let notifications = peer_recorder.captured();
        assert_eq!(
            notifications.iter().filter(|n| n.method == "notifications/tools/list_changed").count(),
            1,
            "expected exactly one list_changed notification; got: {notifications:?}",
        );
    }
```

If no such fixture exists and building one is scope creep for this task, SKIP the full test and instead add a unit test that verifies the dispatch code structure: extract the emission into a helper `pub(crate) async fn emit_tool_list_changed(peer: &Peer<RoleServer>)` and unit-test that the helper doesn't panic on a failing peer (constructed to return an error).

At minimum, add a REGRESSION comment or `#[doc]` test noting the expected behavior so reviewers see the contract.

- [ ] **Step 4: Run workspace tests + clippy**

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS and clean.

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
git add crates/rimap-server/src/mcp/server.rs
# Plus any test infrastructure additions
git commit -m "server: emit tools/list_changed on successful use_account (#80)

call_tool's UseAccount arm now emits
notifications/tools/list_changed via context.peer after
handle_use_account returns successfully. MCP clients that cached
the list_tools output get a prompt to refresh — the effective
tool set for bare / defaulted calls changed because the session
default account flipped.

Transport failures on the notification are logged at warn! and do
not fail the tool call: the use_account operation itself
succeeded, and the notification is a best-effort sync signal."
```

---

## Task 3: Final verification + PR

- [ ] **Step 1: Run the full verification pipeline**

```bash
cd /home/dave/src/rusty-imap-mcp-mcp-dispatch
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check advisories bans licenses sources
typos
```

All five must pass.

- [ ] **Step 2: Push + open PR**

Branch: `feat/mcp-dispatch-hygiene`. Target: `main`. PR body references `Closes #73`, `Closes #80`.

PR body should note that this is the FINAL sub-group of the roadmap. After this merges, Tier 1 of the open-issues roadmap is complete; Tier 2 (#75, #79, #81, #93, #94) remains as a future sweep.

- [ ] **Step 3: After merge, close out the roadmap spec**

Edit `docs/superpowers/specs/2026-04-19-open-issues-roadmap-design.md` — either mark all six Tier 1 sub-groups as ✅ done, or delete the Tier 1 inventory block (if the roadmap is intended as a running list of open work).
