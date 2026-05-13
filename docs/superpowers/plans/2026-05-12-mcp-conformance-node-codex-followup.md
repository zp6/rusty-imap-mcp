# Phase 2 — Codex Adversarial Review Follow-up Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the two findings from Codex's branch adversarial review on PR #271, before merge:
1. **[high]** SDK schema regression test only validates 2 infrastructure tools; account-scoped tool schemas (22 of them) never see SDK Zod validation.
2. **[medium]** `pnpm-lock.yaml` was generated with `settings.autoInstallPeers: true` despite the `.npmrc` claiming `auto-install-peers=false`. `zod` (the SDK's strict-validation peer) is not directly pinned, so the install surface isn't fully expressed in the manifest.

**Architecture:** Add a test-support CLI subcommand `dump-tool-catalog` to `rusty-imap-mcp` that emits the static `TOOL_DEFS` map as line-delimited JSON. Phase 2 invokes this subcommand and validates each tool definition through the SDK's exported `ToolSchema` (Zod). This catches Zod-strict shape failures on the full 24-tool catalog without standing up an IMAP server. Separately, pin `zod` as a direct devDependency and regenerate the lockfile under the project's `.npmrc`.

**Tech Stack:** Same as parent plan (TypeScript 6.0.3, Vitest 4.1.6, `@modelcontextprotocol/sdk` 1.29.0, pnpm 11.1.1). The new CLI subcommand uses existing clap infrastructure in `rimap-server`.

**Spec reference:** [`docs/superpowers/specs/2026-05-12-mcp-conformance-node-design.md`](../specs/2026-05-12-mcp-conformance-node-design.md)
**Parent plan:** [`2026-05-12-mcp-conformance-node.md`](./2026-05-12-mcp-conformance-node.md)
**Branch:** `test/mcp-conformance-node` (this work appends to it)
**Codex review output:** captured in PR #271 description (or the chat log preceding this plan).

---

## File map

**Create:**
- `tests/mcp-conformance/src/catalog-dump-harness.ts` — invokes `rusty-imap-mcp dump-tool-catalog` and parses its line-delimited JSON stdout

**Modify:**
- `crates/rimap-server/src/cli/mod.rs` — add a `#[cfg(feature = "test-support")]` `DumpToolCatalog` subcommand variant
- `crates/rimap-server/src/main.rs` — wire the new subcommand to its handler
- `crates/rimap-server/src/cli/dump_tool_catalog.rs` — new file (or inline in `dry_run.rs`-style sibling) implementing the dump
- `crates/rimap-server/tests/dump_tool_catalog.rs` — new Rust integration test (TDD)
- `tests/mcp-conformance/package.json` — add `zod` as exact devDependency
- `tests/mcp-conformance/pnpm-lock.yaml` — regenerated under project `.npmrc`
- `tests/mcp-conformance/src/wire.test.ts` — add `wire_all_advertised_tools_pass_sdk_schema (CLI dump)` test
- `crates/rimap-server/src/mcp/tool_catalog.rs` — make `TOOL_DEFS` accessible to the new subcommand handler (it's `pub(super)` today; may need to widen to `pub(crate)`)

---

## Resolved versions (at plan-write time, 2026-05-12)

| dep | version | source | publish |
|---|---|---|---|
| `zod` | `<read from node_modules/zod/package.json during Task 1>` | indirect peer of `@modelcontextprotocol/sdk` 1.29.0 | published well outside the 24h cooldown (zod 3.x has been stable for months) |

The exact zod version is determined at Task 1's first step by reading the currently-installed copy. The version is committed exactly. If the SDK's peer dependency range allows multiple zod versions, we pin the one currently in the lockfile — i.e., we ratify the version pnpm chose, rather than picking a new one.

---

### Task 1: Pin `zod` as a direct devDependency and regenerate the lockfile

**Why this is its own task:** It's mechanical and unblocked. Doing it first means the lockfile change isn't tangled with the rimap-server / Node-test work in Tasks 2-3.

**Files:**
- Modify: `tests/mcp-conformance/package.json`
- Modify: `tests/mcp-conformance/pnpm-lock.yaml`

- [ ] **Step 1: Find the zod version pnpm currently resolved**

```bash
cd /Users/dave/src/rusty-imap-mcp/tests/mcp-conformance
node -e 'console.log(require("zod/package.json").version)'
```

Expected: prints something like `3.23.8` (or whatever 3.x version is current). Record this value — call it `<ZOD_VERSION>` for the next step.

- [ ] **Step 2: Add `zod` to `devDependencies` in `package.json`**

Edit `tests/mcp-conformance/package.json`. Inside the `devDependencies` object, add:

```jsonc
{
  "devDependencies": {
    "@modelcontextprotocol/sdk": "1.29.0",
    "@types/node": "25.7.0",
    "oxfmt": "0.49.0",
    "oxlint": "1.64.0",
    "typescript": "6.0.3",
    "vitest": "4.1.6",
    "zod": "<ZOD_VERSION>"
  }
}
```

Preserve alphabetical ordering. Exact pin (no `^`/`~`). Keep all other fields unchanged.

- [ ] **Step 3: Regenerate the lockfile under the project `.npmrc`**

```bash
rm -rf tests/mcp-conformance/node_modules tests/mcp-conformance/pnpm-lock.yaml
cd tests/mcp-conformance
pnpm install --config=tests/mcp-conformance/.npmrc
```

Actually, pnpm reads `.npmrc` from the project directory automatically when invoked with cwd inside the project. The flag-explicit form above is redundant — `cd tests/mcp-conformance && pnpm install` is sufficient. Use whichever works.

- [ ] **Step 4: Verify the lockfile records `autoInstallPeers: false`**

```bash
head -10 tests/mcp-conformance/pnpm-lock.yaml
```

Expected: the `settings:` block shows `autoInstallPeers: false`. If it still shows `true`, the `.npmrc` isn't being applied — investigate before continuing. Likely culprits:
- A global `~/.npmrc` overriding `auto-install-peers=true`.
- pnpm running from outside the project root.

If you have to override globals, regenerate with:

```bash
cd tests/mcp-conformance
NPM_CONFIG_AUTO_INSTALL_PEERS=false pnpm install
```

- [ ] **Step 5: Verify `pnpm install --frozen-lockfile` is now reproducible**

```bash
cd tests/mcp-conformance
pnpm install --frozen-lockfile
```

Expected: "Already up to date" or "Lockfile is up to date" with no changes.

- [ ] **Step 6: Verify the full test suite still passes**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo build -p rimap-server --bin rusty-imap-mcp --features test-support --locked
cd tests/mcp-conformance
RUSTY_IMAP_MCP_BIN=$(pwd)/../../target/debug/rusty-imap-mcp pnpm test
pnpm lint
pnpm format:check
```

Expected: 23 tests pass, lint clean, format clean.

- [ ] **Step 7: Commit**

```bash
git add tests/mcp-conformance/package.json tests/mcp-conformance/pnpm-lock.yaml
git commit -m "test(mcp): pin zod directly and regenerate lockfile under .npmrc (#264)"
```

---

### Task 2: Add `dump-tool-catalog` test-support CLI subcommand (Rust, TDD)

**Why this design:** The Codex finding cites that account-scoped tool schemas (22 tools) are never validated by Phase 2 because `accounts = []` means `list_tools` advertises only the 2 infrastructure tools. The cleanest fix that doesn't require standing up a real IMAP server or mocking the registry boot path is a CLI subcommand on `rusty-imap-mcp` that dumps the static `TOOL_DEFS` map. The subcommand is `#[cfg(feature = "test-support")]` so it does not exist in production builds. Per the spec §4.7 constraint (test-support code MUST NOT alter MCP wire-protocol behavior), this is allowed: a CLI subcommand is not an MCP method.

**Files:**
- Create: `crates/rimap-server/src/cli/dump_tool_catalog.rs`
- Create: `crates/rimap-server/tests/dump_tool_catalog.rs`
- Modify: `crates/rimap-server/src/cli/mod.rs` (add `DumpToolCatalog` variant)
- Modify: `crates/rimap-server/src/main.rs` (dispatch the new subcommand)
- Modify: `crates/rimap-server/src/mcp/tool_catalog.rs` (widen `TOOL_DEFS` visibility from `pub(super)` to `pub(crate)`)

- [ ] **Step 1: Read the existing CLI structure**

```bash
cd /Users/dave/src/rusty-imap-mcp
cat crates/rimap-server/src/cli/mod.rs
```

Determine the existing clap structure (likely an enum of subcommands under a `clap::Subcommand` derive). Note the patterns for:
- `#[cfg(feature = "test-support")]` gating of CLI flags
- Subcommand variant naming
- Match-arm dispatch in `main.rs`

- [ ] **Step 2: Widen `TOOL_DEFS` visibility**

In `crates/rimap-server/src/mcp/tool_catalog.rs`, change:

```rust
pub(super) static TOOL_DEFS: ...
```

to:

```rust
pub(crate) static TOOL_DEFS: ...
```

This allows the new `cli::dump_tool_catalog` module to access it.

- [ ] **Step 3: Write the failing Rust integration test at `crates/rimap-server/tests/dump_tool_catalog.rs`**

```rust
//! Integration test for the `dump-tool-catalog` test-support
//! subcommand (issue #264, Phase 2 Codex follow-up).
//!
//! Verifies the CLI subcommand emits the full TOOL_DEFS catalog as
//! line-delimited JSON, with each entry's `inputSchema.type` equal
//! to `"object"`. The Node conformance harness consumes this output
//! to drive every tool's schema through the SDK's Zod Tool validator.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use assert_cmd::cargo::cargo_bin;
use serde_json::Value;
use std::process::Command;

#[test]
fn dump_tool_catalog_emits_object_schemas() {
    let output = Command::new(cargo_bin("rusty-imap-mcp"))
        .arg("dump-tool-catalog")
        .output()
        .expect("spawn rusty-imap-mcp dump-tool-catalog");
    assert!(
        output.status.success(),
        "dump-tool-catalog must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    // 24 ToolName variants minus 2 sub-capabilities (SearchAdvanced,
    // FetchMessageHtml) that share schemas with their parents = 22 defs.
    assert_eq!(
        lines.len(),
        22,
        "expected 22 tool defs (24 ToolName variants - 2 sub-capabilities); got {}",
        lines.len(),
    );

    for line in lines {
        let value: Value = serde_json::from_str(line).expect("each line is JSON");
        let name = value["name"].as_str().expect("name is string");
        let schema = &value["inputSchema"];
        assert!(
            schema.is_object(),
            "tool {name}: inputSchema must be an object, got {schema}",
        );
        assert_eq!(
            schema["type"],
            Value::String("object".to_string()),
            "tool {name}: inputSchema.type must be \"object\", got {}",
            schema["type"],
        );
    }
}
```

- [ ] **Step 4: Run the test, see it fail**

```bash
cargo nextest run -p rimap-server --test dump_tool_catalog --features test-support
```

Expected: failure — the subcommand doesn't exist yet, so clap rejects `dump-tool-catalog`.

- [ ] **Step 5: Add the `DumpToolCatalog` subcommand variant in `crates/rimap-server/src/cli/mod.rs`**

Locate the existing `Subcommand` enum (the one that has `Login`, `Audit`, etc.) and add a new variant inside a `#[cfg(feature = "test-support")]` block, e.g.:

```rust
#[cfg(feature = "test-support")]
/// Dump the static MCP tool catalog as line-delimited JSON.
/// Used by the Phase 2 Node conformance harness to validate every
/// tool's inputSchema against the SDK's Zod Tool definition without
/// requiring a configured account or live IMAP server.
DumpToolCatalog,
```

Match the surrounding style (doc comments, attribute placement).

- [ ] **Step 6: Implement the handler at `crates/rimap-server/src/cli/dump_tool_catalog.rs`**

```rust
//! `dump-tool-catalog` test-support CLI subcommand. Emits the static
//! MCP tool catalog as line-delimited JSON to stdout. Used by the
//! Phase 2 Node conformance harness (issue #264) to validate every
//! tool's `inputSchema` through the SDK's Zod Tool definition
//! without standing up a configured account or live IMAP server.

use std::io::Write;

use rimap_core::tool::ToolName;

use crate::mcp::tool_catalog::TOOL_DEFS;

/// Print each entry of the static `TOOL_DEFS` map as one line of
/// JSON to the given writer. Iteration order follows `ToolName::all()`
/// so the output is stable across runs.
///
/// # Errors
///
/// Returns the underlying I/O error if the writer fails or the
/// serializer cannot encode an entry. The static catalog is built
/// from `Tool::new`, which always produces a JSON-serializable
/// object, so the serializer should not fail in practice.
pub fn dump_tool_catalog<W: Write>(writer: &mut W) -> std::io::Result<()> {
    for tn in ToolName::all() {
        let Some(def) = TOOL_DEFS.get(&tn) else {
            continue;
        };
        serde_json::to_writer(&mut *writer, def)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
```

- [ ] **Step 7: Wire the handler into `crates/rimap-server/src/main.rs`**

Locate the existing match arm for CLI subcommand dispatch. Add a new arm for `DumpToolCatalog`, gated by `#[cfg(feature = "test-support")]`. The arm calls `dump_tool_catalog(&mut std::io::stdout().lock())` and exits 0 on success.

Approximate shape (adjust to match the existing pattern):

```rust
#[cfg(feature = "test-support")]
Some(Subcommand::DumpToolCatalog) => {
    crate::cli::dump_tool_catalog::dump_tool_catalog(&mut std::io::stdout().lock())?;
    return Ok(std::process::ExitCode::SUCCESS);
}
```

If `main.rs` already returns `ExitCode` from a match expression, adapt accordingly.

- [ ] **Step 8: Add `mod dump_tool_catalog;` to `crates/rimap-server/src/cli/mod.rs`**

Under `#[cfg(feature = "test-support")]`:

```rust
#[cfg(feature = "test-support")]
pub mod dump_tool_catalog;
```

(Match the existing pattern — if `dry_run.rs` uses `pub mod dry_run;` here, follow suit.)

- [ ] **Step 9: Run the test, verify it passes**

```bash
cargo nextest run -p rimap-server --test dump_tool_catalog --features test-support
```

Expected: PASS. 1 test.

- [ ] **Step 10: Run `cargo clippy` and `cargo fmt`**

```bash
just lint
just fmt
```

Expected: 0 warnings, no formatting changes.

- [ ] **Step 11: Run the full Rust suite to confirm no regressions**

```bash
cargo nextest run -p rimap-server --features test-support
```

Expected: all rimap-server tests pass.

- [ ] **Step 12: Commit**

```bash
git add crates/rimap-server/src/cli/mod.rs \
        crates/rimap-server/src/cli/dump_tool_catalog.rs \
        crates/rimap-server/src/main.rs \
        crates/rimap-server/src/mcp/tool_catalog.rs \
        crates/rimap-server/tests/dump_tool_catalog.rs
git commit -m "test(mcp): add dump-tool-catalog test-support subcommand (#264)"
```

---

### Task 3: Add Node-side SDK Zod validation of the dumped catalog

**Files:**
- Create: `tests/mcp-conformance/src/catalog-dump-harness.ts`
- Modify: `tests/mcp-conformance/src/wire.test.ts`

- [ ] **Step 1: Verify the SDK exports a Tool Zod schema we can use directly**

```bash
cd /Users/dave/src/rusty-imap-mcp/tests/mcp-conformance
grep -n "export const ToolSchema\|export.*ToolSchema" node_modules/@modelcontextprotocol/sdk/dist/esm/types.d.ts
node -e 'import("@modelcontextprotocol/sdk/types.js").then(m => console.log(typeof m.ToolSchema, m.ToolSchema?._def?.typeName));'
```

Expected: prints `object ZodObject` (or similar). If `ToolSchema` is not exported under that exact name, look for `ListToolsResultSchema.shape.tools.element` or similar. Record the exact import path and symbol name to use.

If the SDK does not expose a Tool Zod schema directly, fall back to calling the SDK's Zod-aware client on synthetic input — but this is unlikely; the SDK exposes its Zod schemas as public types.

- [ ] **Step 2: Implement `tests/mcp-conformance/src/catalog-dump-harness.ts`**

```ts
import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

async function resolveBinaryPath(): Promise<string> {
  const envPath = process.env["RUSTY_IMAP_MCP_BIN"];
  if (envPath !== undefined && envPath !== "") {
    await access(envPath);
    return envPath;
  }
  const here = dirname(fileURLToPath(import.meta.url));
  const fallback = resolve(here, "..", "..", "..", "target", "debug", "rusty-imap-mcp");
  await access(fallback);
  return fallback;
}

/**
 * Invokes `rusty-imap-mcp dump-tool-catalog` and returns the parsed
 * line-delimited JSON tool definitions.
 *
 * The binary must have been built with `--features test-support`;
 * a non-test-support build does not have the subcommand and clap
 * exits non-zero before producing output.
 */
export async function dumpToolCatalog(): Promise<unknown[]> {
  const binPath = await resolveBinaryPath();
  return await new Promise<unknown[]>((resolveResult, rejectResult) => {
    const child = spawn(binPath, ["dump-tool-catalog"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errChunks.push(chunk));
    child.on("error", (err) => rejectResult(err));
    child.on("exit", (code) => {
      if (code !== 0) {
        rejectResult(
          new Error(
            `dump-tool-catalog exited ${code}; stderr: ${Buffer.concat(errChunks).toString("utf8")}`,
          ),
        );
        return;
      }
      try {
        const stdout = Buffer.concat(chunks).toString("utf8");
        const lines = stdout.split("\n").filter((l) => l.length > 0);
        const parsed = lines.map((l) => JSON.parse(l) as unknown);
        resolveResult(parsed);
      } catch (err) {
        rejectResult(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}
```

- [ ] **Step 3: Append the new test to `tests/mcp-conformance/src/wire.test.ts`**

Add at the top of the file with the existing imports:

```ts
import { ToolSchema } from "@modelcontextprotocol/sdk/types.js";

import { dumpToolCatalog } from "./catalog-dump-harness.js";
```

(Use whatever symbol Step 1 verified the SDK exports. Adjust to that exact name.)

Add a new describe block at the end of the file:

```ts
describe("wire conformance (CLI catalog dump)", () => {
  it("wire_all_advertised_tools_pass_sdk_schema (CLI dump) — regression net for issue #264 strict-client gap", async () => {
    // The SDK harness only sees infrastructure tools when the server
    // is spawned with accounts=[]. This test invokes the test-support
    // `dump-tool-catalog` subcommand on the binary directly and
    // validates every TOOL_DEFS entry against the SDK's Zod Tool
    // schema. Catches malformed account-scoped tool schemas that the
    // wire-path SDK tests cannot reach without a live IMAP server.
    const entries = await dumpToolCatalog();
    expect(entries.length, "dump must contain 22 tool defs (24 ToolName variants - 2 sub-capabilities)").toBe(22);

    for (const entry of entries) {
      const result = ToolSchema.safeParse(entry);
      if (!result.success) {
        const name = (entry as { name?: string })?.name ?? "<unknown>";
        throw new Error(
          `SDK ToolSchema rejected tool ${name}: ${result.error.message}`,
        );
      }
    }
  });
});
```

- [ ] **Step 4: Run the new test, verify it passes**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo build -p rimap-server --bin rusty-imap-mcp --features test-support --locked
cd tests/mcp-conformance
RUSTY_IMAP_MCP_BIN=$(pwd)/../../target/debug/rusty-imap-mcp pnpm test src/wire.test.ts
```

Expected: 10 wire tests pass total (was 9; +1 new). Full suite (`pnpm test`): 24 total (was 23; +1 new).

If `ToolSchema.safeParse(entry)` fails, that's the test catching real Zod drift — investigate the specific tool's inputSchema in `tools.rs` / `tool_catalog.rs`.

- [ ] **Step 5: Run `pnpm lint` and `pnpm format:check`**

Expected: 0 errors. Fix any formatting drift with `pnpm exec oxfmt src/catalog-dump-harness.ts`.

- [ ] **Step 6: Commit**

```bash
git add tests/mcp-conformance/src/catalog-dump-harness.ts \
        tests/mcp-conformance/src/wire.test.ts
git commit -m "test(mcp): validate all 22 advertised tools through SDK Zod (#264)"
```

---

### Task 4: Local verification and PR update

**Files:**
- No source files modified.

- [ ] **Step 1: Run `just ci` cold from clean state**

```bash
cd /Users/dave/src/rusty-imap-mcp
cargo clean -p rimap-server
rm -rf tests/mcp-conformance/node_modules
just ci
```

Expected: all targets pass. Cold runtime should still be in the 5-7 minute range.

The Rust test count should grow by 1 (`dump_tool_catalog_emits_object_schemas`). The Node test count should grow by 1 (`wire_all_advertised_tools_pass_sdk_schema`).

- [ ] **Step 2: Push**

```bash
git push origin test/mcp-conformance-node
```

- [ ] **Step 3: Add a comment to PR #271 summarizing the follow-up**

```bash
gh pr comment 271 --body "$(cat <<'EOF'
Addresses both Codex adversarial-review findings on this branch:

- **[high]** Account-scoped schema coverage: new `dump-tool-catalog` test-support CLI subcommand emits all 22 advertised tool definitions as line-delimited JSON. New conformance test `wire_all_advertised_tools_pass_sdk_schema (CLI dump)` validates each through the SDK's exported `ToolSchema` (Zod). Catches Zod-strict shape failures on the full catalog without standing up a real IMAP server.
- **[medium]** Pinned `zod` as an exact direct devDependency in `package.json` and regenerated `pnpm-lock.yaml` under the project `.npmrc` so the lockfile records `settings.autoInstallPeers: false`. The install surface is now fully expressed in the manifest.

Three new commits on the branch. `just ci` green from cold cache after the changes.
EOF
)"
```

- [ ] **Step 4: Verify CI is green on the new commits**

```bash
gh pr checks 271 --watch
```

Expected: all 11 checks pass (existing 10 + the `mcp-conformance (Node)` job, which now also runs the new test).

---

## Self-review

**Codex finding coverage:**

| Finding | Severity | Addressed in |
|---|---|---|
| SDK schema regression test only covers infrastructure tools | high | Task 2 (subcommand) + Task 3 (Node-side validation) |
| Lockfile generated with peer auto-install enabled; `zod` not directly pinned | medium | Task 1 |

**Placeholder scan:** the only deliberate placeholder is `<ZOD_VERSION>` in Task 1 Step 2, which is filled in by reading `node_modules/zod/package.json` in Step 1. That's the same pattern Task 2 in the parent plan used for tool versions.

**Type consistency:** `dumpToolCatalog` returns `unknown[]`, the test parses each via `ToolSchema.safeParse`. The SDK's exact symbol name for the Tool Zod schema is confirmed in Task 3 Step 1 before use; if the SDK at this version uses a different name (e.g., `Tool` vs `ToolSchema`), adjust at that step.

**Scope check:** four tasks, each independently committable. No task touches more than one of (Rust, Node, package metadata). Total expected new commits on the branch: 3 (Task 4 produces no commit beyond what the previous tasks add).

**Risk: ToolSchema not directly exported.** If Task 3 Step 1 finds that the SDK doesn't expose `ToolSchema` as a top-level export, the fallback is `ListToolsResultSchema.shape.tools.element`. If even that's inaccessible, we can construct a minimal-viable Zod schema manually that matches the SDK's published Tool spec (object with `name`, `description?`, `inputSchema: {type: "object", ...}`). The plan should not pre-commit to the fallback; Step 1 verifies first, then chooses.
