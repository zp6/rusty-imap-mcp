# MCP Node Strict-Client Conformance Harness — Design

**Status:** Draft 2026-05-12
**Scope:** Phase 2 of 4 (issue #264) — a Node + TypeScript test suite
that spawns `rusty-imap-mcp` via the official
`@modelcontextprotocol/sdk` (Zod-validated) and asserts wire conformance
against the SDK's stricter schemas. Phase 1 (#263, landed) covers
spec JSON Schema validation; Phases 3 (#265) and 4 (#266) cover
behavioral IMAP conformance and protocol fuzzing respectively and are
out of scope here.

## 1. Motivation

Phase 1 catches wire-shape regressions against the MCP spec's official
JSON Schemas (permissive). It does not catch the class of bug where
the spec's JSON Schema accepts a payload but the official TypeScript
SDK's Zod schemas reject it. Real-world clients deriving from
`@modelcontextprotocol/sdk` (`bobshell`, IBM's Bob desktop in some
modes, and likely others) enforce Zod, not raw spec JSON Schema.

The `fix/tool-input-schema-object-type` bug is the canonical example:
the MCP spec's `Tool` schema permits a bare `"inputSchema": {}`, but
the SDK's Zod requires `type: "object"`. Phase 1's validator passes;
real strict clients reject. Only running through the actual SDK
catches the divergence — that is the unique job of Phase 2.

This phase eliminates the SDK-strict bug class from regression-testing
without depending on Phase 1's coverage or duplicating it.

## 2. Goals & Non-Goals

### Goals

- Build a Node + TypeScript test suite that uses the official
  `@modelcontextprotocol/sdk` `Client` + `StdioClientTransport` to
  spawn the production `rusty-imap-mcp` binary and drive a fixed
  JSON-RPC sequence.
- Mirror all nine Phase 1 test cases through the SDK's typed surface,
  with two harness flavors — SDK-driven for the cases Zod adds value
  to, raw-stdio for the three cases the SDK abstracts away.
- Permanent regression nets for both cited bugs **via SDK enforcement**
  (Zod throw) and **belt-and-suspenders explicit asserts** (so a future
  SDK relaxation doesn't silently void the net):
  - `initialize.result.capabilities.tools` is present after `connect()`.
  - Every `listTools().tools[*].inputSchema.type === "object"`.
- Run on every PR with the same gating treatment as the Rust
  conformance harness.
- Supply-chain hygiene at the level the global standards require:
  exact-pinned deps, postinstall blocked, 24h release cooldown,
  SHA-pinned actions, `pnpm install --frozen-lockfile`.

### Non-Goals

- IMAP behavior (Phase 3 / #265).
- Coverage-guided fuzzing or property tests (Phase 4 / #266).
- Replacement of Phase 1 — both run; they catch different things. The
  Rust harness validates against the spec's permissive JSON Schema;
  the Node harness validates against the SDK's stricter Zod. Together
  they triangulate.
- Custom JS reimplementation of `bobshell`'s exact validation. We use
  the official SDK as a proxy; `bobshell` appears to derive from the
  same SDK.
- Multi-OS Node CI. Ubuntu-only, matching the existing `test (stable)`
  job. macOS-specific Node-runtime regressions are an accepted gap.
- Tool-output Zod validation. The SDK's `callTool()` validates the
  envelope; per-tool result shape is content-pipeline territory.

## 3. Architecture

### 3.1 Directory layout

A top-level `tests/mcp-conformance/` directory holds an isolated
TypeScript + Vitest project. It is **not** part of any cargo
workspace; cargo and pnpm coexist without cross-tool surprises
because their roots don't overlap.

```
tests/mcp-conformance/
├── package.json          # name, scripts, exact-pinned devDeps, engines.node, packageManager
├── pnpm-lock.yaml        # committed; CI verifies with `pnpm install --frozen-lockfile`
├── tsconfig.json         # strict per global CLAUDE.md
├── vitest.config.ts      # test discovery under src/; hookTimeout sized for binary spawn
├── .npmrc                # ignore-scripts, minimum-release-age, strict-peer-dependencies
├── .gitignore            # node_modules/, coverage/, *.log
├── README.md             # how to run locally; relationship to Phase 1
└── src/
    ├── sdk-harness.ts    # Client + StdioClientTransport wrapper
    ├── raw-harness.ts    # child_process.spawn with manual line-delimited JSON-RPC
    ├── config.ts         # buildConfigToml(tempdir) — mirrors Phase 1's inline TOML
    └── wire.test.ts      # 9 test cases mirroring mcp_wire_conformance.rs
```

`Cargo.toml` workspace excludes are unnecessary because `tests/` is
already outside `crates/`. The repo-root `.gitignore` gains
`tests/mcp-conformance/node_modules/` and `tests/mcp-conformance/coverage/`.

### 3.2 Two harness flavors

Phase 1's Rust `Harness` exposes both high-level helpers (initialize,
tools/list) and a raw `request()` for arbitrary methods. Phase 2
splits these into two TypeScript modules because the SDK's `Client`
deliberately hides several of the operations Phase 1 exercises:

- **`sdk-harness.ts`** — wraps the SDK's `Client` and
  `StdioClientTransport`. Used by the six cases where Zod adds value
  over Phase 1.
- **`raw-harness.ts`** — `child_process.spawn` with stdin/stdout
  piping and a line-delimited JSON-RPC reader/writer. Used by the
  three cases that need access to the raw transport (no-response
  assertion, arbitrary methods, child exit status). Modeled
  line-for-line on Phase 1's Rust `Harness` so cross-language drift is
  catchable in code review.

Both share `buildConfigToml(tempdir)` from `config.ts`.

### 3.3 SDK-harness shape

```ts
// src/sdk-harness.ts (sketch)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export interface SdkHandles {
  client: Client;
  transport: StdioClientTransport;
  tempdir: string;
  close(): Promise<void>;
}

export async function spawnSdk(binPath: string): Promise<SdkHandles> {
  const tempdir = await mkdtemp(join(tmpdir(), "rusty-imap-mcp-conformance-"));
  const configPath = join(tempdir, "config.toml");
  await writeFile(configPath, buildConfigToml(tempdir), "utf8");

  const transport = new StdioClientTransport({
    command: binPath,
    args: ["--config", configPath, "--allow-empty-accounts"],
    stderr: "ignore",
  });
  const client = new Client(
    { name: "rusty-imap-mcp-conformance-harness-node", version: pkgVersion() },
    { capabilities: {} },
  );
  await client.connect(transport);
  return { client, transport, tempdir, close: async () => { await client.close(); } };
}
```

Per-test isolation via `beforeEach`/`afterEach` — each `it` owns its
own harness so a failing test cannot poison another's stdin.

### 3.4 Raw-harness shape

```ts
// src/raw-harness.ts (sketch)
export interface RawHandles {
  child: ChildProcessWithoutNullStreams;
  request(method: string, params: unknown): Promise<JsonRpcResponse>;
  notify(method: string, params: unknown): Promise<void>;
  assertNoResponseWithin(ms: number): Promise<void>;
  shutdownAndWait(): Promise<number>;       // exit code, throws on non-zero / timeout
}
```

Line-delimited reader; 2 s per-request timeout; 5 s shutdown timeout —
identical envelope to Phase 1's Rust `Harness`. Errors surface with
the captured stderr (drained from the child) attached for diagnostics.

### 3.5 Test sequence (9 cases mirroring Phase 1)

| # | Phase 1 test                                                   | Phase 2 implementation                                                                                                                                                                                                                                                | Harness |
|---|----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| 1 | `wire_smoke_initialize_returns_valid_envelope`                 | `spawnSdk()` succeeds. `Client.connect()` validates `InitializeResult` through Zod; success is the assertion. Belt-and-suspenders: re-assert `serverInfo` present.                                                                                                     | SDK     |
| 2 | `wire_initialize_advertises_tools_capability`                  | `client.getServerCapabilities()?.tools !== undefined` — regression net for #261.                                                                                                                                                                                       | SDK     |
| 3 | `wire_protocol_version_negotiation_matches_vendored_schema`    | Four-way drift check: SDK's `LATEST_PROTOCOL_VERSION` constant === negotiated `protocolVersion` from the server === literal `"2025-11-25"` in the test. Phase 1's three-way check (rmcp, fixture, constant) plus the SDK's constant.                                   | SDK     |
| 4 | `wire_initialized_notification_elicits_no_response`            | The SDK sends `notifications/initialized` for us during `connect()`. To assert no response, drop to Raw: send `initialize` → send `notifications/initialized` → wait 200 ms for no stdout line.                                                                        | Raw     |
| 5 | `wire_tools_list_returns_object_schemas`                       | `await client.listTools()`. Zod throws if any tool's `inputSchema` is malformed — regression net for `fix/tool-input-schema-object-type`. Explicit asserts: `list_accounts`/`use_account` present; every tool's `inputSchema.type === "object"`.                       | SDK     |
| 6 | `wire_resources_list_is_empty_for_no_accounts`                 | `await client.listResources()`; Zod validates envelope; assert `.resources.length === 0`.                                                                                                                                                                              | SDK     |
| 7 | `wire_tools_call_unknown_tool_returns_error_envelope`          | `await expect(client.callTool({ name: "this_tool_does_not_exist", arguments: {} })).rejects.toThrow(McpError)` with `.code === -32602`.                                                                                                                                | SDK     |
| 8 | `wire_unknown_method_returns_minus_32601`                      | SDK's `Client` doesn't expose "send arbitrary method." Raw: handshake, then send `{"method":"rimap/no_such_method"}`; assert `error.code === -32601`.                                                                                                                  | Raw     |
| 9 | `wire_clean_eof_shutdown_exits_zero`                           | Need child `ExitStatus`, abstracted away by the SDK transport. Raw: spawn, handshake, close stdin, await child exit; assert `code === 0` within 5 s.                                                                                                                   | Raw     |

The three Raw cases (4, 8, 9) are partially redundant with Phase 1.
They stay because the "full mirror" decision is load-bearing for
catching Node-platform-specific differences (line buffering, EOL,
signal handling) that a Rust-only harness cannot surface.

## 4. Build, invocation, supply-chain hygiene

### 4.1 `justfile` target

```just
# Run the Node strict-client conformance suite (issue #264, Phase 2).
mcp-conformance-node:
    cargo build --bin rusty-imap-mcp --locked
    cd tests/mcp-conformance && pnpm install --frozen-lockfile
    cd tests/mcp-conformance && \
        RUSTY_IMAP_MCP_BIN="{{justfile_directory()}}/target/debug/rusty-imap-mcp" \
        pnpm test
```

Added to `just ci` for local-CI parity:

```just
ci: fmt-check lint test test-msrv deny mcp-conformance-node
```

Adding the target to `just ci` preserves the "if `just ci` passes
locally, CI will pass" promise from `AGENTS.md`, which is load-bearing
for the project's PR workflow. The cost is that Node ≥22 and pnpm ≥9
become hard prerequisites for `just ci`. The `setup` target's tool
list grows to install both; contributors who haven't run `setup`
since this lands will need to re-run it. Individual Rust targets
(`just lint`, `just test`, `just test-msrv`, `just deny`) remain
runnable without Node for contributors making Rust-only changes.

### 4.2 `package.json`

```jsonc
{
  "name": "rusty-imap-mcp-conformance",
  "private": true,
  "type": "module",
  "engines": { "node": ">=22.0.0", "pnpm": ">=9.0.0" },
  "packageManager": "pnpm@<exact-version>",
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit",
    "format:check": "oxfmt --check ."
  },
  "devDependencies": {
    "@modelcontextprotocol/sdk": "<exact>",
    "vitest": "<exact>",
    "typescript": "<exact>",
    "@types/node": "<exact>",
    "oxlint": "<exact>",
    "oxfmt": "<exact>"
  }
}
```

**Exact versions** (no `^`/`~`) per global CLAUDE.md and the issue.
Actual version strings are pinned during plan execution by reading
current stable from each package's registry page.

### 4.3 `.npmrc` (committed)

```ini
ignore-scripts=true
minimum-release-age=1440
auto-install-peers=false
strict-peer-dependencies=true
```

This satisfies the issue's supply-chain requirements without relying
on per-developer `pnpm config set`. `ignore-scripts=true` blocks
postinstall — a real attack vector. `minimum-release-age=1440` gives
a 24h cooldown so a freshly-published malicious version cannot land
via dependabot.

### 4.4 `tsconfig.json`

Strict per global CLAUDE.md: `strict`, `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitOverride`,
`noPropertyAccessFromIndexSignature`, `verbatimModuleSyntax`,
`isolatedModules`, `module: "NodeNext"`, `moduleResolution: "NodeNext"`,
`target: "ES2023"`.

### 4.5 Linting and formatting

`oxlint` and `oxfmt` per global CLAUDE.md, run via the existing
`prek` framework. New hook entries under `.pre-commit-config.yaml`
trigger on TS/JS file changes under `tests/mcp-conformance/`. If
`oxlint`/`oxfmt` are not usable against TypeScript at the chosen
versions, the design falls back to `tsc --noEmit` only and the
`format:check` script is dropped — decided at plan execution time.

### 4.6 Dependabot

Add an `npm` ecosystem entry to `.github/dependabot.yml` for
`tests/mcp-conformance/` with a 7-day cooldown and grouped updates per
repo convention.

### 4.7 Binary path discovery

`process.env.RUSTY_IMAP_MCP_BIN`, falling back to a computed default
of `../../target/debug/rusty-imap-mcp` relative to
`tests/mcp-conformance/`. The `just mcp-conformance-node` target and
the CI workflow both set the env var explicitly. If the binary
doesn't exist, Vitest's `beforeAll` fails with a clear error pointing
at `just mcp-conformance-node`.

## 5. CI workflow

A new job in the existing `.github/workflows/ci.yml`, alongside the
seven status checks already there. Single job (not a separate
workflow file) so it shows up under the same Actions run and inherits
the workflow-level `permissions: contents: read`.

```yaml
mcp-conformance-node:
  name: mcp-conformance (Node)
  runs-on: ubuntu-24.04
  steps:
    - uses: actions/checkout@<sha>  # vX.Y.Z
      with:
        persist-credentials: false

    - uses: dtolnay/rust-toolchain@<sha>  # v1 (toolchain: 1.94.0) # zizmor: ignore[superfluous-actions]
      with:
        toolchain: 1.94.0
    - uses: Swatinem/rust-cache@<sha>  # v2.9.1
      with:
        key: mcp-conformance-node

    - name: Build rusty-imap-mcp (debug)
      run: cargo build --bin rusty-imap-mcp --locked

    - uses: pnpm/action-setup@<sha>  # v4.x.x
      with:
        version: <exact-pnpm-version>
        run_install: false
    - uses: actions/setup-node@<sha>  # v4.x.x
      with:
        node-version: '22'
        cache: 'pnpm'
        cache-dependency-path: tests/mcp-conformance/pnpm-lock.yaml

    - name: Install Node deps
      working-directory: tests/mcp-conformance
      run: pnpm install --frozen-lockfile

    - name: Type-check
      working-directory: tests/mcp-conformance
      run: pnpm lint

    - name: Run conformance suite
      working-directory: tests/mcp-conformance
      env:
        RUSTY_IMAP_MCP_BIN: ${{ github.workspace }}/target/debug/rusty-imap-mcp
      run: pnpm test
```

**Action SHA pinning** is mandatory per repo convention; `zizmor`
checks this in CI and rejects tag/branch pins. Exact SHAs are
resolved during plan execution by querying each action's release
tags.

**Single-job rationale.** Building the binary in the same job avoids
artifact upload/download between jobs. The Rust cache (Swatinem)
already makes warm runs cheap. Cold cost: ~3 min build + ~30 s pnpm
install + ~10 s tests. Warm cost: ~20 s + ~10 s + ~10 s.

**Branch-protection sequencing.** The new check name
`mcp-conformance (Node)` must be added to the required checks list
for `main`. Branch protection is configured outside the YAML — this
is an operator action recorded in the plan with a `gh api` snippet.
Sequencing avoids the "first PR's own CI gates itself out" problem:

1. Land Phase 2 with the new job running but **not** required.
2. Verify it goes green on `main` at least once.
3. Add to required checks via `gh api`.

**zizmor.** The existing `zizmor self-check` step covers
`.github/workflows/` recursively, so the new steps are audited
automatically. No new workflow file means no extra surface beyond the
job itself.

## 6. Risks & mitigations

| # | Risk | Mitigation |
|---|---|---|
| 1 | SDK pre-1.0 churn breaks the harness on minor bumps | Exact-pinned `@modelcontextprotocol/sdk` version. Dependabot opens PRs; bumps go through the same `mcp-conformance (Node)` check that proves the bump still works. |
| 2 | `ignore-scripts=true` blocks a postinstall a dep legitimately needs | Chosen deps don't require postinstall on the install surface. Verified during plan execution; any dep added later that needs it must be approved out-of-band. |
| 3 | Phase 1 fixture version, rmcp `LATEST`, SDK `LATEST_PROTOCOL_VERSION`, and the Phase 2 literal drift independently | Test 3 turns this into a four-way drift check (was three-way in Phase 1). Failure mode is "the version-negotiation test fails first with a clear diagnostic naming all four values." |
| 4 | macOS-specific Node bugs (line endings, signal handling) escape the Ubuntu-only CI run | Documented limitation. Phase 2 doesn't promise multi-OS coverage; if a real bug surfaces on macOS we extend the matrix. Phase 1's `check (macOS)` already exercises macOS compile-paths for the binary. |
| 5 | Parallel Vitest workers spawn many binaries simultaneously | Each spawn owns its own tempdir; no shared state. Bounded by Vitest's default pool size; mirrors Phase 1's parallel cargo-test model. |
| 6 | `--allow-empty-accounts` flag removed, breaking both phases together | Acceptable coupling — the flag is a deliberate test-support boundary documented in the rimap-server CLI. Removal would require updating both harnesses in the same PR. |
| 7 | SDK upgrade silently relaxes the strict shape we depend on | Belt-and-suspenders explicit asserts (tools array contains `list_accounts`/`use_account`; every tool's `inputSchema.type === "object"`) survive even if Zod's enforcement weakens. |
| 8 | The binary writes non-JSON to stdout before the JSON-RPC stream | Phase 1's same guard applies — the boot logging path already goes to stderr. The Raw harness's first read after spawn asserts the first stdout line is parseable JSON-RPC. If a future change adds stdout noise, this guard fires before anything else. |

## 7. Acceptance criteria mapping

| Issue #264 criterion | Where addressed |
| --- | --- |
| `pnpm test` runs the conformance sequence against a freshly-built `rusty-imap-mcp` | §4 (justfile, package.json), §3.5 (test cases) |
| Every advertised tool's `inputSchema` passes the SDK's Tool definition (Zod) | §3.5 test 5 |
| `initialize` response capability assertions pass without manual coercion | §3.5 test 2 |
| Documented in `docs/superpowers/specs/` and cross-linked from `AGENTS.md` | This spec + an `AGENTS.md` edit during plan execution |
| Node toolchain footprint in CI documented in `.github/workflows/` | §5 (inline comments in the new job) |

## 8. Open items resolved during plan execution

- Exact pinned versions for `@modelcontextprotocol/sdk`, `vitest`,
  `typescript`, `@types/node`, `oxlint`, `oxfmt`, and `pnpm` itself
  (each picked at plan time from current stable + 24h cooldown).
- Exact SHA + version-comment pins for `pnpm/action-setup` and
  `actions/setup-node`.
- Confirmation that `client.connect()` in the chosen SDK version
  rejects on missing `capabilities.tools` (the assumed behavior —
  verified by reading the SDK's source at the pinned tag during plan
  execution, not from memory).
- Whether `oxlint` and `oxfmt` are usable against TypeScript at the
  chosen versions; fallback path documented in §4.5.
- Whether `StdioClientTransport`'s `stderr: "ignore"` option is the
  correct shape at the pinned SDK version (the SDK's transport API
  has evolved; check at fetch time).

## 9. References

- Issue #264 — phasing parent for this work.
- Issue #263 — Phase 1, landed via PR #270.
- #261 — capabilities-empty bug, fixed.
- `fix/tool-input-schema-object-type` — inputSchema-empty bug, fix
  landed.
- `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`
  — Phase 1 design; this document deliberately mirrors its structure.
- MCP TypeScript SDK:
  `https://github.com/modelcontextprotocol/typescript-sdk`
- MCP specification repo:
  `https://github.com/modelcontextprotocol/modelcontextprotocol`
