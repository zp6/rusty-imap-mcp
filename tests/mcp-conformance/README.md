# rusty-imap-mcp — MCP Conformance Suite (Node, Phase 2)

This directory holds a Node + TypeScript test suite that drives the
production `rusty-imap-mcp` binary through the official
`@modelcontextprotocol/sdk` and asserts wire conformance against the
SDK's Zod schemas (stricter than the spec's permissive JSON Schema
that Phase 1 validates against).

See [`docs/superpowers/specs/2026-05-12-mcp-conformance-node-design.md`](../../docs/superpowers/specs/2026-05-12-mcp-conformance-node-design.md)
for the full design.

## Running locally

From the repo root:

```bash
just mcp-conformance-node
```

This builds the binary with `--features test-support` (required for
the `--allow-empty-accounts` test flag), installs pinned Node deps,
runs `tsc --noEmit`, and then runs Vitest.

## Running individual tests

```bash
cd tests/mcp-conformance
pnpm install --frozen-lockfile
RUSTY_IMAP_MCP_BIN=$(pwd)/../../target/debug/rusty-imap-mcp pnpm test
```

You need to have built the binary with `--features test-support`
first:

```bash
cargo build -p rimap-server --bin rusty-imap-mcp --features test-support --locked
```

## Relationship to Phase 1

Phase 1 (Rust, `crates/rimap-server/tests/mcp_wire_conformance.rs`)
validates wire payloads against the MCP spec's permissive JSON
Schema. Phase 2 (this directory) validates the same wire flow through
the official TypeScript SDK's Zod schemas, which are stricter and
match what real-world strict clients (`bobshell`, etc.) enforce.

Both run on every PR. Together they triangulate.
