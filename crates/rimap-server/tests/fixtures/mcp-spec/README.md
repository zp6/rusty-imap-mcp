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
