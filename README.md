# rusty-imap-mcp

A security-first [Model Context Protocol](https://modelcontextprotocol.io/) server
for IMAP email, written in Rust. Primary target: Proton Mail via Proton Bridge.
Compatible with standard IMAP servers (Dovecot, Cyrus, Gmail app password, etc.).

**Status:** Sprint 0 — scaffolding only. No functionality yet. See
[`docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`](docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md)
for the full design.

## Why

LLM agents reading email are an attractive target for prompt injection. A single
crafted message can contain hidden instructions that induce the agent to send mail,
leak data, or pivot to other tools. `rusty-imap-mcp` is built around that threat:
every byte of email content is treated as untrusted input, sanitized aggressively,
tagged structurally, and accompanied by server-generated security warnings about
look-alike domains, hidden content, and content provenance.

## Security postures

Three presets with per-tool overrides:

- **`readonly`** — list, search, fetch, download. No mutations. Safest.
- **`draft-safe`** (default) — read + flag + move + *create drafts* (appended to
  Drafts with a `$PendingReview` keyword). **Never opens an SMTP connection.**
- **`full`** — everything above plus advanced search, HTML bodies, and (in v2)
  direct SMTP send, delete, and expunge.

## Building

```bash
just setup    # install required tooling and pre-commit hooks
just ci       # run the full local-CI equivalent
```

Developer toolchain is pinned in `rust-toolchain.toml`. MSRV is 1.85.1, verified
independently in CI.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure and the threat model
summary.
