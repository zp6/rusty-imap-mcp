# Rusty IMAP MCP — Design Specification

**Status:** Approved 2026-04-07
**Target:** v1.0.0
**Scope:** Read + draft-safe send MCP server for IMAP email, targeting Proton Bridge with
general IMAP compatibility, built in Rust, security-first with agentic threat vectors as
a primary concern.

## Table of Contents

1. [Goals & Non-Goals](#1-goals--non-goals)
2. [Architecture Overview](#2-architecture-overview)
3. [Crate Layout, MSRV & Local Dev](#3-crate-layout-msrv--local-dev)
4. [Configuration & Postures](#4-configuration--postures)
5. [MCP Tool Surface (v1)](#5-mcp-tool-surface-v1)
6. [Content Pipeline & Sanitization](#6-content-pipeline--sanitization)
7. [Unicode Policy](#7-unicode-policy)
8. [Look-alike Detection Policy](#8-look-alike-detection-policy)
9. [Authorization, Rate Limiting, Circuit Breaker](#9-authorization-rate-limiting-circuit-breaker)
10. [Audit Log](#10-audit-log)
11. [Testing Strategy](#11-testing-strategy)
12. [Development Roadmap](#12-development-roadmap)
13. [Post-v1 Roadmap](#13-post-v1-roadmap)

---

## 1. Goals & Non-Goals

### Goals

- Expose IMAP mailbox functionality to MCP-speaking agents with a **security-first**
  posture, treating every byte of email content as untrusted adversarial input.
- **Primary target:** Proton Mail via Proton Bridge (localhost IMAPS with a self-signed
  certificate), while remaining compatible with standard IMAP servers (Dovecot, Cyrus,
  Gmail via IMAP+app password, etc.).
- **Full functionality** for v1.x+, with **tiered security postures** that let users opt
  into more powerful capabilities. The default posture prevents autonomous mail sending.
- **Defense in depth** against prompt injection: content tagging, aggressive
  sanitization, structured look-alike detection, provenance-aware audit logging.
- **Reproducible builds**: pinned MSRV, pinned dependencies, supply-chain auditing.

### Non-Goals (v1)

- Direct SMTP sending (deferred to v2; draft-safe flow covers the common case).
- Multi-account support in a single process (single account per instance; deferred to v3).
- IMAP IDLE / push notifications (deferred to v2.x).
- HTTP / SSE / streamable MCP transport (stdio only; HTTP deferred to v3.x).
- OAuth2 / XOAUTH2 (deferred to v4; Proton Bridge does not need it).
- Message body confusable scanning (false-positive explosion; look-alike detection is
  bounded to addresses, domains, link text, and filenames).
- Reputation services, network lookups, machine learning. All detection is local,
  deterministic, and rules-based.

### Threat Model Summary

The primary adversary is a crafted email that, when read by an agent through this MCP
server, attempts to induce the agent to take a harmful action: exfiltrate data, send
mail on the attacker's behalf, modify mailbox state, or pivot to other tools. Secondary
adversaries include a hostile IMAP server (MITM, malformed responses) and local
malware with the user's file-system privileges.

The server does **not** trust: email bodies, headers, sender addresses, display names,
attachment filenames, link targets, or any server-provided content. It treats all of
these as untrusted input that must be parsed, sanitized, tagged, and structurally
separated from server-controlled metadata before being returned to an MCP client.

The server **does** trust: its own configuration file, its own keychain entries, its
own audit log, and (within limits defined by fingerprint pinning) the TLS identity of
its configured IMAP server.

---

## 2. Architecture Overview

Single-binary async Rust MCP server communicating over stdio. One process instance
serves one IMAP account (v1). Tokio runtime. `rmcp` for MCP protocol. `async-imap` for
IMAP protocol.

```
┌─────────────────────────────────────────────────────────────┐
│ rusty-imap-mcp (single process, stdio)                      │
│                                                             │
│  ┌─────────────┐   ┌──────────────────┐   ┌──────────────┐  │
│  │  rmcp       │──▶│  Tool Dispatcher │──▶│ Authorization│  │
│  │  (stdio)    │   │                  │   │ (posture)    │  │
│  └─────────────┘   └──────────────────┘   └──────┬───────┘  │
│                              │                    │         │
│                              ▼                    ▼         │
│                    ┌──────────────────┐   ┌──────────────┐  │
│                    │ Rate limiter +   │   │ Audit log    │  │
│                    │ circuit breaker  │   │ (JSONL)      │  │
│                    └────────┬─────────┘   └──────────────┘  │
│                             │                               │
│                             ▼                               │
│                    ┌──────────────────┐                     │
│                    │ IMAP session     │                     │
│                    │ (async-imap)     │◀──── TLS + pinned   │
│                    └────────┬─────────┘      fingerprint    │
│                             │                               │
│                             ▼                               │
│                    ┌──────────────────┐                     │
│                    │ Content pipeline │                     │
│                    │ parse→sanitize→  │                     │
│                    │ tag→return       │                     │
│                    └──────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### Design principles

- **Module isolation.** Each module has one clear purpose and communicates through
  typed interfaces. The content pipeline never touches IMAP; authorization never
  touches network; the audit log is a pure append. Each is independently testable.
- **Trust boundaries are explicit.** Every tool response structurally separates
  server-controlled metadata (`meta`), untrusted email content (`untrusted`), and
  server-generated security assessments (`security_warnings`).
- **Sanitize-before-emit.** All untrusted bytes flow through the content pipeline
  before leaving any tool. There is no code path where raw email content reaches a
  tool response unchanged.
- **Every call is auditable.** Every tool invocation produces exactly two audit
  records (start + end), linked by a monotonic sequence number, with provenance
  information about what the server recently read.
- **Fail loud on security-relevant errors.** Startup errors, audit write failures,
  TLS fingerprint mismatches, and lock conflicts all fail hard rather than degrading
  silently.

### Dispatch chain (every tool call)

```
ToolCall → input validation → posture authorization → circuit breaker check
        → rate limiter → audit start → tool execution → audit end → response
```

Any stage failing short-circuits to a structured error response and records an audit
entry. Failures in stages before tool execution never reach the network.

---

## 3. Crate Layout, MSRV & Local Dev

### Workspace layout

```
rusty-imap-mcp/
├── Cargo.toml                  # workspace root
├── rust-toolchain.toml         # dev toolchain (current stable)
├── deny.toml                   # cargo-deny config
├── rustfmt.toml
├── justfile
├── .pre-commit-config.yaml
├── crates/
│   ├── rimap-core/             # shared types: Message, Folder, Posture, AuditRecord
│   ├── rimap-config/           # config loading, validation, keychain + env merging
│   ├── rimap-imap/             # async-imap wrapper: connect, search, fetch, append, flag, move
│   ├── rimap-content/          # MIME parsing, HTML→text, sanitization, look-alike, Unicode
│   ├── rimap-audit/            # JSONL audit log writer, rotation, locking, provenance
│   ├── rimap-authz/            # posture enforcement, per-tool overrides, rate limit, breaker
│   └── rimap-server/           # rmcp server, tool definitions, dispatch, main.rs (bin)
├── tests/
│   ├── integration/
│   │   ├── dovecot/            # Dockerized Dovecot end-to-end
│   │   └── proton/             # Proton Bridge gated tests
│   └── injection-corpus/       # adversarial .eml fixtures + .expected.json
└── docs/
    ├── configuration.md
    ├── postures.md
    ├── security-model.md
    ├── proton-bridge-setup.md
    └── audit-log.md
```

### Why a workspace

- Forces real API boundaries between content handling, IMAP I/O, and authorization.
- `rimap-content` has zero network dependencies: fast, deterministic tests with
  `proptest` and the injection corpus.
- `rimap-authz` has zero IMAP dependencies: posture logic is unit-testable against a
  fake tool registry.
- The server crate is thin — it wires everything together and defines tool schemas.

### Dependencies (version-pinned in `[workspace.dependencies]`)

- `rmcp` — MCP server protocol
- `async-imap`, `tokio`, `rustls`, `tokio-rustls` — IMAP over TLS
- `mail-parser` — RFC 5322 / MIME parsing
- `mail-builder` — RFC 5322 construction for drafts
- `ammonia` — HTML sanitization
- `html5ever`, `scraper` — HTML parsing for the text-extraction path
- `encoding_rs` — charset decoding
- `unicode-normalization` — NFKC
- `unicode-segmentation` — grapheme clusters
- `unicode-script` — script classification
- `idna` — IDN / TR46 / punycode
- `keyring` — OS keychain
- `governor` — rate limiting
- `fs2` — advisory file locking
- `infer` — MIME sniffing for downloaded attachments
- `serde`, `serde_json`
- `thiserror` (library crates), `anyhow` (server crate)
- `tracing`, `tracing-subscriber` — stderr logs (never stdout; stdout is MCP transport)
- `ulid` — process IDs
- `proptest`, `insta`, `cargo-mutants` — dev

### MSRV & reproducibility

- **MSRV pinned at `1.85.1`**, declared at the workspace root via
  `[workspace.package] rust-version = "1.85.1"`, inherited by every member crate.
- **CI MSRV job** installs exactly `1.85.1` (SHA-pinned `dtolnay/rust-toolchain@1.85.1`)
  and runs `cargo check --workspace --all-targets --all-features`. Separate from the
  stable job so a clippy update can't mask an MSRV regression.
- **`rust-toolchain.toml`** pins the *development* toolchain to current stable with
  `components = ["rustfmt", "clippy"]`, `profile = "minimal"`. Developers get stable;
  CI proves MSRV still works.
- **`cargo-msrv` in CI** runs weekly to verify the declared MSRV is still accurate.
- **`Cargo.lock` committed.**
- **`[workspace.dependencies]` in root** — every dependency version declared once,
  inherited by member crates via `foo.workspace = true`. Prevents drift.
- **`cargo deny check`** in CI: advisories, licenses, bans
  (`[bans] multiple-versions = "deny"` with documented exceptions), source allowlist
  (crates.io only).
- **All CI and release builds use `--locked`** so a stale lockfile is a hard error.

### `justfile` targets

| Target | Purpose |
|---|---|
| `setup` | Verify tooling (`rustup`, MSRV toolchain, stable toolchain, `prek`, `cargo-deny`, `cargo-msrv`, `cargo-nextest`), run `prek install`, print ready summary |
| `check` | `cargo check --workspace --all-targets` |
| `fmt` / `fmt-check` | `cargo fmt --all` / with `-- --check` |
| `lint` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| `test` | `cargo nextest run --workspace` (unit + fast tests, no Proton Bridge) |
| `test-msrv` | `cargo +1.85.1 check` and `cargo +1.85.1 nextest run --workspace --locked` |
| `test-integration` | Proton Bridge suite with `PROTON_BRIDGE_TEST=1`, prerequisite-checked |
| `test-injection` | Adversarial email corpus against the content pipeline |
| `deny` | `cargo deny check` |
| `audit-msrv` | `cargo msrv verify` |
| `ci` | `fmt-check && lint && test && test-msrv && deny` — local equivalent of CI |
| `hooks` | Re-runs `prek install` and `prek run --all-files` |

### Pre-commit hooks (`prek`)

Installed on `just setup`. Configured with `prek auto-update --cooldown-days 7`.

**On commit (blocking):**

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `shellcheck` on `scripts/*.sh`
- `actionlint` + `zizmor` on `.github/workflows/**` when touched
- `typos`
- Custom hook rejecting commits on `main`/`master`
- Custom hook forbidding `println!`/`dbg!`/`todo!` in non-test Rust source

**On push (blocking):**

- `cargo nextest run --workspace` (unit tests only)
- `cargo deny check advisories bans`
- `just test-msrv` if `Cargo.toml` or `Cargo.lock` changed

**Not in hooks:** Proton Bridge integration tests, `cargo-mutants`, `cargo-vet` full
runs. Manual or CI only.

**Contract:** if `just ci` passes locally, CI will pass. Developers never get
surprised by CI.

---

## 4. Configuration & Postures

### Config file location (XDG-aware)

- Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml` (default `~/.config/...`)
- macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`
- Override via `--config <path>` or `RUSTY_IMAP_MCP_CONFIG`

### File format

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "dave@proton.me"
# TLS cert pinning (primary) — required for self-signed like Proton Bridge
tls_fingerprint_sha256 = "ab:cd:ef:..."  # optional; omit for system trust store
command_timeout_seconds = 30

[security]
posture = "draft-safe"                    # "readonly" | "draft-safe" | "full"

# Per-tool overrides on top of the posture
[security.tools]
# delete_message = "deny"                 # deny even if posture allows it
# advanced_search = "allow"                # allow even if posture wouldn't

[security.lookalike]
enabled = true
known_domains = []                         # user-curated watchlist (e.g. ["paypal.com"])
warn_on_any_non_ascii_domain = false

[limits]
max_search_results = 200
max_search_results_cap = 1000              # hard ceiling
max_fetch_body_bytes = 5_242_880           # 5 MiB
max_attachment_bytes = 26_214_400          # 25 MiB
commands_per_second = 10
drafts_per_minute = 5
circuit_breaker_error_threshold = 5
circuit_breaker_window_seconds = 30

[audit]
path = "~/Library/Application Support/rusty-imap-mcp/audit.jsonl"
rotate_bytes = 10_485_760                  # 10 MiB
rotate_keep = 5
provenance_window_seconds = 60
fail_open = false                          # do NOT continue on audit write failure

[attachments]
download_dir = ""                          # empty = per-session tempdir
```

### Credential resolution order

1. OS keychain under service `rusty-imap-mcp`, account `<username>@<host>` — primary.
2. Env var `RUSTY_IMAP_MCP_PASSWORD` — fallback for headless/container/CI.
3. Clear error: "no credential found; run `rusty-imap-mcp login` or set env var".

The server **never** prompts interactively on stdio (stdio is the MCP transport). The
subcommand `rusty-imap-mcp login` handles interactive credential storage and exits. It
is the only non-MCP operating mode of the binary apart from `--dry-run` and
`audit merge`.

### Posture matrix

| Tool | `readonly` | `draft-safe` (default) | `full` |
|---|---|---|---|
| `list_folders` | ✅ | ✅ | ✅ |
| `search` (structured) | ✅ | ✅ | ✅ |
| `search` (`advanced_query` escape hatch) | ❌ | ❌ | ✅ |
| `fetch_message` (text) | ✅ | ✅ | ✅ |
| `fetch_message` (`include_html`) | ❌ | ❌ | ✅ |
| `list_attachments` | ✅ | ✅ | ✅ |
| `download_attachment` | ✅ | ✅ | ✅ |
| `mark_read` / `mark_unread` | ❌ | ✅ | ✅ |
| `flag` / `unflag` | ❌ | ✅ | ✅ |
| `move_message` | ❌ | ✅ | ✅ |
| `create_draft` (append Drafts + `$PendingReview`) | ❌ | ✅ | ✅ |
| `delete_message` (move to Trash) | ❌ | ❌ | v2 |
| `expunge` | ❌ | ❌ | v2 |
| `send_email` (direct SMTP) | ❌ | ❌ | v2 |

Per-tool overrides merge on top of the posture. Overrides referencing unknown or v2
tools are a startup error.

Tools denied by the active posture are **not advertised** via `list_tools`. Denial
happens both at discovery (defense in depth) and at dispatch.

### Config validation at startup

- Posture name is valid.
- Every override tool name exists in the v1 tool set.
- TLS fingerprint parses as 32 hex bytes.
- Paths are writable (audit dir, attachment download dir).
- All numeric limits are positive and sane.
- Loud, actionable errors on any failure. No silent defaults for security-relevant
  fields.

---

## 5. MCP Tool Surface (v1)

Every tool returns structured JSON with three top-level fields:

- **`meta`** — server-controlled metadata (folder names, UIDs, flags, sizes). Trusted.
- **`untrusted`** — sanitized content derived from email data. Agents and host LLMs
  should treat this as untrusted input.
- **`security_warnings`** — structured observations emitted by the server's look-alike
  and sanitization layers. Trusted metadata (the server's assessment).

### `list_folders`

- **Input:** `{}`
- **Output:** `{ meta: { folders: [{ name, delimiter, flags, exists, unseen, uid_validity }] } }`
- Folder names are NFKC-normalized and control-char-stripped (they come from the
  server, but untrusted-input discipline applies even to names).
- All postures.

### `search`

**Input:**

```jsonc
{
  "folder": "INBOX",                   // required
  "from": "alice@example.com",         // optional
  "to": "...",
  "cc": "...",
  "subject": "...",                    // substring
  "body": "...",                       // substring
  "since": "2026-03-01",               // ISO date
  "before": "2026-04-01",
  "seen": true,
  "flagged": true,
  "has_attachment": true,              // derived from BODYSTRUCTURE
  "list_id": "rust-users.lists.example.org",
  "headers": { "X-Spam-Status": "No" },  // arbitrary header match via IMAP HEADER
  "advanced_query": "OR FROM alice FROM bob",  // full posture ONLY
  "limit": 100,                        // clamped to max_search_results_cap
  "offset": 0
}
```

**Output:**

```jsonc
{
  "meta": { "folder": "INBOX", "total_matched": 142, "returned": 100, "truncated": true },
  "untrusted": {
    "messages": [{
      "uid": 12345,
      "message_id": "<...>",
      "date": "2026-04-05T14:22:00Z",
      "from": { "name": "Alice", "address": "alice@example.com" },
      "to": [...], "cc": [...],
      "subject": "...",
      "flags": ["\\Seen"],
      "size_bytes": 4821,
      "has_attachments": false,
      "mailing_list": { "list_id": "...", "list_post": "...", "list_unsubscribe": "..." }
    }]
  },
  "security_warnings": [ /* look-alike warnings per Section 8 */ ]
}
```

Search results include headers only — never body content. Body requires
`fetch_message`.

### `fetch_message`

**Input:** `{ folder, uid, include_html?: bool, max_body_bytes?: number }`

- `include_html` is rejected unless the posture or per-tool override allows it.

**Output:**

```jsonc
{
  "meta": { "folder", "uid", "message_id", "size_bytes", "truncated": false },
  "untrusted": {
    "headers": { /* all headers, NFKC-normalized, control chars stripped */ },
    "common_headers": { "from", "to", "cc", "bcc", "reply_to", "date", "subject",
                        "in_reply_to", "references" },
    "mailing_list": { /* when detected */ },
    "body_text": "...",                  // always present
    "body_html_sanitized": "...",        // only when include_html=true and allowed
    "attachments": [{
      "part_id": "2",
      "filename_sanitized": "report.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 12345
    }],
    "link_warnings": [ /* text/href mismatches from HTML parse */ ]
  },
  "security_warnings": [ /* look-alike warnings */ ]
}
```

### `list_attachments`

- **Input:** `{ folder, uid }`
- **Output:** `{ meta, untrusted: { attachments: [...] }, security_warnings: [...] }`
- Separate from `fetch_message` so agents can enumerate attachments without pulling
  the body.

### `download_attachment`

- **Input:** `{ folder, uid, part_id, dest_dir?: string }`
- `dest_dir` must be inside the configured `attachments.download_dir` (or session
  tempdir); path traversal rejected.
- Filename sanitization: strip directories, null bytes, control chars, leading dots,
  Windows reserved names; truncate to 255 bytes on a grapheme boundary; de-duplicate
  on collision.
- MIME sniffing via `infer`; both declared and sniffed types returned so agents see
  discrepancies.
- **Output:** `{ meta: { path, size_bytes, sha256, mime_type_declared, mime_type_sniffed },
  untrusted: { filename_original: "..." }, security_warnings: [...] }`

### `mark_read` / `mark_unread` / `flag` / `unflag`

- **Input:** `{ folder, uid }` or `{ folder, uids: [...] }` (≤100 UIDs per call)
- **Output:** `{ meta: { folder, uids_updated: [...] } }`
- `draft-safe` and `full` postures.

### `move_message`

- **Input:** `{ source_folder, dest_folder, uid }` (or `uids` bounded ≤100)
- **Output:** `{ meta: { source_folder, dest_folder, moves: [{ old_uid, new_uid }] } }`
- Uses IMAP `MOVE` extension when available; `COPY`+`STORE \Deleted` fallback.

### `create_draft`

**Input:**

```jsonc
{
  "to": [{ "name": "...", "address": "..." }],
  "cc": [...], "bcc": [...],
  "subject": "...",
  "body_text": "...",
  "in_reply_to_uid": 12345,            // optional; server fetches referenced message's
  "in_reply_to_folder": "INBOX"        // Message-ID and References for threading
}
```

**Output:** `{ meta: { folder: "Drafts", uid, message_id, keywords: ["$PendingReview"] } }`

- Builds an RFC 5322 message locally via `mail-builder`.
- IMAP `APPEND` to Drafts with `\Draft` and `$PendingReview` keywords.
- **Never opens an SMTP connection.** Both `draft-safe` and `full` postures use the
  same code path in v1; direct SMTP send is v2.
- Separately rate-limited (`limits.drafts_per_minute`, default 5/min) to prevent
  draft-bombing.

### Cross-cutting tool rules

- Every tool enforces the full dispatch chain (input validation → authz → breaker →
  rate limit → audit start → execute → audit end).
- Every string derived from network content is NFKC-normalized and has control chars
  (except `\n`, `\t`) stripped before placement under `untrusted`. See Section 7.
- Every look-alike check produces a structured `security_warnings` entry — never a
  rejection. Agents decide policy. See Section 8.
- Tool errors return structured MCP errors with stable codes; see Section 9.

---

## 6. Content Pipeline & Sanitization

Lives in `rimap-content`. Zero IMAP dependencies — takes `&[u8]` in, emits `Content`
types out. Every byte from IMAP flows through this pipeline before reaching any tool
response.

### Pipeline stages

1. **Parse.** `mail-parser` decodes RFC 5322 into headers + body parts. Malformed
   messages produce a structured error, not a panic. Original bytes preserved for
   audit.

2. **Header extraction.** Every header captured into a multimap. Header names are
   ASCII-validated (control chars in names → header smuggling, rejected). Values
   decoded from RFC 2047 encoded-words, then processed through the Unicode pipeline.
   Common headers (`From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `In-Reply-To`,
   `References`) parsed into typed structures. Address headers produce `{name, address}`
   pairs with the local-part and domain validated separately. After RFC 2047 decoding,
   any CR/LF inside a decoded value is **rejected** (header smuggling) with a
   `parse_errors` entry and that header is dropped.

3. **Mailing list detection.** If `List-Id` is present, a `mailing_list` object is
   populated with all `List-*` headers. Done *before* sanitization so the raw
   `List-Id` survives intact for agent filtering.

4. **Body part selection.** MIME tree walk:
    - Prefer `text/plain` if present and non-empty.
    - Otherwise take `text/html` → HTML-to-text converter.
    - `multipart/alternative`: prefer the text/plain branch.
    - `multipart/related`: use the root body; ignore inline images.
    - `message/rfc822` attachments are **not** recursively parsed into the body;
      they appear as attachments with their own metadata.

5. **HTML → text conversion** (when needed): custom pipeline built on `html5ever` +
   `scraper`:
    - **Strip** `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>`, `<link>`,
      `<meta>`, `<form>`, `<input>`, `<button>`, all SVG.
    - **Strip** elements with `hidden`, `display:none`, `visibility:hidden`,
      `opacity:0`, `font-size:0`, and white-on-white / same-as-background color
      heuristics (inline style parsed; color vs. parent bgcolor compared).
    - **Strip** zero-width, soft-hyphen, and bidirectional override characters per
      Section 7.
    - **Link handling:** `<a href="...">text</a>` → `text [href]`. If the visible
      text looks like a URL or domain whose apparent domain differs from the href's
      domain (after punycode ↔ unicode decoding), append a `link_warnings` entry and
      render as `text [⚠ actually: href]`.
    - **Preserve** structural whitespace (paragraph breaks, list bullets, table cell
      boundaries) so output is human-readable for the agent.
    - Output goes through the Unicode pipeline (Section 7).

6. **Sanitized HTML path** (only when `include_html=true` and allowed): `ammonia`
   with a conservative allowlist — no scripts, no event handlers, no external
   resources, no `data:` URIs except images under 1 MiB, `javascript:` links
   stripped. `link_warnings` computed on this path too.

7. **Attachment metadata extraction.** Per-part: MIME type (declared), filename
   (raw + sanitized), size, content-transfer-encoding, part ID. Filenames sanitized
   per `download_attachment` rules. **No bytes are read at this stage.** Bytes are
   only read when `download_attachment` is invoked.

8. **Content tagging.** The final `Content` struct is wrapped in the `untrusted`
   field. Metadata goes in `meta`. The two are never conflated.

### Size enforcement

- Body parts exceeding `max_fetch_body_bytes` are **truncated** (not rejected), with
  `meta.truncated = true` and `meta.truncated_at_bytes` set. Truncation happens at
  the byte level *before* HTML parsing so a multi-gigabyte body cannot exhaust
  memory during parse.
- Attachments exceeding `max_attachment_bytes` appear in metadata but
  `download_attachment` refuses them with `ERR_ATTACHMENT_TOO_LARGE`.

### Error handling

- Parse failures produce a minimal `Content` with empty body, a populated
  `parse_errors: [...]` array, and raw headers where recoverable. The tool response
  never fails entirely on a malformed message — agents can still see *that* a message
  exists and why it could not be parsed.

---

## 7. Unicode Policy

Every string that leaves the content pipeline is (a) valid UTF-8, (b) in NFKC form,
(c) free of invisible/ambiguous codepoints, (d) preserves legitimate scripts (CJK,
Hebrew, Arabic, European accents, emoji).

### Stages

1. **Decode to UTF-8.**
    - Read the MIME part's declared charset.
    - Decode via `encoding_rs` (legacy charsets supported: Shift_JIS, GB18030,
      ISO-8859-*, Windows-125*, etc.).
    - Undeclared → UTF-8 lossy (`U+FFFD` replacement on invalid sequences).
    - Declared but unknown → UTF-8 lossy + `parse_errors` entry naming the charset.
    - Downstream stages see only `&str`.

2. **Normalize to NFKC.** Via `unicode-normalization`. Collapses visually-equivalent
   forms (full-width ASCII → ASCII, ligatures → components, superscripts → base
   digits). NFKC is deliberately more aggressive than NFC: we accept typographic
   loss for security wins against homograph representations.

3. **Codepoint filtering.** After NFKC, the following categories are removed:

    **Removed entirely:**
    - **Zero-width / invisible formatting:** ZWSP (`U+200B`), ZWNJ (`U+200C`),
      ZWJ (`U+200D`) *when standalone between grapheme clusters* (ZWJ inside a
      valid emoji ZWJ sequence is preserved — detected via `unicode-segmentation`
      grapheme boundaries), BOM (`U+FEFF`), WORD JOINER (`U+2060`), SOFT HYPHEN
      (`U+00AD`), MONGOLIAN VOWEL SEPARATOR (`U+180E`), variation selectors
      `U+FE00`–`U+FE0F` *except* within emoji sequences, tag characters
      `U+E0000`–`U+E007F`.
    - **Bidirectional overrides:** `U+202A`–`U+202E` (LRE/RLE/PDF/LRO/RLO) and
      `U+2066`–`U+2069` (LRI/RLI/FSI/PDI). Trojan Source class. RTL scripts still
      render correctly without explicit overrides — the Unicode Bidi Algorithm
      keys on script properties.
    - **C0/C1 controls** except `\t` (`U+0009`), `\n` (`U+000A`), `\r`
      (`U+000D` → normalized to `\n`). C1 controls `U+0080`–`U+009F` always stripped.
    - **Unassigned / Private Use** (Unicode categories `Cn`, `Co`).
    - **Non-characters** `U+FDD0`–`U+FDEF` and `U+nFFFE`/`U+nFFFF` for each plane.

    **Preserved:**
    - All assigned letters, marks, numbers, punctuation, symbols (`L*`, `M*`, `N*`,
      `P*`, `S*`).
    - Regular whitespace (`U+0020`; NBSP `U+00A0` is normalized to regular space
      during NFKC).
    - Emoji including ZWJ sequences and skin-tone modifiers (grapheme-cluster aware).

4. **Line-ending normalization.** CRLF / CR → LF, applied after codepoint filtering.

5. **Length bounding.** Result size-checked against the relevant cap
   (`max_fetch_body_bytes` for bodies, 4 KiB per header value, 1 KiB per filename).
   Truncation at a **grapheme-cluster boundary** (never mid-codepoint).

### Headers

Same pipeline, plus: after RFC 2047 decoding, any CR or LF inside the decoded content
is **rejected** and the header is dropped with a `parse_errors` entry. Raw header
bytes remain accessible for forensic audit but do not appear under `untrusted`.

### Filenames

Pipeline plus:

- Path separators (`/`, `\`) stripped.
- Leading dots stripped (no hidden files).
- Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`)
  prefixed with `_`.
- Trailing spaces and dots stripped.
- Truncated at 255 *bytes* (filesystem limit), on a grapheme boundary.
- `untrusted.filename_original` carries the raw pre-sanitization filename for
  display; `meta.filename` (or the on-disk name) carries only the sanitized form.

---

## 8. Look-alike Detection Policy

**Principle:** detect and *flag*, never silently rewrite, never reject. Legitimate
email uses every script; we do not "correct" content. Structured warnings surface in
`security_warnings` for agent reasoning.

### Detection surfaces

| Surface | Why | Check |
|---|---|---|
| Sender address (`From` local-part@domain) | Registered lookalike domains | Full confusables + mixed-script + TR46 |
| Sender display name vs. address | `From: "support@paypal.com" <eve@evil.example>` | Extract address-looking substrings from display name, compare domains |
| Reply-To vs. From | `Reply-To` domain confusable with `From` domain | Domain comparison with confusables |
| Link href domain vs. link text | Phishing | Same engine |
| Attachment filenames | `invoice.pdf‮exe` (RLO trick) | Bidi pre-strip + extension mismatch |

**Body text prose is not scanned** — running confusables on prose would swamp agents
with false positives from legitimate multilingual content.

### Detection engine

Single module `rimap-content::lookalike`. All surfaces produce a typed
`LookalikeReport`:

```rust
struct LookalikeReport {
    mixed_script: Option<MixedScript>,
    confusable_with: Vec<Confusable>,
    invisible_chars_pre_strip: Vec<char>,
    bidi_chars_pre_strip: Vec<char>,
    punycode_mismatch: Option<Punycode>,
}
```

**1. Mixed-script detection** (`unicode-script`):

- Split into grapheme clusters, classify by Unicode script property.
- Apply TR39 "Highly Restrictive" profile: one identifier may contain scripts from
  at most one of `{Latin+Han+Hiragana+Katakana, Latin+Han+Bopomofo, Latin+Han+Hangul}`
  plus Common/Inherited. Anything else is flagged.
- `paypal` with a Cyrillic `а` → Latin + Cyrillic → flagged.
- `日本語` → single group → not flagged.

**2. Confusable skeleton (TR39):**

- Compute the skeleton by replacing each confusable codepoint with its representative
  per a vendored slice of Unicode `confusables.txt`, compiled to a `phf` map at build
  time.
- Maintain a small user-configurable allowlist `known_domains`. If a skeleton matches
  a known domain but the raw string is not in the allowlist, that is a strong
  phishing signal.
- Within a single message: two addresses with matching skeletons but different raw
  forms (e.g. `From` vs. `Reply-To` differing only in script) are flagged.

**3. Invisible-character pre-strip audit.**

- The filter pipeline strips invisible chars. The lookalike path records *that* they
  were present before stripping. Any invisible char inside a domain, address, or
  filename → flagged. Legitimate emoji ZWJ sequences do not reach this path because
  lookalike runs on identifier-shaped fields, not body prose.

**4. Bidi-override pre-strip audit.**

- Same mechanism for `U+202A`–`U+202E` / `U+2066`–`U+2069`.
- Filenames: compute extension *before* and *after* bidi stripping; mismatch → flag.

**5. Punycode / IDN.**

- Domains decoded A-label → U-label via `idna` with TR46 strict mode.
- Both forms included in the report when `xn--` is present.
- Mixed-script/confusable checks run on the U-label.
- Domains failing TR46 are flagged distinctly — strict IDN rules failing often
  indicates hostile input.

### Warning emission

`security_warnings` entries are structured observations, **not** email content, and
sit at the same trust level as `meta`. Stable codes:

- `LOOKALIKE_SENDER_MIXED_SCRIPT`
- `LOOKALIKE_SENDER_CONFUSABLE`
- `LOOKALIKE_SENDER_INVISIBLE_CHAR`
- `LOOKALIKE_DISPLAY_NAME_SPOOFS_ADDRESS`
- `LOOKALIKE_REPLY_TO_DOMAIN_MISMATCH`
- `LOOKALIKE_LINK_DOMAIN_MISMATCH`
- `LOOKALIKE_LINK_MIXED_SCRIPT`
- `LOOKALIKE_FILENAME_BIDI_EXTENSION`
- `LOOKALIKE_FILENAME_INVISIBLE_CHAR`
- `LOOKALIKE_IDN_INVALID`

Example:

```jsonc
{
  "code": "LOOKALIKE_SENDER_MIXED_SCRIPT",
  "surface": "from.address",
  "detail": "Domain 'pаypal.com' contains Latin+Cyrillic mixed script",
  "raw": "pаypal.com",
  "skeleton": "paypal.com"
}
```

### What this does not do

- No body-text confusable scanning.
- No rejection — every check is a warning.
- No network lookups (no reputation APIs, no DNS, no whois). Fully local,
  deterministic, reproducible.
- No machine learning.

---

## 9. Authorization, Rate Limiting, Circuit Breaker

All three live in `rimap-authz` and are chained ahead of every tool dispatch. Each
stage is a pure function over `(ToolCall, State) → Result<(), AuthzError>`.

### Dispatch chain

```
  1. Input validation       (schema + semantic: folders, UID ranges, list sizes)
  2. Posture authorization  (effective matrix: posture + per-tool overrides)
  3. Circuit breaker check  (open → fail fast)
  4. Rate limiter           (token bucket; wait up to 250 ms then fail)
  5. Audit: tool_start      (issues sequence number)
  6. Tool execution         (IMAP I/O + content pipeline)
  7. Audit: tool_end        (status, duration, provenance)
```

Any stage failing short-circuits to an error and records the audit end entry.

### Posture authorization

- Compile-time `const` `PostureMatrix` holding the Section 4 table.
- At startup, the *effective* matrix is computed from the base posture merged with
  per-tool overrides, stored in an `Arc<EffectiveMatrix>`.
- Dispatch is an `O(1)` lookup.
- Unknown tool in overrides → startup error.
- Override referencing a v2 tool → startup error.
- Tools denied by the effective matrix are **not advertised** in `list_tools`.

### Rate limiter

- `governor` direct rate limiter (single-account process, one global bucket).
- Default 10 req/sec with a burst of 20, from `limits.commands_per_second`.
- On exceed: wait up to 250 ms (jittered), then fail with `ERR_RATE_LIMITED` and a
  `retry_after_ms` hint.
- Rate is **per tool call**, not per IMAP command. A `search` issuing multiple
  underlying IMAP commands counts once.
- Separate stricter counter for `create_draft`: `limits.drafts_per_minute`, default 5.

### Circuit breaker

Sliding-window count-based breaker:

- **Closed** (normal): count errors in `circuit_breaker_window_seconds` (default 30s).
  When ≥ `circuit_breaker_error_threshold` (default 5), transition to **Open**.
- **Open**: immediately fail with `ERR_CIRCUIT_OPEN` for a cooldown (default 15s).
- **Half-open**: next call allowed through. Success → Closed. Failure → Open with
  doubled cooldown (cap 5 min).
- Auth failures trip immediately (single failure → Open for 60s, doubling on repeat,
  cap 10 min).

**Trips the breaker:** `ConnectionLost`, `AuthFailure`, `Timeout`, `ProtocolError`,
`TlsError`.
**Does not trip:** `NotFound`, `InvalidInput`, `PostureDenied`, `RateLimited`,
`AttachmentTooLarge`, `BodyTruncated` (user/agent/policy errors, not service health
signals).

### Connection management

- Single long-lived authenticated session inside `Arc<Mutex<Session>>`. MCP stdio is
  inherently serialized, so a mutex is acceptable and simpler than a pool.
- Lazy connect on first tool call requiring network.
- Idle timeout: 5 minutes of no tool activity → clean `LOGOUT`; next call reconnects.
- Reconnect-on-half-open: the breaker's half-open probe *is* the reconnect attempt.
  There is no independent reconnect loop.
- Per-command hard timeout: `imap.command_timeout_seconds`, default 30s, enforced via
  `tokio::time::timeout` around each async-imap call.

### Error codes (stable, documented)

Every error carries a machine-readable `code` and a human-readable `message`. Codes
are stable across releases; changing a code is a semver-major break.

| Code | Meaning | Recoverable? |
|---|---|---|
| `ERR_INVALID_INPUT` | Input validation failed | No (fix call) |
| `ERR_POSTURE_DENIED` | Tool not allowed by current posture | No (change config) |
| `ERR_RATE_LIMITED` | Token bucket empty | Yes (`retry_after_ms`) |
| `ERR_CIRCUIT_OPEN` | Breaker open | Yes (`retry_after_ms`) |
| `ERR_NOT_FOUND` | UID/folder/part missing | No |
| `ERR_IMAP_PROTOCOL` | Server misbehaved | Sometimes |
| `ERR_TLS` | Handshake or cert verification failed | No |
| `ERR_AUTH` | Authentication rejected | No |
| `ERR_CONNECTION_LOST` | Mid-call disconnect | Yes (retry) |
| `ERR_TIMEOUT` | Command exceeded limit | Sometimes |
| `ERR_ATTACHMENT_TOO_LARGE` | Exceeds cap | No |
| `ERR_CONFIG` | Startup-time configuration error | No |
| `ERR_INTERNAL` | Bug / invariant violation / audit failure | No |

---

## 10. Audit Log

Append-only JSONL, single file at the configured path, exclusively locked for the
process lifetime. One file. One writer. Loud failure on conflict.

### Record schema

All records share:

```jsonc
{
  "seq": 42,                              // per-process monotonic, starts at 1
  "ts": "2026-04-07T14:22:01.234Z",       // RFC 3339, millisecond UTC
  "process_id": "01JX...",                // ULID per process start
  "kind": "tool_start" | "tool_end" | "process_start" | "process_end" | "config" | "auth"
}
```

**`process_start`:**

```jsonc
{
  "seq": 1, "ts": "...", "process_id": "...", "kind": "process_start",
  "version": "0.1.0",
  "git_commit": "abc123...",              // embedded at build via vergen
  "posture": "draft-safe",
  "config_path": "/Users/dave/...",
  "config_hash_sha256": "...",
  "previous_last_seq": 9998,              // read from previous last line
  "previous_process_id": "01JW...",
  "previous_file_inode": 12345,
  "audit_file_inode_changed": false
}
```

**`process_end`** — best-effort on SIGTERM/SIGINT/EOF:

```jsonc
{
  "seq": 9999, "ts": "...", "kind": "process_end",
  "reason": "signal_int" | "eof" | "error",
  "total_tool_calls": 42
}
```

**`auth`:**

```jsonc
{
  "seq": 2, "ts": "...", "kind": "auth",
  "result": "success" | "failure",
  "host": "127.0.0.1", "port": 1143,
  "username": "dave@proton.me",
  "tls_fingerprint_sha256": "...",        // fingerprint actually observed
  "fingerprint_match": true,              // vs. configured expected
  "error_code": null
}
```

**`tool_start`:**

```jsonc
{
  "seq": 10, "ts": "...", "kind": "tool_start",
  "tool": "fetch_message",
  "posture_effective": "draft-safe",
  "arguments_redacted": { "folder": "INBOX", "uid": 12345, "include_html": false },
  "arguments_hash_sha256": "..."
}
```

**`tool_end`:**

```jsonc
{
  "seq": 11, "ts": "...", "kind": "tool_end",
  "start_seq": 10,
  "tool": "fetch_message",
  "status": "ok" | "error",
  "error_code": null,
  "duration_ms": 47,
  "result_summary": {
    "message_ids_returned": ["<abc@example>"],
    "bytes_returned": 4821,
    "truncated": false,
    "security_warnings_emitted": ["LOOKALIKE_SENDER_MIXED_SCRIPT"]
  },
  "provenance": {
    "window_seconds": 60,
    "message_ids_recently_read": ["<abc@example>", "<def@example>"]
  }
}
```

### Argument redaction

Structural, per-tool. Each tool declares a redaction schema:

- **Replaced with `"<redacted:length>"`:** fields carrying untrusted user content
  that should not be duplicated into the log (`create_draft.body_text`, `.subject`,
  `search.body`).
- **Kept verbatim:** structural fields (folder names, UIDs, flags, bools, posture).
- **Hashed with a process-lifetime salt:** recipient addresses in `create_draft` —
  the log records *that* two calls share a recipient without recording the recipient.
- **Never logged:** passwords, tokens (defense-in-depth deny-list).

The SHA-256 `arguments_hash_sha256` is computed over the *unredacted* payload for
integrity.

### Provenance tracking

The server maintains an in-memory ring buffer of recently-read message IDs: each
`fetch_message` (and `search` result entries, though with lower weight) adds IDs with
a timestamp; entries older than `audit.provenance_window_seconds` are evicted. Every
`tool_end` copies the current contents into `provenance.message_ids_recently_read`.

Interpretation is **post-hoc**, by reviewers or a separate analyzer. The server does
not make autonomous decisions based on provenance in v1; it records evidence. A
provenance analyzer that consumes JSONL and flags suspicious read-then-send sequences
is a v1.x follow-up.

### File handling & locking

- **Path:** from `audit.path`. Parent directory created with mode `0700` if missing.
  File created with mode `0600`.
- **Exclusive advisory lock** acquired on the audit file itself via
  `fs2::FileExt::try_lock_exclusive` (POSIX `flock(LOCK_EX | LOCK_NB)` / Windows
  `LockFileEx` equivalent). **Non-blocking.** Failure → `ERR_CONFIG` at startup,
  naming the conflicting file and advising the user. No retry. No wait.
- **Lock held for the full process lifetime.** Released implicitly on process exit
  (OS-released, crash-safe).
- **Rotation under lock:** when the file exceeds `rotate_bytes`, the process
  (which holds `LOCK_EX` on the active file) renames the file (the lock tracks the
  inode, not the path), creates the new file, locks the new file, then drops the old
  fd. Brief window with two fds held; both locked by the same process.
- **Readers** (`audit merge` subcommand, external tools) use shared lock `LOCK_SH`.
- **Write discipline:** each record = one `write_all(serialized + "\n")`, buffered
  flush, plus `fsync` on `process_start` / `process_end` / `auth` records.
  `tool_start` / `tool_end` are flushed but not fsync'd (performance — a crash may
  lose a few trailing entries).
- **Write failure policy:** audit write failure fails the tool call with
  `ERR_INTERNAL`. The server does not silently continue without audit.
  Escape hatch: `audit.fail_open = true` (default `false`) for users who explicitly
  accept the tradeoff.

### Startup self-check

Before writing `process_start`, the server:

1. Verifies the audit file is writable (creates it if missing).
2. Attempts to read the last line of the existing file, extracts `seq` and
  `process_id`, records them in the new `process_start` as `previous_last_seq` and
  `previous_process_id`. This chains history across restarts.
3. Records the file's current inode in `previous_file_inode`. If a manual `rm`
  occurred between runs, the inode differs on the next boot; `audit_file_inode_changed`
  is set to `true` in the new start record as a tamper signal.

### What is not in the audit log

- Full message bodies or HTML.
- Passwords, tokens, keychain internals.
- Config file contents (only path + hash).
- IMAP wire-level traffic. `tracing` logs to stderr handle debugging separately and
  are not persisted by default.

### `audit merge` subcommand

`rusty-imap-mcp audit merge [options] <path>` reads the active file with shared lock
and streams JSONL to stdout, supporting `--since`, `--until`, `--tool`, `--kind`,
`--process` filters. Trailing malformed lines (from a mid-record crash) emit a
stderr warning and are skipped. Output is trivially pipeable into `jq`.

---

## 11. Testing Strategy

Phased approach (the commitment made in Q16 option D).

### Sprint 1–2: foundations

- **Unit tests** in every crate. Minimum 90% coverage on `rimap-authz` (posture
  matrix exhaustive, rate limiter steady-state property test, breaker state-machine
  exhaustive transitions).
- **Audit concurrent-process test**: spawn two instances against the same path,
  assert second fails with `ERR_CONFIG`.
- **Audit rotation-under-lock test**: cross the rotation boundary, verify no record
  loss and the new file is properly locked.
- **Audit partial-line recovery test**: synthetic truncated trailing line; `audit
  merge` emits valid records with a warning.
- **Audit inode-change detection test**: delete the file between runs, verify
  `audit_file_inode_changed = true`.

### Sprint 3: integration harnesses

- **Dovecot in Docker** (`tests/integration/dovecot/`): `docker compose` file and
  fixture script to load a known mailbox; test helpers connect with pinned
  fingerprint. Runs in CI.
- **Proton Bridge** (`tests/integration/proton/`): documented setup, tests gated
  behind `PROTON_BRIDGE_TEST=1`. Local developer runs; not in CI.
- Connection lifecycle, fingerprint mismatch rejection (both with a deliberately
  wrong fingerprint against Dovecot, and against real Bridge), timeout enforcement,
  breaker-opens-on-repeated-failures.

### Sprint 4: adversarial corpus

- **`tests/injection-corpus/`** — each fixture is a `.eml` file + `.expected.json`
  declaring required/forbidden content and emitted warning codes. Seeded corpus
  (each a separate fixture):
    - Classic prompt-injection body text ("ignore previous instructions…").
    - White-on-white hidden instructions.
    - CSS `display:none` injection.
    - Zero-width character poisoning.
    - Unicode bidi override attacks (Trojan Source CVE-2021-42574 samples).
    - Homograph domains in link text (`paypal.com` / `pаypal.com`).
    - Text/href mismatch phishing.
    - Header smuggling via RFC 2047 encoded-word CRLF tricks.
    - MIME type spoofing (executable declared as image).
    - Oversized body (verify truncation).
    - Deeply nested multipart bomb.
    - `message/rfc822` nested attachment.
    - Mailing list message (verify `mailing_list` extraction + no interference
      with sanitization).
    - One fixture per look-alike warning code, asserting exact codes emitted.
    - **Known-good negative fixtures:** legitimate multilingual mail (Japanese,
      Hebrew, Arabic, German with umlauts) produces **zero** warnings.
- **Property tests** (`proptest`):
    - NFKC stability: `nfkc(output) == output`.
    - No stripped codepoints in output.
    - No C0/C1 controls except `\n`/`\t` in output.
    - HTML→text output contains no tags.
    - Output is valid UTF-8.
- **Snapshot tests** (`insta`): sanitizer output per fixture. Sanitizer changes
  must produce visible diffs.
- **Mutation testing** (`cargo-mutants`) on `rimap-content`: target ≥ 80% mutants
  killed. Document survivors with reasons.

### Sprint 5: end-to-end

- Full scripted session against Dovecot and Proton Bridge: connect → list → search →
  fetch → flag → `create_draft` → verify draft visible with `$PendingReview` → move →
  mark unread. Audit log assertions at each step.
- Redaction round-trip tests per tool's argument schema.

### Ongoing

- **`cargo-mutants` on `rimap-content`** added as a CI job (v1.x follow-up if
  runtime is prohibitive).
- **Dependabot grouped updates** with 7-day cooldowns.
- **Weekly `cargo-msrv verify`** scheduled CI.

---

## 12. Development Roadmap

Five sprints. Each ends in a releasable artifact. v1 ships at Sprint 5. No time
estimates — sprints are ordering and grouping only.

### Sprint 0 — Repo scaffolding & guardrails

Everything required before feature code.

- Feature branch off `main` for all work; main stays pristine.
- Workspace `Cargo.toml` with `[workspace.package] rust-version = "1.85.1"`,
  `[workspace.dependencies]` pinning everything.
- Empty member crates: `rimap-core`, `rimap-config`, `rimap-imap`, `rimap-content`,
  `rimap-audit`, `rimap-authz`, `rimap-server` (bin).
- `Cargo.toml` clippy lint config per global standards (`pedantic`, `unwrap_used = deny`,
  `panic = deny`, `dbg_macro = deny`, etc.).
- `rustfmt.toml`, `deny.toml`, `.pre-commit-config.yaml`.
- Full `justfile` with all targets.
- `rust-toolchain.toml` pinning dev toolchain to current stable.
- `.github/workflows/ci.yml`, SHA-pinned actions, jobs: `fmt`, `clippy`, `test`,
  `msrv` (separate toolchain install), `deny`, `zizmor` self-check.
- `.github/dependabot.yml` with 7-day cooldowns, grouped updates.
- `prek install` run and verified.
- `README.md` rewrite: goals, posture summary, install, links.
- `SECURITY.md` with disclosure contact + threat model summary.
- `LICENSE` — dual MIT/Apache-2.0.
- `CHANGELOG.md` seeded with `## [Unreleased]`.

**Exit criteria:** `just ci` green locally; CI green; a deliberately broken commit
rejected by `prek run`.

### Sprint 1 — Config, postures, authz skeleton

- `rimap-core`: shared types (`Posture`, `ToolName` enum, `AuditRecord` enum, error
  types via `thiserror`).
- `rimap-config`: TOML loading, XDG paths, validation, credential resolution
  (keychain primary, env fallback, `login` subcommand skeleton).
- `rimap-authz`: `PostureMatrix` as a `const`, `EffectiveMatrix` from merge,
  `governor` rate limiter, `CircuitBreaker` state machine; composable `DispatchGuard`.
- Unit tests: full posture × tool coverage, override merge cases (including
  deny-overrides-allow and reject-invalid-name), rate limiter property test, breaker
  state-machine exhaustive.
- `rimap-server` `main.rs`: parse `--config`, load, print effective matrix under
  `--dry-run`, exit.

**Exit criteria:** `rusty-imap-mcp --config x.toml --dry-run` prints the effective
tool matrix; `rimap-authz` unit coverage ≥ 90%.

### Sprint 2 — Audit log

- `rimap-audit`: `AuditWriter` with `Arc<Mutex<BufWriter<File>>>`, `fs2` exclusive
  lock on open, per-record write + buffered flush, fsync on `process_*`/`auth`,
  rotation preserving the lock across rename, shared-lock reader API.
- Redaction schemas for every tool (schemas declared against the Sprint-1 `ToolName`
  enum; implementations are empty until Sprint 5 adds the tool handlers). Property
  tests for redaction round-trips.
- Provenance ring buffer.
- `audit merge` subcommand with filters, tolerant of partial trailing lines.
- Startup self-check (read last line, populate `previous_*`, inode check).
- All tests from Section 11 Sprint-2 list.

**Exit criteria:** audit tests pass; a second `--dry-run` instance against the same
audit path fails with `ERR_CONFIG`; merge subcommand round-trips a synthetic log.

### Sprint 3 — IMAP connection, TLS pinning, read operations

- `rimap-imap`: `Session` wrapper over `async-imap`, `Arc<Mutex<Session>>`, `rustls`
  with custom `ServerCertVerifier` implementing SHA-256 fingerprint pinning (system
  trust store when fingerprint absent), per-call command timeout, lazy connect,
  idle-timeout disconnect, reconnect-on-half-open.
- IMAP operations: `LIST`, `STATUS`, `EXAMINE`/`SELECT`, `SEARCH` (structured + raw
  advanced query), `FETCH` (ENVELOPE, BODYSTRUCTURE, UID, FLAGS, RFC822.SIZE),
  `FETCH BODY[]` for full retrieval. No `STORE`, `APPEND`, or `MOVE` yet.
- `auth` events recorded to audit log with observed vs. expected fingerprint.
- Dovecot container harness + Proton Bridge harness per Section 11 Sprint-3.
- Tests: connect lifecycle, fingerprint mismatch, timeout enforcement, breaker
  transitions, half-open reconnect.

**Exit criteria:** `rimap-imap` authenticates to Bridge and Dovecot, lists folders,
runs structured search, fetches raw messages; integration suite green under both;
TLS failures produce `ERR_TLS` with observed/expected in audit log.

### Sprint 4 — Content pipeline, Unicode, look-alike

- `rimap-content::parse` on `mail-parser`: headers, RFC 2047, MIME tree walk, body
  part selection, attachment metadata.
- `rimap-content::unicode`: decode (`encoding_rs`) → NFKC → codepoint filter →
  line-ending normalization → grapheme-cluster length bounding. Pure functions,
  property-tested.
- `rimap-content::html`: `html5ever` + `scraper` pipeline per Section 6, producing
  plain text and (on request) `ammonia`-cleaned HTML. Hidden-element detection,
  link-warning extraction.
- `rimap-content::lookalike`: mixed-script detection, TR39 skeleton (vendored
  `confusables.txt` → `phf`), punycode/IDN via `idna`, bidi/invisible pre-strip audit,
  filename extension-after-bidi-strip check.
- `rimap-content::output`: `Content` type with `meta` / `untrusted` /
  `security_warnings` structure.
- **Adversarial corpus seeded** (Section 11 Sprint-4 list).
- Property tests per Section 11.
- `cargo-mutants` on `rimap-content` ≥ 80%, survivors documented.

**Exit criteria:** every corpus fixture passes; proptest runs ≥ 10,000 cases per
property; mutation score documented; `rimap-content` builds and tests with zero
network/IMAP dependencies.

### Sprint 5 — MCP server, v1 tool surface, draft-safe send

- `rimap-server` on `rmcp`: stdio transport, tool registration driven by the
  effective matrix (denied tools not advertised).
- Every v1 tool per Section 5 implemented as a thin handler (validate → guard →
  `rimap-imap` call → `rimap-content` pipeline → response with `meta`/`untrusted`/
  `security_warnings` → audit records).
- `rimap-imap` additions: `STORE` (flag manipulation), `MOVE` (extension + fallback),
  `APPEND` (for drafts).
- RFC 5322 construction for drafts via `mail-builder` (verified at sprint start).
  Threading headers via fetched `Message-ID` / `References` when `in_reply_to_uid`
  provided.
- Attachment download sandboxing: per-session tempdir, path-traversal rejection,
  filename sanitization, `infer` MIME sniffing with declared/sniffed discrepancy
  reporting.
- End-to-end tests against Dovecot and Proton Bridge (Section 11 Sprint-5).
- Documentation pass: `configuration.md`, `postures.md`, `security-model.md`,
  `proton-bridge-setup.md` (with fingerprint capture walkthrough),
  `audit-log.md` (schema + `audit merge` reference).

**Exit criteria:** binary runs as an MCP server against Claude Code / Claude
Desktop; every v1 tool works against Proton Bridge; adversarial corpus still green;
`just ci` green; security docs published. Tag `v0.1.0` on `main`.

---

## 13. Post-v1 Roadmap

Each bullet gets its own spec and plan when taken up. Ordering reflects risk and
dependency, not commitment.

- **v1.x follow-ups:**
  - Provenance analyzer (post-hoc tool consuming JSONL, flagging suspicious
    read-then-send sequences).
  - `cargo vet` adoption.
  - CI `cargo-mutants` gate.
- **v2 — full posture:** `delete_message`, `expunge`, direct SMTP `send_email` via
  `lettre`, DSN/bounce handling. Opens autonomous-send risk; v2 lands only after
  real-world v1 usage has stress-tested the audit log and look-alike warnings.
- **v2.x — IDLE & push:** background IDLE, in-memory message index, MCP
  `notifications/resources/updated`.
- **v3 — multi-account:** `account` parameter on every tool, per-account audit logs
  and postures.
- **v3.x — HTTP transport:** streamable HTTP per MCP spec, token-based auth,
  bind-address restrictions, CORS discipline. Only when a concrete remote use case
  exists.
- **v4 — OAuth2 / XOAUTH2:** Gmail and O365 compatibility. Separate auth provider
  abstraction, keychain-stored refresh tokens.
