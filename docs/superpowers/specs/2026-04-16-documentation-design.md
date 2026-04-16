# Documentation Overhaul Design

**Date:** 2026-04-16
**Scope:** README rewrite, two quickstart guides, documentation index
**Priority audiences:** New visitors (landing on GitHub) and operators (setting up the server)

## Context

The project reached v1.0.0 on 2026-04-13. Existing reference documentation
is strong (configuration, security model, audit log, multi-account, postures)
but the README reads as a reference sheet rather than a first-class landing
page, and there is no guided setup experience for new users.

A documentation audit identified these gaps for the priority audiences:

- No feature showcase or competitive positioning
- No step-by-step setup guide with verification checkpoints
- No documentation index connecting the existing docs
- The Proton Bridge setup doc is the only provider-specific guide

## Approach

Hub-and-spoke: the README is a focused landing page (~250 lines) that links
to standalone guides and a full documentation index. Existing reference docs
stay unchanged.

## Deliverables

### 1. README.md rewrite (~250 lines)

**Structure:**

```
# rusty-imap-mcp
One-liner + badges (CI, release, license, MSRV)

## Why this exists
3-4 sentences: the threat (prompt injection via email), the solution
(treat all email as adversarial), the outcome (agents can safely read
email).

## Features
Organized by category, each item a one-line description:

- Content defense: sanitization, Unicode NFKC normalization, invisible
  character stripping, look-alike detection, HTML hidden-element removal,
  content tagging (meta/untrusted/security_warnings envelope)
- Authorization: 4-tier security postures, per-tool overrides, tool
  advertisement filtering, $PendingReview human-in-the-loop gate
- Audit and limits: append-only JSONL audit log, token-bucket rate
  limiting, circuit breaker, TLS fingerprint pinning
- Email operations: 22 posture-gated tools (read, search, flag, label,
  move, draft, send, folder management), multi-account support, SMTP
  with Sent-folder copy
- Operations: pre-built binaries (5 platforms), single static binary,
  TOML configuration, OS keychain credential storage, --dry-run
  validation

## How it compares
Feature matrix table comparing rusty-imap-mcp against three projects:

- mcp-email-server (ai-zerolab, 205 stars, Python)
- email-mcp (codefuturist, 30 stars, TypeScript)
- read-no-evil-mcp (thekie, 2 stars, Python)

Rows (~15):

| Feature | rusty-imap-mcp | mcp-email-server | email-mcp | read-no-evil-mcp |
|---------|:-:|:-:|:-:|:-:|
| Content sanitization | yes | no | no | no |
| Prompt injection defense | structural | no | no | ML (72%) |
| Unicode normalization | yes | no | no | no |
| Invisible char stripping | yes | no | no | partial |
| Look-alike detection | yes | no | no | no |
| Security postures | 4 tiers + overrides | no | no | per-account perms |
| Audit log | append-only JSONL | no | audit trail | no |
| TLS fingerprint pinning | yes | no | no | no |
| Rate limiting | token-bucket | no | token-bucket | no |
| Circuit breaker | yes | no | no | no |
| Tool count | 24 | ~10 | 47 | 7 |
| Multi-account | yes | yes | yes | yes |
| SMTP send | yes | yes | yes | yes |
| Credential storage | OS keychain | env vars | config file | env vars |
| IMAP IDLE / watcher | no | no | yes | no |
| Email scheduling | no | no | yes | no |
| Language | Rust | Python | TypeScript | Python |
| Binary | static ~15MB | Python + pip | Node.js | Python + PyTorch |
| Docker | no | yes | yes | yes |

Footer disclaimer: "Based on public documentation as of April 2026.
Corrections welcome via issue or PR."

## Get started
Two links:
- Quick start with Gmail -> docs/quickstart-gmail.md
- Quick start with Proton Bridge -> docs/quickstart-proton-bridge.md

## MCP tools
Keep existing categorized list (read/mutate/manage + 2 infrastructure).

## Build from source
Keep existing content, trimmed.

## Documentation
5-6 top-level links to the most important docs:
- Configuration reference
- Security model and posture matrix
- Multi-account support
- Audit log format
- Full documentation index -> docs/INDEX.md

## License / Security
Keep existing.
```

### 2. docs/quickstart-gmail.md (~150 lines)

Step-by-step setup guide for Gmail users.

**Prerequisites:**
- Gmail account with 2FA enabled
- App password generated (link to Google support page)

**Steps:**

1. **Install** — download binary or build from source, verify with
   `rusty-imap-mcp --version`

2. **Create config** — minimal TOML for Gmail:
   ```toml
   [imap]
   host = "imap.gmail.com"
   port = 993
   username = "you@gmail.com"

   [smtp]
   host = "smtp.gmail.com"
   port = 465
   encryption = "tls"
   username = "you@gmail.com"

   [audit]
   path = "~/.local/state/rusty-imap-mcp/audit.jsonl"
   ```
   Where to place it (Linux and macOS paths).

3. **Store credentials** — `rusty-imap-mcp login`, expected output shown.

4. **Test the connection (CLI verification)** —
   `rusty-imap-mcp --dry-run`, annotated expected output. Common errors
   and what they mean: wrong password, TLS failure, config not found.

5. **Add to your MCP client** — Claude Desktop JSON snippet, Claude Code
   config snippet.

6. **Verify with your agent (agent-driven verification)** — three
   prompts the user gives their agent:
   - "List my email folders" — expected: INBOX, Sent, Drafts, etc.
   - "Search for a recent email from [known sender]" — expected:
     sanitized content with meta/untrusted envelope visible
   - "Search for an email that doesn't exist" — expected: empty result,
     not an error

**What's next:** links to postures.md, configuration.md, multi-account.md.

### 3. docs/quickstart-proton-bridge.md (~180 lines)

Same 6-step skeleton as the Gmail guide with Proton-specific details.

**Differences from Gmail guide:**

- **Prerequisites** add: install Proton Bridge, enable IMAP in Bridge
  settings, note the bridge-generated password (not your Proton account
  password)

- **Step 2 config** uses localhost (127.0.0.1:1143 IMAP, 127.0.0.1:1025
  SMTP) and includes tls_fingerprint_sha256 field

- **Step 2.5 (additional):** capture TLS fingerprint via
  `openssl s_client -connect 127.0.0.1:1143` command, with expected
  output and how to extract the SHA256 fingerprint

- **Steps 3-6:** same structure, Proton-specific expected output

- **Known quirks section** at the end:
  - Bridge password vs Proton account password
  - Self-signed certificate (why fingerprint pinning is required)
  - Folder naming (INBOX, Drafts, Sent, Trash, Archive, Spam, Labels/,
    Folders/)
  - MOVE command support
  - SMTP port (1025 STARTTLS)
  - Recommended timeout settings
  - TLS fingerprint changes on Bridge updates (re-run openssl command)

**Replaces** `docs/proton-bridge-setup.md` as the primary entry point.
All unique content from that document is folded into this guide. The old
file is deleted.

### 4. docs/INDEX.md (~50 lines)

Full documentation catalog organized by journey stage.

```
# Documentation

## Getting Started

| Guide | Provider | Time |
|-------|----------|------|
| Quick start: Gmail | Gmail (app password) | ~10 min |
| Quick start: Proton Bridge | Proton Mail via Bridge | ~15 min |

## Configuration and Operations

| Document | Description |
|----------|-------------|
| Configuration reference | All config fields, defaults, validation |
| Security postures | 4-tier tool matrix, per-tool overrides, folder safety |
| Multi-account support | Account discovery, selection, isolation |
| Audit log | JSONL format, rotation, merge, tamper detection |

## Security

| Document | Description |
|----------|-------------|
| Security model | Threat model, content pipeline, defense layers |
| SECURITY.md | Vulnerability disclosure, supported versions |
| Supply-chain watchlist | Dependency risk tracking |

## Architecture (for contributors)

| Document | Description |
|----------|-------------|
| AGENTS.md | Developer guide: layout, standards, testing |
| Audit locking | Mutex discipline for async + audit writer |
| CHANGELOG.md | Release history |
```

## What stays unchanged

All existing reference documentation:
- docs/configuration.md
- docs/security-model.md
- docs/audit-log.md
- docs/multi-account.md
- docs/postures.md
- docs/architecture/audit-locking.md
- docs/security/supply-chain-watchlist.md
- AGENTS.md, SECURITY.md, CHANGELOG.md

## What gets retired

- `docs/proton-bridge-setup.md` — all content folded into
  docs/quickstart-proton-bridge.md

## Out of scope

The following were identified as gaps but are deferred (they serve agent
developers and contributors, not the priority audiences):

- Tool reference with input/output schemas and examples
- Error code catalog
- Operations guide (systemd, Docker, log rotation, backup)
- Testing guide for contributors
- Crate-level API documentation

## Comparison data sources

Feature claims for the comparison matrix are based on public
documentation (GitHub README files) crawled on 2026-04-16:

- ai-zerolab/mcp-email-server: v0.6.2, 205 stars, Python, BSD-3
- codefuturist/email-mcp: v0.2.1, 30 stars, TypeScript, LGPL-3.0
- thekie/read-no-evil-mcp: v0.3.3, 2 stars, Python, Apache-2.0

Detection percentages for read-no-evil-mcp come from their published
DETECTION_MATRIX.md (71.6% overall, 91% invisible characters).
