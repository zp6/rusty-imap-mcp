# Documentation Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the README for a first-class new user experience, create two provider-specific quickstart guides with verification checkpoints, and add a documentation index connecting all docs.

**Architecture:** Hub-and-spoke. README (~250 lines) is the landing page with feature showcase and comparison matrix, linking to standalone quickstart guides and a full documentation index. Existing reference docs stay unchanged.

**Spec:** `docs/superpowers/specs/2026-04-16-documentation-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Rewrite | `README.md` | Landing page: badges, why, features, comparison matrix, get started links, tools list, build, docs links |
| Create | `docs/quickstart-gmail.md` | 6-step Gmail setup with CLI and agent verification |
| Create | `docs/quickstart-proton-bridge.md` | 7-step Proton Bridge setup with TLS fingerprint capture, CLI and agent verification, known quirks |
| Create | `docs/INDEX.md` | Full documentation catalog organized by journey stage |
| Delete | `docs/proton-bridge-setup.md` | Content folded into quickstart-proton-bridge.md |

---

### Task 1: Create `docs/INDEX.md`

Start with the index because other docs will link to it.

**Files:**
- Create: `docs/INDEX.md`

- [ ] **Step 1: Write the index file**

```markdown
# Documentation

## Getting started

| Guide | Provider | Time |
|-------|----------|------|
| [Quick start: Gmail](quickstart-gmail.md) | Gmail (app password) | ~10 min |
| [Quick start: Proton Bridge](quickstart-proton-bridge.md) | Proton Mail via Bridge | ~15 min |

## Configuration and operations

| Document | Description |
|----------|-------------|
| [Configuration reference](configuration.md) | All config fields, types, defaults, and validation rules |
| [Security postures](postures.md) | 4-tier tool matrix, per-tool overrides, folder safety |
| [Multi-account support](multi-account.md) | Account discovery, selection, per-account isolation |
| [Audit log](audit-log.md) | JSONL format, rotation, merge subcommand, tamper detection |

## Security

| Document | Description |
|----------|-------------|
| [Security model](security-model.md) | Threat model, content pipeline, defense layers |
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy, supported versions |
| [Supply-chain watchlist](security/supply-chain-watchlist.md) | Dependency risk tracking |

## Architecture (for contributors)

| Document | Description |
|----------|-------------|
| [AGENTS.md](../AGENTS.md) | Developer guide: workspace layout, coding standards, testing |
| [Audit locking](architecture/audit-locking.md) | Mutex discipline for async and audit writer |
| [CHANGELOG.md](../CHANGELOG.md) | Release history |
```

- [ ] **Step 2: Verify all links resolve**

Run from the repo root:

```bash
for f in \
  docs/quickstart-gmail.md \
  docs/quickstart-proton-bridge.md \
  docs/configuration.md \
  docs/postures.md \
  docs/multi-account.md \
  docs/audit-log.md \
  docs/security-model.md \
  SECURITY.md \
  docs/security/supply-chain-watchlist.md \
  AGENTS.md \
  docs/architecture/audit-locking.md \
  CHANGELOG.md; do
  [ -f "$f" ] && echo "OK: $f" || echo "MISSING: $f"
done
```

Expected: all OK except `docs/quickstart-gmail.md` and `docs/quickstart-proton-bridge.md` (created in later tasks).

- [ ] **Step 3: Commit**

```bash
git add docs/INDEX.md
git commit -m "docs: add documentation index"
```

---

### Task 2: Create `docs/quickstart-gmail.md`

**Files:**
- Create: `docs/quickstart-gmail.md`
- Reference (read-only): `docs/configuration.md` for config field names and types

- [ ] **Step 1: Write the quickstart guide**

```markdown
# Quick start: Gmail

Set up rusty-imap-mcp with a Gmail account in about 10 minutes.

## Prerequisites

- A Gmail account with [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification) enabled
- An [App Password](https://myaccount.google.com/apppasswords) generated for "Mail" (16-character code, spaces don't matter)

## Step 1: Install

Download a pre-built binary from the
[releases page](https://github.com/randomparity/rusty-imap-mcp/releases),
or build from source:

```bash
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo build --release
# Binary at target/release/rusty-imap-mcp
```

Verify the binary works:

```bash
rusty-imap-mcp --version
```

## Step 2: Create the config file

Create `~/.config/rusty-imap-mcp/config.toml` (Linux) or
`~/Library/Application Support/rusty-imap-mcp/config.toml` (macOS):

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

Replace `you@gmail.com` with your Gmail address.

## Step 3: Store your credentials

Store the App Password in your OS keychain:

```bash
rusty-imap-mcp login
```

When prompted, paste your 16-character App Password (not your Google
account password). The password is stored in the OS keychain under
service `rusty-imap-mcp`, account `you@gmail.com@imap.gmail.com`.

## Step 4: Test the connection

Validate the config and test the IMAP connection without starting the
MCP server:

```bash
rusty-imap-mcp --dry-run
```

A successful run prints the account summary and server capabilities,
then exits.

**If it fails:**

| Error | Cause | Fix |
|-------|-------|-----|
| `ERR_AUTH` | Wrong password | Re-run `rusty-imap-mcp login` with the correct App Password |
| `ERR_TLS` | TLS handshake failure | Verify your network allows connections to imap.gmail.com:993 |
| `ERR_CONFIG` | Config parse error | Check TOML syntax and field names against the [configuration reference](configuration.md) |
| Config not found | Wrong file location | Verify the path matches your platform (see Step 2) or use `--config <path>` |

## Step 5: Add to your MCP client

### Claude Desktop

Edit your Claude Desktop config
(`~/Library/Application Support/Claude/claude_desktop_config.json` on
macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "email": {
      "command": "rusty-imap-mcp"
    }
  }
}
```

### Claude Code

```bash
claude mcp add email rusty-imap-mcp
```

Restart your MCP client after adding the server.

## Step 6: Verify with your agent

Test the full integration by asking your agent to perform these actions:

**Test 1 — List folders:**
> "List my email folders."

Expected: a list including INBOX, [Gmail]/Sent Mail, [Gmail]/Drafts,
[Gmail]/Trash, and any labels you have.

**Test 2 — Search for a known email:**
> "Search for a recent email from [someone you know]."

Expected: results with sanitized content. Each message has a structured
envelope with `meta` (trusted server data), `untrusted` (sanitized
email content), and `security_warnings` (any detected issues).

**Test 3 — Search for something that doesn't exist:**
> "Search for emails from nonexistent-sender-abc123@example.com."

Expected: an empty result set, not an error.

## What's next

- [Security postures](postures.md) — change what the agent can do
  (default is `draft-safe`: read + flags/labels/moves/drafts, no send)
- [Configuration reference](configuration.md) — all config options
- [Multi-account support](multi-account.md) — add more email accounts
- [Full documentation index](INDEX.md)
```

- [ ] **Step 2: Verify internal links**

```bash
for f in \
  docs/configuration.md \
  docs/postures.md \
  docs/multi-account.md \
  docs/INDEX.md; do
  [ -f "$f" ] && echo "OK: $f" || echo "MISSING: $f"
done
```

Expected: all OK.

- [ ] **Step 3: Commit**

```bash
git add docs/quickstart-gmail.md
git commit -m "docs: add Gmail quickstart guide with verification steps"
```

---

### Task 3: Create `docs/quickstart-proton-bridge.md` and delete `docs/proton-bridge-setup.md`

**Files:**
- Create: `docs/quickstart-proton-bridge.md`
- Delete: `docs/proton-bridge-setup.md`
- Reference (read-only): `docs/proton-bridge-setup.md` (content to fold in), `docs/configuration.md`

- [ ] **Step 1: Write the quickstart guide**

```markdown
# Quick start: Proton Bridge

Set up rusty-imap-mcp with Proton Mail via Proton Bridge in about
15 minutes.

## Prerequisites

- [Proton Bridge](https://proton.me/mail/bridge) installed and signed in
- IMAP enabled in Bridge settings
- The bridge password noted (displayed in Bridge settings — this is not
  your Proton account password)

## Step 1: Install

Download a pre-built binary from the
[releases page](https://github.com/randomparity/rusty-imap-mcp/releases),
or build from source:

```bash
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo build --release
# Binary at target/release/rusty-imap-mcp
```

Verify the binary works:

```bash
rusty-imap-mcp --version
```

## Step 2: Capture the TLS fingerprint

Proton Bridge uses a self-signed TLS certificate that is not in your
system trust store. Pin the certificate fingerprint so the server can
verify it.

```bash
openssl s_client -connect 127.0.0.1:1143 < /dev/null 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}'
```

This prints a 64-character hex string. Copy it for the next step.

The fingerprint changes when Proton Bridge regenerates its certificate
(after a Bridge update or reinstall). If the server later fails with
`ERR_TLS`, re-run this command and update the config.

## Step 3: Create the config file

Create `~/.config/rusty-imap-mcp/config.toml` (Linux) or
`~/Library/Application Support/rusty-imap-mcp/config.toml` (macOS):

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "you@proton.me"
tls_fingerprint_sha256 = "paste-your-64-char-fingerprint-here"

[smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "you@proton.me"

[security]
posture = "draft-safe"

[audit]
path = "~/.local/state/rusty-imap-mcp/audit.jsonl"
```

Replace `you@proton.me` with your Proton email address and
`tls_fingerprint_sha256` with the output from Step 2.

## Step 4: Store your credentials

Store the Bridge password in your OS keychain:

```bash
rusty-imap-mcp login
```

When prompted, paste the bridge password from Proton Bridge settings
(not your Proton account password). The password is stored in the OS
keychain under service `rusty-imap-mcp`, account
`you@proton.me@127.0.0.1`.

For SMTP (if using `send_email` in `full` posture), the same bridge
password is used. Store it for the SMTP host:

```bash
RUSTY_IMAP_MCP_PASSWORD=<bridge-password> rusty-imap-mcp login
```

## Step 5: Test the connection

Validate the config and test the IMAP connection without starting the
MCP server:

```bash
rusty-imap-mcp --dry-run
```

A successful run prints the account summary and server capabilities
(including TLS fingerprint verification), then exits.

**If it fails:**

| Error | Cause | Fix |
|-------|-------|-----|
| `ERR_AUTH` | Wrong password | Re-run `rusty-imap-mcp login` with the bridge password (not your Proton account password) |
| `ERR_TLS` | Fingerprint mismatch or Bridge not running | Verify Bridge is running, then re-capture the fingerprint (Step 2) |
| `ERR_CONFIG` | Config parse error | Check TOML syntax and field names against the [configuration reference](configuration.md) |
| Connection refused | Bridge not running or wrong port | Start Proton Bridge and verify the IMAP port in Bridge settings |

## Step 6: Add to your MCP client

### Claude Desktop

Edit your Claude Desktop config
(`~/Library/Application Support/Claude/claude_desktop_config.json` on
macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "email": {
      "command": "rusty-imap-mcp"
    }
  }
}
```

### Claude Code

```bash
claude mcp add email rusty-imap-mcp
```

Restart your MCP client after adding the server.

## Step 7: Verify with your agent

Test the full integration by asking your agent to perform these actions:

**Test 1 — List folders:**
> "List my email folders."

Expected: a list including INBOX, Drafts, Sent, Trash, Archive, Spam,
and any custom labels (under `Labels/`) or folders (under `Folders/`).

**Test 2 — Search for a known email:**
> "Search for a recent email from [someone you know]."

Expected: results with sanitized content. Each message has a structured
envelope with `meta` (trusted server data), `untrusted` (sanitized
email content), and `security_warnings` (any detected issues).

**Test 3 — Search for something that doesn't exist:**
> "Search for emails from nonexistent-sender-abc123@example.com."

Expected: an empty result set, not an error.

## Known quirks

### Bridge password vs. account password

The IMAP/SMTP password is the bridge-specific password displayed in
Proton Bridge settings, not your Proton account password. Using the
wrong password results in `ERR_AUTH`.

### Self-signed certificate

Without `tls_fingerprint_sha256`, the server rejects the connection
because the certificate is not in the system trust store. Fingerprint
pinning is required for Proton Bridge.

### Folder naming

Proton Bridge maps Proton's label system to IMAP folders. Use
`list_folders` to discover the actual IMAP names. Common mappings:

- `INBOX`, `Drafts`, `Sent`, `Trash`, `Archive`, `Spam`
- Labels appear under `Labels/`
- Subfolders appear under `Folders/`

### MOVE support

Proton Bridge supports the IMAP MOVE extension. `move_message` uses
MOVE directly rather than the COPY+STORE+EXPUNGE fallback.

### SMTP port

Proton Bridge uses port 1025 for SMTP with STARTTLS. The exact port
is shown in Bridge settings.

### Timeouts

The defaults (`connect_timeout_seconds` of 10,
`command_timeout_seconds` of 30) work well with Proton Bridge. If
Bridge is slow to start or your mailbox is large, increase
`command_timeout_seconds` in the config.

### TLS fingerprint changes

The fingerprint changes when Bridge regenerates its certificate (after
updates or reinstalls). If you get `ERR_TLS` after a Bridge update,
re-run the openssl command from Step 2 and update the config.
```

- [ ] **Step 2: Delete the old Proton Bridge setup doc**

```bash
git rm docs/proton-bridge-setup.md
```

- [ ] **Step 3: Update any references to the old file**

Search for links to `proton-bridge-setup.md` in the codebase:

```bash
rg "proton-bridge-setup" --type md
```

Update each reference to point to `quickstart-proton-bridge.md` instead. Known locations:
- `README.md` (will be updated in Task 4)

If other files reference it, update those too.

- [ ] **Step 4: Verify internal links**

```bash
for f in \
  docs/configuration.md \
  docs/postures.md \
  docs/multi-account.md \
  docs/INDEX.md; do
  [ -f "$f" ] && echo "OK: $f" || echo "MISSING: $f"
done
```

Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add docs/quickstart-proton-bridge.md
git commit -m "docs: add Proton Bridge quickstart, retire proton-bridge-setup.md"
```

---

### Task 4: Rewrite `README.md`

**Files:**
- Rewrite: `README.md`
- Reference (read-only): `docs/postures.md` (tool list), `docs/security-model.md` (feature details)

- [ ] **Step 1: Write the new README**

```markdown
# rusty-imap-mcp

[![CI](https://github.com/randomparity/rusty-imap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/randomparity/rusty-imap-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/randomparity/rusty-imap-mcp)](https://github.com/randomparity/rusty-imap-mcp/releases)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-orange)](rust-toolchain.toml)

A security-first [Model Context Protocol](https://modelcontextprotocol.io/)
server for IMAP email, written in Rust.

## Why this exists

LLM agents with email access are targets for prompt injection. A single
crafted message can contain hidden instructions that cause an agent to
send mail, leak data, or pivot to other tools. Most MCP email servers
pass raw message content straight to the model.

rusty-imap-mcp treats every byte of email content as untrusted input.
Messages are parsed, sanitized, normalized, and structurally tagged
before reaching the agent — so the model sees clean content with
security metadata, not raw attack surface.

## Features

### Content defense

- HTML sanitization with hidden-element stripping (CSS `display:none`,
  `visibility:hidden`, `opacity:0`, white-on-white text)
- Unicode NFKC normalization and invisible character stripping
  (zero-width, bidi overrides, C0/C1 controls)
- Look-alike detection: mixed-script domains, confusable skeletons,
  display-name spoofing, reply-to mismatch, filename bidi tricks
- Structured response envelope separating trusted `meta` from
  `untrusted` content and `security_warnings`
- Mailing list detection and content provenance tagging

### Authorization

- Four security postures: `readonly`, `draft-safe` (default), `full`,
  `destructive`
- Per-tool `"allow"` / `"deny"` overrides
- Denied tools hidden from `list_tools` and rejected at dispatch
- `$PendingReview` flag on drafts — human-in-the-loop gate

### Audit and limits

- Append-only JSONL audit log with tamper detection
- Token-bucket rate limiting (per-tool, per-account)
- Circuit breaker with sliding-window error counting
- TLS certificate fingerprint pinning

### Email operations

- 22 posture-gated tools: list, search, fetch, flag, label, move,
  draft, send, folder management, attachment download
- 2 infrastructure tools: `list_accounts`, `use_account`
- Multi-account support with per-account posture, rate limits, and
  circuit breaker
- SMTP sending with automatic Sent-folder copy via IMAP APPEND

### Operations

- Single static binary — no runtime dependencies
- Pre-built binaries for 5 platforms (x86_64/aarch64 Linux, aarch64
  macOS, ppc64le, s390x)
- TOML configuration with strict validation
- OS keychain credential storage (no passwords in config files)
- `--dry-run` mode for connection testing

## How it compares

| Feature | rusty-imap-mcp | [mcp-email-server](https://github.com/ai-zerolab/mcp-email-server) | [email-mcp](https://github.com/codefuturist/email-mcp) | [read-no-evil-mcp](https://github.com/thekie/read-no-evil-mcp) |
|---------|:-:|:-:|:-:|:-:|
| **Security** | | | | |
| Content sanitization | yes | no | no | no |
| Prompt injection defense | structural | no | no | ML (72% detection) |
| Unicode normalization | yes | no | no | no |
| Invisible char stripping | yes | no | no | partial |
| Look-alike detection | yes | no | no | no |
| Security postures | 4 tiers + per-tool | no | no | per-account perms |
| Audit log | append-only JSONL | no | audit trail | no |
| TLS fingerprint pinning | yes | no | no | no |
| Rate limiting | token-bucket | no | token-bucket | no |
| Circuit breaker | yes | no | no | no |
| **Capabilities** | | | | |
| Tool count | 24 | ~10 | 47 | 7 |
| Multi-account | yes | yes | yes | yes |
| SMTP send | yes | yes | yes | yes |
| Credential storage | OS keychain | env vars | config file | env vars |
| IMAP IDLE / watcher | no | no | yes | no |
| Email scheduling | no | no | yes | no |
| **Runtime** | | | | |
| Language | Rust | Python | TypeScript | Python |
| Install | single binary | `pip` / `uvx` | `npx` / `pnpm` | `pip` + PyTorch (~500 MB) |
| Docker | no | yes | yes | yes |

Based on public documentation as of April 2026. Corrections welcome
via issue or PR.

## Get started

Pick your email provider:

- **[Quick start: Gmail](docs/quickstart-gmail.md)** — ~10 minutes,
  requires an App Password
- **[Quick start: Proton Bridge](docs/quickstart-proton-bridge.md)** —
  ~15 minutes, includes TLS fingerprint setup

For other IMAP servers (Fastmail, Dovecot, Cyrus, etc.), follow the
Gmail guide and adjust the `host`, `port`, and `encryption` fields for
your provider.

## MCP tools

**22 posture-gated tools:**

- **Read:** `list_folders`, `search`, `search_advanced`,
  `fetch_message`, `fetch_message_html`, `list_attachments`,
  `download_attachment`, `list_labels`
- **Mutate:** `mark_read`, `mark_unread`, `flag`, `unflag`,
  `add_label`, `remove_label`, `move_message`, `create_draft`
- **Manage:** `send_email`, `delete_message`, `create_folder`,
  `rename_folder`, `expunge`, `delete_folder`

**2 infrastructure tools** (always available):
`use_account`, `list_accounts`

See [docs/postures.md](docs/postures.md) for the full 22-tool x
4-posture matrix.

## Build from source

```bash
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo build --release
```

Requires Rust 1.88.0+ and `libdbus-1-dev` (Linux) or equivalent.

### Development

```bash
just setup    # install required tooling and pre-commit hooks
just ci       # run the full local-CI equivalent
```

## Pre-built binaries

Binaries are published for five targets on each
[release](https://github.com/randomparity/rusty-imap-mcp/releases):
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin`, `powerpc64le-unknown-linux-gnu`,
`s390x-unknown-linux-gnu`. SHA256 checksums included.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Security model and posture matrix](docs/security-model.md)
- [Multi-account support](docs/multi-account.md)
- [Audit log format](docs/audit-log.md)
- [Full documentation index](docs/INDEX.md)

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and
`LICENSE-APACHE`.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure and the
threat model summary.
```

- [ ] **Step 2: Verify no broken links**

```bash
rg "\[.*\]\(([^)]+)\)" README.md -o --no-filename | \
  sed 's/.*(\(.*\))/\1/' | \
  grep -v '^http' | \
  while read -r f; do
    [ -f "$f" ] && echo "OK: $f" || echo "MISSING: $f"
  done
```

Expected: all OK.

- [ ] **Step 3: Check line count**

```bash
wc -l README.md
```

Expected: approximately 200-260 lines.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README with features, comparison matrix, quickstart links"
```

---

### Task 5: Final verification

**Files:** all four deliverables

- [ ] **Step 1: Verify all cross-references**

Search for any remaining references to the deleted file:

```bash
rg "proton-bridge-setup" --type md
```

Expected: no results.

- [ ] **Step 2: Verify all internal doc links resolve**

```bash
for f in docs/INDEX.md docs/quickstart-gmail.md docs/quickstart-proton-bridge.md README.md; do
  echo "=== $f ==="
  rg "\[.*\]\(([^)]+)\)" "$f" -o --no-filename | \
    sed 's/.*(\(.*\))/\1/' | \
    grep -v '^http' | \
    while read -r link; do
      dir=$(dirname "$f")
      resolved="$dir/$link"
      [ -f "$resolved" ] && echo "  OK: $link" || echo "  MISSING: $link -> $resolved"
    done
done
```

Expected: all OK.

- [ ] **Step 3: Spell check**

```bash
typos docs/INDEX.md docs/quickstart-gmail.md docs/quickstart-proton-bridge.md README.md
```

Expected: no errors.

- [ ] **Step 4: Review the full diff**

```bash
git diff HEAD~4 --stat
git diff HEAD~4 -- README.md docs/INDEX.md docs/quickstart-gmail.md docs/quickstart-proton-bridge.md
```

Review for: consistent voice, no placeholder text, accurate config field names, correct file paths.

- [ ] **Step 5: Final commit (if any fixes needed)**

Only if previous steps found issues:

```bash
git add -u
git commit -m "docs: fix issues found in final review"
```
