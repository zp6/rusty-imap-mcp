# Rusty IMAP MCP — Sprint 3 Design Specification

**Status:** Approved 2026-04-13
**Target:** v1.0.0
**Scope:** Multi-account support via account registry and MCP resource discovery,
IMAP keyword-based label tools, and v1.0.0 release preparation with pre-built
binaries for five platform targets.

## Table of Contents

1. [Goals & Non-Goals](#1-goals--non-goals)
2. [Configuration Changes](#2-configuration-changes)
3. [Account Registry & Session State](#3-account-registry--session-state)
4. [MCP Resources for Account Discovery](#4-mcp-resources-for-account-discovery)
5. [Label Tools](#5-label-tools)
6. [Posture Matrix Update](#6-posture-matrix-update)
7. [Audit Log Changes](#7-audit-log-changes)
8. [Error Handling](#8-error-handling)
9. [Testing Strategy](#9-testing-strategy)
10. [Release Preparation](#10-release-preparation)

---

## 1. Goals & Non-Goals

### Goals

- Add multi-account support: multiple IMAP/SMTP accounts in a single process,
  discoverable via MCP resources, selectable per-session or per-call.
- Add three label tools (`add_label`, `remove_label`, `list_labels`) using
  standard IMAP keywords.
- Ship v1.0.0 with pre-built binaries for five platform targets.
- Maintain full backward compatibility — existing single-account configs work
  unchanged.

### Non-Goals (v1.0.0)

- Provider-specific label backends (Gmail `X-GM-LABELS`, Exchange categories).
  Standard IMAP keywords only.
- Per-account audit log files. Single shared writer with account-tagged records.
- Per-account download directories. Shared `download_dir`.
- crates.io publishing. GitHub release only.
- Container images. Binary releases only.
- IDLE / push notifications.
- OAuth2 / XOAUTH2.
- HTTP / streamable MCP transport.

### Threat Model Additions

Multi-account introduces one new threat vector: a prompt-injected agent with
access to multiple accounts could exfiltrate data from one account via another
(read from account A, send via account B). Mitigations:

- Per-account posture gates — a `readonly` account cannot be used for sending
  even if another account is `full`.
- Per-account rate limiting and circuit breakers — one account's limits do not
  affect another.
- Audit log records include the account name on every operation, enabling
  forensic reconstruction of cross-account sequences.
- The existing provenance ring buffer (future v1.x analyzer) can detect
  read-then-send-across-accounts patterns.

---

## 2. Configuration Changes

### New Config Schema

```toml
# Global settings — shared across all accounts
[audit]
path = "~/.local/share/rusty-imap-mcp/audit.jsonl"
rotate_bytes = 10485760
rotate_keep = 3

[attachments]
download_dir = "~/.local/share/rusty-imap-mcp/downloads"

# Defaults inherited by all accounts unless overridden
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Drafts", "Trash"]
expunge_folders = []

[defaults.limits]
commands_per_second = 10
drafts_per_minute = 5
sends_per_minute = 3

# Accounts
[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "user@proton.me"
credential = "keyring:proton-bridge"
tls_fingerprint_sha256 = "AA:BB:CC:..."

[accounts.smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "user@proton.me"
credential = "keyring:proton-bridge"

[[accounts]]
name = "personal"

[accounts.imap]
host = "imap.fastmail.com"
port = 993
username = "me@fastmail.com"
credential = "keyring:fastmail"
# No [accounts.smtp] — send_email not available for this account

[accounts.security]
posture = "readonly"  # overrides the default
```

### Backward Compatibility

A config with no `[[accounts]]` section and the existing flat `[imap]` /
`[smtp]` / `[security]` / `[limits]` structure is treated as a single
anonymous account named `"default"`. Existing v1/v2 configs work unchanged.

Mixing flat top-level `[imap]` and `[[accounts]]` is a startup error
(`MixedConfigFormat`).

### Defaults Inheritance

Per-account `[accounts.security]` and `[accounts.limits]` sections override
the corresponding `[defaults.*]` sections. Fields not specified in the
per-account section inherit from defaults. Fields not specified in defaults
use the same hardcoded defaults as the current flat config.

### Validation Rules

- **Account names:** non-empty, ASCII alphanumeric + hyphens, max 64
  characters. Must be unique across all `[[accounts]]` entries.
- **At least one account:** either flat `[imap]` or at least one
  `[[accounts]]` entry must exist.
- **Per-account `SmtpRequired`:** if `send_email` is effectively enabled
  for an account (posture + per-tool overrides) but that account has no
  `[accounts.smtp]` section, startup error.
- **Per-account `ConflictingFolders`:** if an account's `protected_folders`
  and `expunge_folders` overlap, startup error.
- **`MixedConfigFormat`:** both flat `[imap]` and `[[accounts]]` present.
- **`DuplicateAccountName`:** two accounts share a name.

---

## 3. Account Registry & Session State

### `AccountState`

Per-account runtime bundle in `rimap-server`:

```rust
struct AccountState {
    name:         AccountId,
    config:       AccountConfig,
    imap:         Connection,
    smtp:         Option<SmtpClient>,
    guard:        DispatchGuard<SystemClock>,
    folder_guard: FolderGuard,
}
```

Each account owns its own IMAP connection, SMTP client, rate limiter,
circuit breaker, and folder guard. No shared mutable state between
accounts.

### `AccountRegistry`

```rust
struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    active:   Mutex<Option<AccountId>>,
}
```

The `active` field holds the session-scoped default account set by
`use_account`. It is protected by a `std::sync::Mutex` (not `tokio::Mutex`)
since the critical section is a trivial read/write of an `Option`.

### `ImapMcpServer` Restructure

```rust
pub struct ImapMcpServer {
    registry:     AccountRegistry,
    audit:        AuditWriter,
    download_dir: PathBuf,
}
```

Replaces the current singular `config`, `imap`, `guard`, `folder_guard`
fields.

### Account Resolution

On every tool call (except `use_account` and `list_accounts`):

1. If the tool arguments contain `"account": "<name>"` — use that account.
2. Else if `registry.active` is set — use the session default.
3. Else if exactly one account exists — auto-select it.
4. Else — return `ERR_NO_ACCOUNT`.

### New Tools

**`use_account`:**
- Input: `{ "account": "work" }`
- Sets `registry.active` to the named account.
- Returns confirmation with the account name.
- Bypasses posture checks, rate limiting, and circuit breaker — it is an
  infrastructure tool, not an IMAP operation.
- Audit: `use_account` event with `account` and `previous` fields.

**`list_accounts`:**
- No input.
- Returns array of account summaries:
  `{ "name", "imap_host", "posture", "smtp_configured" }`.
- Bypasses posture checks, rate limiting, and circuit breaker.
- Audit: `list_accounts` event with `count`.

### Tool Handler Changes

Each handler currently takes `&ImapMcpServer`. The dispatch layer resolves
the account first, then passes `(&AccountState, &AuditWriter)` (or an
equivalent context struct) to the handler. The handler signature change is
mechanical: `self.imap` becomes `account.imap`, `self.guard` becomes
`account.guard`, etc.

The `dispatch_tool` method on `ImapMcpServer` resolves the account from the
arguments map before delegating to the tool handler. The `account` key is
stripped from the arguments before passing to `parse_args`.

---

## 4. MCP Resources for Account Discovery

### Resource List

`list_resources` returns one resource per configured account:

```json
[
  {
    "uri": "rimap://accounts/work",
    "name": "work",
    "description": "IMAP account: user@proton.me on 127.0.0.1",
    "mimeType": "application/json"
  },
  {
    "uri": "rimap://accounts/personal",
    "name": "personal",
    "description": "IMAP account: me@fastmail.com on imap.fastmail.com",
    "mimeType": "application/json"
  }
]
```

### Resource Read

`read_resource("rimap://accounts/work")` returns account metadata:

```json
{
  "name": "work",
  "imap_host": "127.0.0.1",
  "imap_port": 1143,
  "imap_username": "user@proton.me",
  "posture": "draft-safe",
  "smtp_configured": true,
  "protected_folders": ["INBOX", "Sent", "Drafts", "Trash"],
  "available_tools": ["list_folders", "search", "fetch_message", "..."]
}
```

### Security

No credentials in resources. Username is metadata (the agent needs it for
context like "which email am I replying from"), but passwords, keyring
references, and TLS fingerprints are never exposed in resource responses.

### URI Scheme

`rimap://accounts/<account-name>` is the only resource URI pattern. Unknown
URIs return `RESOURCE_NOT_FOUND`. The URI scheme is not extensible in v1.0.0
— per-account folder or message resources are a future consideration.

---

## 5. Label Tools

Three new tools using standard IMAP keywords via `STORE +FLAGS` / `-FLAGS`.
No provider-specific extensions.

### Tool Definitions

| Tool | Input | Behavior |
|------|-------|----------|
| `add_label` | `folder`, `uids`, `label` | `STORE +FLAGS (<label>)` on each UID. Returns count of affected messages. |
| `remove_label` | `folder`, `uids`, `label` | `STORE -FLAGS (<label>)` on each UID. Returns count of affected messages. |
| `list_labels` | `folder`, `uid` | `FETCH <uid> (FLAGS)`, returns all non-system flags. |

### What Counts as a Label

Any IMAP flag that is not a system flag (`\Seen`, `\Answered`, `\Flagged`,
`\Deleted`, `\Draft`, `\Recent`). The `$PendingReview` flag used by
`create_draft` is a label by this definition.

### Label Validation

- Max 256 bytes
- No null bytes
- No spaces (IMAP atom syntax)
- No characters outside the IMAP atom character set (no `(`, `)`, `{`, `%`,
  `*`, `"`, `]`)
- Reject flags starting with `\` (reserved for system flag namespace)

Validation failures return `ERR_INVALID_PARAMS`.

### Server Keyword Support

Not all IMAP servers support arbitrary keywords. If the server rejects a
`STORE` for an unknown keyword, the IMAP error propagates as `ERR_IMAP`. No
server capability probing — fail fast, let the agent interpret the error.

### IMAP Operations

`add_label` and `remove_label` require new `Connection` methods in
`rimap-imap`:

- `store_add_flags(folder, uids, flags)` — `SELECT` + `UID STORE +FLAGS`
- `store_remove_flags(folder, uids, flags)` — `SELECT` + `UID STORE -FLAGS`

These are thin wrappers distinct from the existing flag manipulation used by
`mark_read`/`flag` etc., which operate on system flags. The underlying IMAP
command is the same (`STORE`), but the label tools pass arbitrary keyword
strings rather than well-known flag constants.

`list_labels` uses the existing `FETCH FLAGS` capability, filtering the
result to exclude system flags.

---

## 6. Posture Matrix Update

The matrix expands from 19 tools x 4 postures to 22 tools x 4 postures.

| Tool | readonly | draft-safe | full | destructive |
|------|----------|------------|------|-------------|
| `list_folders` | yes | yes | yes | yes |
| `search` | yes | yes | yes | yes |
| `search_advanced` | - | - | yes | yes |
| `fetch_message` | yes | yes | yes | yes |
| `fetch_message_html` | - | - | yes | yes |
| `list_attachments` | yes | yes | yes | yes |
| `download_attachment` | yes | yes | yes | yes |
| `mark_read` | - | yes | yes | yes |
| `mark_unread` | - | yes | yes | yes |
| `flag` | - | yes | yes | yes |
| `unflag` | - | yes | yes | yes |
| `add_label` | - | yes | yes | yes |
| `remove_label` | - | yes | yes | yes |
| `list_labels` | yes | yes | yes | yes |
| `move_message` | - | yes | yes | yes |
| `create_draft` | - | yes | yes | yes |
| `send_email` | - | - | yes | yes |
| `delete_message` | - | - | yes | yes |
| `create_folder` | - | - | yes | yes |
| `rename_folder` | - | - | yes | yes |
| `expunge` | - | - | - | yes |
| `delete_folder` | - | - | - | yes |

### Rationale

- `add_label` / `remove_label` at `draft-safe` — same tier as `flag` /
  `mark_read`; they are metadata mutations, not content mutations.
- `list_labels` at `readonly` — read-only flag inspection, same tier as
  `list_attachments`.

### Infrastructure Tools

`use_account` and `list_accounts` are **not in the posture matrix**. They
bypass posture checks, rate limiting, and circuit breaker gating entirely.
They are always available regardless of account posture. They still produce
audit records.

---

## 7. Audit Log Changes

### Shared Writer, Account-Tagged Records

The `AuditWriter` remains singular. All accounts write to one JSONL file.

### New Record Field

`account: Option<String>` added to all record types (`ProcessStart`, `Auth`,
`ToolStart`, `ToolEnd`). `None` for legacy single-account configs (the
`"default"` synthetic account), `Some("work")` for named multi-account
configs.

### `ProcessStart` Changes

Currently records a single `posture` field. With multi-account, it records
an array of account summaries:

```json
{
  "type": "process_start",
  "accounts": [
    { "name": "work", "posture": "full", "imap_host": "127.0.0.1" },
    { "name": "personal", "posture": "readonly", "imap_host": "imap.fastmail.com" }
  ]
}
```

For legacy single-account configs, the existing flat `posture` field is
emitted instead. No breaking change to the JSONL schema for existing users.

### New Audit Events

| Event | Key Fields |
|-------|-----------|
| `use_account` | `account` (selected), `previous` (if changing) |
| `list_accounts` | `count` |
| `add_label` | `folder`, `uids`, `label` |
| `remove_label` | `folder`, `uids`, `label` |
| `list_labels` | `folder`, `uid` |

### Redaction

- Label values logged verbatim (not PII — user-defined categories).
- Account names logged verbatim (needed for forensic reconstruction).
- No new PII fields introduced.

### `audit merge` Filter

Add `--account <name>` filter to the merge subcommand for extracting
single-account timelines from shared logs.

---

## 8. Error Handling

### New Error Types

| Error | Crate | Trigger |
|-------|-------|---------|
| `RimapError::NoAccount` | `rimap-core` | Tool call with no account selected and multiple accounts configured |
| `RimapError::UnknownAccount` | `rimap-core` | `account` param or `use_account` names a nonexistent account |
| `ConfigError::DuplicateAccountName` | `rimap-config` | Two `[[accounts]]` entries share a name |
| `ConfigError::MixedConfigFormat` | `rimap-config` | Both flat `[imap]` and `[[accounts]]` present |
| `ConfigError::InvalidAccountName` | `rimap-config` | Name fails validation (empty, non-ASCII, too long, spaces) |
| `ConfigError::NoAccounts` | `rimap-config` | Config has neither flat `[imap]` nor `[[accounts]]` |

### New Error Codes

| Code | Meaning |
|------|---------|
| `ERR_NO_ACCOUNT` | No account selected; agent must call `use_account` or pass `account` param |
| `ERR_UNKNOWN_ACCOUNT` | Named account not found in config |

### Actionable Messages

- `ERR_NO_ACCOUNT`: "Multiple accounts configured; call `use_account` or
  pass `account` parameter. Available: work, personal"
- `ERR_UNKNOWN_ACCOUNT`: "Account 'typo' not found. Available: work,
  personal"

### Label Errors

No new error types for labels. `STORE +FLAGS` failures propagate as
`ERR_IMAP`. Label validation failures use `ERR_INVALID_PARAMS`.

---

## 9. Testing Strategy

### Config Tests (`rimap-config`)

- Multi-account TOML parsing with defaults inheritance
- Legacy flat config auto-wrapped as `"default"` account
- `MixedConfigFormat` error on flat + `[[accounts]]`
- `DuplicateAccountName` detection
- `InvalidAccountName` validation (empty, spaces, too long, non-ASCII)
- Per-account `SmtpRequired` and `ConflictingFolders` checks
- Defaults override: account `[security]` overrides `[defaults.security]`

### Account Registry Tests (`rimap-server`)

- Account resolution: explicit param > session default > auto-select > error
- `use_account` sets and overwrites session default
- `list_accounts` returns all configured accounts
- `ERR_NO_ACCOUNT` when multi-account, no selection
- `ERR_UNKNOWN_ACCOUNT` for nonexistent name
- Single-account auto-select without `use_account`

### Label Tests

**Unit (`rimap-server`):**
- Label validation: reject system flags, backslash prefix, null bytes, overlength
- `list_labels` filters system flags from response

**Integration (`rimap-imap`):**
- `add_label` / `remove_label` round-trip via Dovecot harness
- `list_labels` returns custom flags, excludes system flags
- Multiple UIDs in one `add_label` call

### Authz Tests (`rimap-authz`)

- Expanded posture matrix: 22 tools x 4 postures
- `use_account` and `list_accounts` bypass posture checks
- Label tools at correct posture levels

### Audit Tests (`rimap-audit`)

- `account` field present on records when multi-account
- `account` field `None` for legacy single-account
- `ProcessStart` records multi-account summary
- `audit merge --account work` filters correctly

### MCP Resource Tests (`rimap-server`)

- `list_resources` returns one resource per account
- `read_resource` returns metadata without credentials
- Unknown URI returns not-found error

### Release Validation

- All five binary targets build and print `--version`
- `just ci` green on the release commit

---

## 10. Release Preparation

### Version

`workspace.package.version` set to `1.0.0`. The semver stability
commitment covers:

- Config file format (TOML schema)
- MCP tool names and input/output schemas
- MCP resource URI scheme (`rimap://accounts/<name>`)
- Audit log JSONL schema
- CLI flags and exit codes

### CHANGELOG

Full v1.0.0 entry covering the entire feature surface. Organized by
capability, not by sprint or development history.

### Documentation

| Document | Content |
|----------|---------|
| `README.md` | Rewrite for v1.0: what it does, quick-start, multi-account config example, posture overview, links to detailed docs |
| `docs/configuration.md` | Full config reference with multi-account and legacy examples |
| `docs/multi-account.md` | Account discovery, `use_account`, MCP resources, single-account backward compat |
| `docs/security-model.md` | Posture matrix (22 tools x 4 postures), threat model, audit log |
| `docs/proton-bridge-setup.md` | TLS fingerprint capture walkthrough |

### Build Targets

| Target | Build Method |
|--------|-------------|
| `x86_64-unknown-linux-gnu` | Native `cargo build` (CI runner) |
| `aarch64-unknown-linux-gnu` | `cross` |
| `aarch64-apple-darwin` | Native `cargo build` (macOS runner) |
| `powerpc64le-unknown-linux-gnu` | QEMU user-mode emulation — native `cargo build` inside ppc64le container |
| `s390x-unknown-linux-gnu` | QEMU user-mode emulation — native `cargo build` inside s390x container |

### QEMU Build Strategy

GitHub Actions jobs use `docker/setup-qemu-action` to register binfmt_misc
handlers, then run `docker run --platform linux/ppc64le` (and `linux/s390x`)
with a Rust container image, mounting the source tree and running
`cargo build --release` natively under emulation. Slower than
cross-compilation but avoids linker/toolchain issues with `cross` on these
architectures.

### Release Workflow

A new `.github/workflows/release.yml` triggered on version tags (`v*`):

1. Run five build jobs in parallel (one per target).
2. Collect binary artifacts.
3. Generate SHA256 checksums file.
4. Create GitHub release with all binaries and checksums attached.
5. Release notes generated from CHANGELOG.

### Not in Scope for v1.0.0

- crates.io publishing
- Container / OCI images
- `cargo vet` adoption
- `cargo-mutants` CI gate
- Provenance analyzer
- IDLE / push notifications
