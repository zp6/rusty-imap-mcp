# Multi-Account Support

rusty-imap-mcp supports multiple IMAP/SMTP accounts in a single server
process. Each account has its own IMAP connection, SMTP client, rate
limiter, circuit breaker, and folder guard. There is no shared mutable
state between accounts.

## Configuration

Define accounts with the `[[accounts]]` array in the config file:

```toml
[defaults.security]
posture = "draft-safe"

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "user@proton.me"
tls_fingerprint_sha256 = "ab:cd:..."

[accounts.smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "user@proton.me"

[[accounts]]
name = "personal"

[accounts.imap]
host = "imap.fastmail.com"
port = 993
username = "me@fastmail.com"

[accounts.security]
posture = "readonly"
```

See [configuration.md](configuration.md) for the full config reference.

## Account discovery via MCP resources

Agents discover accounts through the MCP resource protocol.
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

Reading a resource returns account metadata:

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

No credentials, TLS fingerprints, or passwords are exposed in resources.

## Account selection

### `use_account` tool

Sets the session-scoped default account:

```json
{ "account": "work" }
```

All subsequent tool calls use this account unless overridden per-call.
`use_account` bypasses posture checks, rate limiting, and circuit
breaker -- it is an infrastructure tool, not an IMAP operation.

### Per-call `account` parameter

Any tool call can include an `"account"` parameter to target a specific
account for that call only:

```json
{ "account": "personal", "folder": "INBOX", "limit": 10 }
```

The per-call parameter does not change the session default.

### Resolution order

On every tool call (except `use_account` and `list_accounts`):

1. If the tool arguments contain `"account": "<name>"` -- use that account.
2. Else if `use_account` has been called -- use the session default.
3. Else if exactly one account is configured -- auto-select it.
4. Else -- return `ERR_NO_ACCOUNT` with a list of available accounts.

### `list_accounts` tool

Returns an array of account summaries:

```json
[
  { "name": "work", "imap_host": "127.0.0.1", "posture": "full", "smtp_configured": true },
  { "name": "personal", "imap_host": "imap.fastmail.com", "posture": "readonly", "smtp_configured": false }
]
```

`list_accounts` bypasses posture checks and is always available.

## Per-account isolation

Each account has independent:

- IMAP connection
- SMTP client (if configured)
- Rate limiter (`commands_per_second`, `drafts_per_minute`,
  `sends_per_minute`)
- Circuit breaker
- Folder guard (`protected_folders`, `expunge_folders`)
- Security posture

One account's rate limit or circuit breaker state does not affect
another.

## Backward compatibility

A config with no `[[accounts]]` section and the existing flat `[imap]` /
`[smtp]` / `[security]` / `[limits]` structure is treated as a single
anonymous account named `"default"`. No config changes are required when
upgrading from pre-1.0.

Mixing flat top-level `[imap]` and `[[accounts]]` is a startup error
(`MixedConfigFormat`).

## Audit log

All accounts share a single audit log file. Every record includes an
`account` field identifying which account the operation targeted. The
`audit merge --account <name>` flag filters records by account name.

## Threat model

Multi-account introduces a cross-account data exfiltration vector: a
prompt-injected agent with access to multiple accounts could read from
one account and send via another. Mitigations:

- Per-account posture gates -- a `readonly` account cannot send even if
  another account is `full`.
- Per-account rate limiting and circuit breakers.
- Audit log records include the account name on every operation for
  forensic reconstruction.
