# Configuration

rusty-imap-mcp uses a single TOML config file. Two formats are supported:

- **Single-account (legacy):** flat `[imap]` / `[security]` / `[limits]`
  sections. Works unchanged from pre-1.0.
- **Multi-account:** `[[accounts]]` array with optional `[defaults]`.
  Each account has its own IMAP, SMTP, security, and limits settings.

Mixing both formats in one file is a startup error.

## Config file location

Resolution order:

1. `--config <path>` CLI argument
2. `RUSTY_IMAP_MCP_CONFIG` environment variable
3. Platform default:
   - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
     (falls back to `~/.config/rusty-imap-mcp/config.toml`)
   - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

## Single-account example (legacy)

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@proton.me"
tls_fingerprint_sha256 = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"

[smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "alice@proton.me"

[security]
posture = "draft-safe"

[limits]
commands_per_second = 10

[audit]
path = "/home/alice/.local/state/rusty-imap-mcp/audit.jsonl"

[attachments]
download_dir = ""
```

## Multi-account example

```toml
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Drafts", "Trash"]

[defaults.limits]
commands_per_second = 10

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

[audit]
path = "/home/user/.local/state/rusty-imap-mcp/audit.jsonl"
```

See [multi-account.md](multi-account.md) for account discovery and
selection details.

## `[imap]` section

IMAP connection settings. Required per account (or at the top level in
single-account format).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | IMAP server hostname or IP |
| `port` | u16 | (required) | IMAP server port (IMAPS) |
| `username` | string | (required) | IMAP login identity |
| `tls_fingerprint_sha256` | string | (none) | Pinned TLS certificate SHA-256 fingerprint. Hex, colons optional. Required for self-signed certs (e.g. Proton Bridge). Omit to use the system trust store. |
| `command_timeout_seconds` | u32 | 30 | Per-command timeout for IMAP operations |
| `connect_timeout_seconds` | u32 | 10 | TCP + TLS handshake + greeting + CAPABILITY probe deadline |

## `[smtp]` section

SMTP connection settings. Optional -- required only when `send_email` is
enabled by the active posture.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | SMTP server hostname or IP |
| `port` | u16 | (required) | SMTP server port (587 for STARTTLS, 465 for implicit TLS) |
| `encryption` | string | (required) | `"starttls"`, `"tls"`, or `"none"` |
| `username` | string | (required) | SMTP login identity |
| `command_timeout_seconds` | u32 | 30 | Per-command timeout for SMTP operations |

## `[security]` section

Controls which tools are available.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `posture` | string | `"draft-safe"` | Base posture: `"readonly"`, `"draft-safe"`, `"full"`, or `"destructive"`. See [security-model.md](security-model.md). |
| `tools` | table | (empty) | Per-tool overrides. Keys are tool names, values are `"allow"` or `"deny"`. |
| `protected_folders` | list | `["INBOX", "Sent", "Drafts", "Trash"]` | Folders that cannot be renamed or deleted |
| `expunge_folders` | list | `[]` | Folders where `expunge` and `delete_folder` are permitted (default empty = deny all) |

### Special-use folder discovery

At account boot, the server runs `LIST "" "*"` once and records any
RFC 6154 special-use markers (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
`\Archive`, `\All`, `\Flagged`) reported by the server. These names
are then:

1. Used as the target folder for `create_draft` (`\Drafts`) and
   `send_email`'s Sent copy (`\Sent`), falling back to the literal
   strings `"Drafts"` and `"Sent"` if the server does not advertise
   special-use attributes.
2. Merged (case-insensitively) into the `protected_folders` list, so
   Gmail's `[Gmail]/Sent Mail` is protected by the default config even
   though the literal list contains `"Sent"`. The merge only adds
   names; user-configured entries are preserved.

No config is required to opt in. The expansion is additive — there is
no way to disable it short of setting `protected_folders` to a list
that already covers the server-native names.

### `[security.lookalike]` subsection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable look-alike detection on addresses, domains, links, and filenames |
| `known_domains` | list | `[]` | User-curated watchlist of protected domains (e.g. `["paypal.com"]`) |
| `warn_on_any_non_ascii_domain` | bool | false | Warn on any non-ASCII domain, even if not in the watchlist |

### Per-tool overrides

Override the posture's default for individual tools:

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"                # deny even though draft-safe allows it
"search.advanced_query" = "allow" # allow even though draft-safe denies it
```

Valid tool names: `list_folders`, `search`, `search.advanced_query`,
`fetch_message`, `fetch_message.include_html`, `list_attachments`,
`download_attachment`, `mark_read`, `mark_unread`, `flag`, `unflag`,
`add_label`, `remove_label`, `list_labels`, `move_message`,
`create_draft`, `send_email`, `delete_message`, `create_folder`,
`rename_folder`, `expunge`, `delete_folder`.

## `[limits]` section

Numeric limits for rate limiting, search, and size caps.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_search_results` | u32 | 200 | Default search result limit |
| `max_search_results_cap` | u32 | 1000 | Hard ceiling on search results |
| `max_fetch_body_bytes` | u64 | 5,242,880 (5 MiB) | Max fetched body bytes per message |
| `max_attachment_bytes` | u64 | 26,214,400 (25 MiB) | Max attachment download size |
| `max_append_bytes` | u64 | 10,485,760 (10 MiB) | Max APPEND message size (drafts, sent copy) |
| `commands_per_second` | u32 | 10 | Rate limiter: tool calls per second |
| `drafts_per_minute` | u32 | 5 | Separate rate limit for `create_draft` |
| `sends_per_minute` | u32 | 3 | Separate rate limit for `send_email` |
| `circuit_breaker_error_threshold` | u32 | 5 | Error count within the window to trip the circuit breaker |
| `circuit_breaker_window_seconds` | u32 | 30 | Sliding window for the circuit breaker error counter |

## `[audit]` section

Audit log settings. `path` is required. Global (shared across all
accounts in multi-account configs).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | (required) | Path to the audit log file (JSONL) |
| `rotate_bytes` | u64 | 10,485,760 (10 MiB) | Rotate when the file reaches this size. `0` disables rotation. |
| `rotate_keep` | u32 | 5 | Number of rotated files to keep after rotation |
| `retention_seconds` | u64 | (none) | Time-based retention for rotated files. Omit to disable. |
| `provenance_window_seconds` | u32 | 60 | Provenance ring buffer window |
| `fail_open` | bool | false | If true, continue on audit write failure (insecure). Default: audit write failure fails the tool call. |
| `allowed_base_dir` | string | (platform default) | Containment base for `audit.path`. Defaults to `$XDG_STATE_HOME/rusty-imap-mcp/`. Set to `"/"` to disable (not recommended). |

See [audit-log.md](audit-log.md) for the log format and record types.

## `[attachments]` section

Global (shared across all accounts).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `download_dir` | string | `""` | Directory for downloaded attachments. Empty string means a per-session temporary directory. |

## `[defaults]` section (multi-account only)

Default security and limits settings inherited by all accounts unless
overridden per-account. Only valid in multi-account configs.

```toml
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Drafts", "Trash"]

[defaults.limits]
commands_per_second = 10
drafts_per_minute = 5
```

Per-account `[accounts.security]` and `[accounts.limits]` sections
override the corresponding `[defaults.*]` sections. Fields not specified
in the per-account section inherit from defaults.

## Credential resolution

Passwords are never stored in the config file. Resolution order:

1. **OS keychain** -- service `rusty-imap-mcp`, account
   `<username>@<host>`. Store credentials with:
   ```
   rusty-imap-mcp login
   ```
2. **Environment variable** `RUSTY_IMAP_MCP_PASSWORD` -- fallback for
   headless, container, or CI environments.
3. **Error** -- if neither source has a value, the server exits with a
   message directing the user to run `rusty-imap-mcp login` or set the
   environment variable.

The server never prompts interactively on stdio (stdio is the MCP
transport). The `login` subcommand is the only interactive mode.

## Validation

The config is validated at startup. Validation errors are fatal:

- Posture name is one of `readonly`, `draft-safe`, `full`, `destructive`
- Every tool override name exists in the tool set
- TLS fingerprint (if set) parses as 32 hex bytes
- Numeric limits are positive
- Unknown fields in any section are rejected (`deny_unknown_fields`)
- Account names: non-empty, ASCII alphanumeric + hyphens, max 64 chars,
  unique across all accounts
- At least one account (flat `[imap]` or `[[accounts]]`) must exist
- Flat `[imap]` and `[[accounts]]` cannot coexist (`MixedConfigFormat`)
- SMTP required when `send_email` is enabled for an account
- `protected_folders` and `expunge_folders` must not overlap
