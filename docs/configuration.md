# Configuration

rusty-imap-mcp uses a single TOML config file. All sections except `[imap]`
and `[audit]` have defaults and can be omitted.

## Config file location

Resolution order:

1. `--config <path>` CLI argument
2. `RUSTY_IMAP_MCP_CONFIG` environment variable
3. Platform default:
   - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
     (falls back to `~/.config/rusty-imap-mcp/config.toml`)
   - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

## Minimal example

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "/home/alice/.local/state/rusty-imap-mcp/audit.jsonl"
```

All other sections use defaults when omitted.

## `[imap]` section

IMAP connection settings. `host`, `port`, and `username` are required.

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | (required) | IMAP server hostname or IP |
| `port` | u16 | (required) | IMAP server port (IMAPS) |
| `username` | string | (required) | IMAP login identity |
| `tls_fingerprint_sha256` | string | (none) | Pinned TLS certificate SHA-256 fingerprint. Hex, colons optional (`"ab:cd:..."` or `"abcd..."`). Required for self-signed certs (e.g. Proton Bridge). Omit to use the system trust store. |
| `command_timeout_seconds` | u32 | 30 | Per-command timeout for IMAP operations |
| `connect_timeout_seconds` | u32 | 10 | TCP + TLS handshake + greeting + CAPABILITY probe deadline |

## `[security]` section

Controls which tools are available.

| Field | Type | Default | Description |
|---|---|---|---|
| `posture` | string | `"draft-safe"` | Base posture: `"readonly"`, `"draft-safe"`, or `"full"`. See [postures.md](postures.md). |
| `tools` | table | (empty) | Per-tool overrides. Keys are tool names, values are `"allow"` or `"deny"`. |

### `[security.lookalike]` subsection

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | true | Enable look-alike detection on addresses, domains, links, and filenames |
| `known_domains` | list of strings | `[]` | User-curated watchlist of protected domains (e.g. `["paypal.com"]`) |
| `warn_on_any_non_ascii_domain` | bool | false | Warn on any non-ASCII domain, even if not in the watchlist |

### Per-tool overrides

Override the posture's default for individual tools. Use the tool's
canonical name as the key:

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
`move_message`, `create_draft`.

Overrides referencing unknown or v2 tools (`delete_message`, `expunge`,
`send_email`) are a startup error.

## `[limits]` section

Numeric limits for rate limiting, search, and size caps.

| Field | Type | Default | Description |
|---|---|---|---|
| `max_search_results` | u32 | 200 | Default search result limit |
| `max_search_results_cap` | u32 | 1000 | Hard ceiling on `max_search_results` |
| `max_fetch_body_bytes` | u64 | 5,242,880 (5 MiB) | Max fetched body bytes per message. Bodies exceeding this are truncated. |
| `max_attachment_bytes` | u64 | 26,214,400 (25 MiB) | Max attachment bytes. Attachments exceeding this are refused at download. |
| `commands_per_second` | u32 | 10 | Rate limiter: tool calls per second |
| `drafts_per_minute` | u32 | 5 | Separate rate limit for `create_draft` |
| `circuit_breaker_error_threshold` | u32 | 5 | Error count within the window to trip the circuit breaker |
| `circuit_breaker_window_seconds` | u32 | 30 | Sliding window for the circuit breaker error counter |

## `[audit]` section

Audit log file settings. `path` is required.

| Field | Type | Default | Description |
|---|---|---|---|
| `path` | string | (required) | Path to the audit log file (JSONL) |
| `rotate_bytes` | u64 | 10,485,760 (10 MiB) | Rotate when the file reaches this size. `0` disables rotation. |
| `rotate_keep` | u32 | 5 | Number of rotated files to keep after rotation |
| `provenance_window_seconds` | u32 | 60 | Provenance ring buffer window for tracking recently-read message IDs |
| `fail_open` | bool | false | If true, continue on audit write failure (insecure). Default is false: audit write failure fails the tool call. |
| `allowed_base_dir` | string | (platform default) | Containment base for `audit.path`. The path must resolve under this directory. Defaults to `$XDG_STATE_HOME/rusty-imap-mcp/` or platform equivalent. Set to `"/"` to disable containment (not recommended). |

See [audit-log.md](audit-log.md) for the log format and record types.

## `[attachments]` section

| Field | Type | Default | Description |
|---|---|---|---|
| `download_dir` | string | `""` | Directory for downloaded attachments. Empty string means a per-session temporary directory. |

## Full example

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "dave@proton.me"
tls_fingerprint_sha256 = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
command_timeout_seconds = 30
connect_timeout_seconds = 10

[security]
posture = "draft-safe"

[security.tools]
# mark_read = "deny"

[security.lookalike]
enabled = true
known_domains = ["paypal.com", "example.com"]
warn_on_any_non_ascii_domain = false

[limits]
max_search_results = 200
max_search_results_cap = 1000
max_fetch_body_bytes = 5_242_880
max_attachment_bytes = 26_214_400
commands_per_second = 10
drafts_per_minute = 5
circuit_breaker_error_threshold = 5
circuit_breaker_window_seconds = 30

[audit]
path = "/home/dave/.local/state/rusty-imap-mcp/audit.jsonl"
rotate_bytes = 10_485_760
rotate_keep = 5
provenance_window_seconds = 60
fail_open = false

[attachments]
download_dir = ""
```

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

The config is validated at startup. Validation errors are fatal. Checks
include:

- Posture name is one of `readonly`, `draft-safe`, `full`
- Every tool override name exists in the v1 tool set
- TLS fingerprint (if set) parses as 32 hex bytes
- Numeric limits are positive
- Unknown fields in any section are rejected (`deny_unknown_fields`)
