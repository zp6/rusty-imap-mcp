# Security Postures

rusty-imap-mcp uses three security postures to control which tools are
available. The posture is set in the config file under `[security].posture`
and defaults to `draft-safe`.

## Posture values

| Posture | Description |
|---|---|
| `readonly` | Read-only operations. No flag changes, no drafts, no moves. |
| `draft-safe` | Read + safe mutations: flag changes, moves, and draft creation with `$PendingReview`. Default. |
| `full` | Everything in `draft-safe` plus escape hatches: `search.advanced_query` and `fetch_message.include_html`. |

## Tool matrix

Each row is a dispatchable capability. Some MCP tools expose multiple
gated capabilities (e.g. `search` has a separate `search.advanced_query`
capability).

| Capability | `readonly` | `draft-safe` | `full` |
|---|---|---|---|
| `list_folders` | allowed | allowed | allowed |
| `search` | allowed | allowed | allowed |
| `search.advanced_query` | **denied** | **denied** | allowed |
| `fetch_message` | allowed | allowed | allowed |
| `fetch_message.include_html` | **denied** | **denied** | allowed |
| `list_attachments` | allowed | allowed | allowed |
| `download_attachment` | allowed | allowed | allowed |
| `mark_read` | **denied** | allowed | allowed |
| `mark_unread` | **denied** | allowed | allowed |
| `flag` | **denied** | allowed | allowed |
| `unflag` | **denied** | allowed | allowed |
| `move_message` | **denied** | allowed | allowed |
| `create_draft` | **denied** | allowed | allowed |

## Per-tool overrides

The base posture can be adjusted per-tool in the config file:

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"                # deny even though draft-safe allows it
"search.advanced_query" = "allow" # allow even though draft-safe denies it
```

- `"allow"` grants the tool regardless of what the posture would deny.
- `"deny"` blocks the tool regardless of what the posture would allow.
- An override that matches the posture's default is a no-op (not an error).
- Overrides referencing unknown tool names or v2 tools (`delete_message`,
  `expunge`, `send_email`) cause a startup error.

## Tool advertisement

Tools denied by the effective matrix (posture + overrides) are **not
advertised** via the MCP `list_tools` response. Denial is enforced at
both discovery and dispatch (defense in depth).

The `advertised` set is the list of tool names where the effective
matrix resolves to `allowed`. For example, with `readonly` posture and
no overrides, `list_tools` returns only: `list_folders`, `search`,
`fetch_message`, `list_attachments`, `download_attachment`.

## Escape hatches (full posture only)

Two capabilities are restricted to the `full` posture by default:

- **`search.advanced_query`** -- allows raw IMAP search queries
  (e.g. `"OR FROM alice FROM bob"`). Bypasses the structured query
  builder. Useful for queries the structured form cannot express, but
  exposes the full IMAP SEARCH grammar.

- **`fetch_message.include_html`** -- returns sanitized HTML alongside
  the text body. The HTML is sanitized by `ammonia` with a conservative
  allowlist, but still carries more attack surface than plain text.

Both can be individually enabled in lower postures via per-tool
overrides if the operator accepts the tradeoff.

## `$PendingReview` flag

In both `draft-safe` and `full` postures, `create_draft` appends
messages to the Drafts folder with the `\Draft` flag and a
`$PendingReview` keyword. This acts as a human-in-the-loop gate: the
agent can compose a draft, but a human must review and send it from
their mail client. The server never opens an SMTP connection in v1.

## Config example

```toml
# Read-only posture for monitoring/analysis use cases
[security]
posture = "readonly"
```

```toml
# Default posture (can be omitted entirely)
[security]
posture = "draft-safe"
```

```toml
# Full posture with one tool locked down
[security]
posture = "full"

[security.tools]
create_draft = "deny"
```
