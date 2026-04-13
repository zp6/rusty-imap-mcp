# Security Postures

rusty-imap-mcp uses four security postures to control which tools are
available. The posture is set in the config file under
`[security].posture` and defaults to `draft-safe`.

## Posture values

| Posture | Description |
|---------|-------------|
| `readonly` | Read-only operations. No flag changes, no drafts, no moves. |
| `draft-safe` | Read + safe mutations: flag/label changes, moves, and draft creation with `$PendingReview`. Default. |
| `full` | Everything in `draft-safe` plus send, delete, folder management, HTML bodies, advanced search. |
| `destructive` | Everything in `full` plus permanent deletion: expunge and delete_folder. |

## Tool matrix

Each row is a dispatchable capability. Some MCP tools expose multiple
gated capabilities (e.g. `search` has a separate `search.advanced_query`
capability).

| Capability | `readonly` | `draft-safe` | `full` | `destructive` |
|------------|:----------:|:------------:|:------:|:-------------:|
| `list_folders` | allowed | allowed | allowed | allowed |
| `search` | allowed | allowed | allowed | allowed |
| `search.advanced_query` | denied | denied | allowed | allowed |
| `fetch_message` | allowed | allowed | allowed | allowed |
| `fetch_message.include_html` | denied | denied | allowed | allowed |
| `list_attachments` | allowed | allowed | allowed | allowed |
| `download_attachment` | allowed | allowed | allowed | allowed |
| `mark_read` | denied | allowed | allowed | allowed |
| `mark_unread` | denied | allowed | allowed | allowed |
| `flag` | denied | allowed | allowed | allowed |
| `unflag` | denied | allowed | allowed | allowed |
| `add_label` | denied | allowed | allowed | allowed |
| `remove_label` | denied | allowed | allowed | allowed |
| `list_labels` | allowed | allowed | allowed | allowed |
| `move_message` | denied | allowed | allowed | allowed |
| `create_draft` | denied | allowed | allowed | allowed |
| `send_email` | denied | denied | allowed | allowed |
| `delete_message` | denied | denied | allowed | allowed |
| `create_folder` | denied | denied | allowed | allowed |
| `rename_folder` | denied | denied | allowed | allowed |
| `expunge` | denied | denied | denied | allowed |
| `delete_folder` | denied | denied | denied | allowed |

`use_account` and `list_accounts` are infrastructure tools that bypass
posture checks entirely and are always available.

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

## Tool advertisement

Tools denied by the effective matrix (posture + overrides) are **not
advertised** via the MCP `list_tools` response. Denial is enforced at
both discovery and dispatch (defense in depth).

## Folder safety (full and destructive postures)

- `protected_folders` (default: INBOX, Sent, Drafts, Trash) blocks
  `rename_folder` and `delete_folder` on critical folders.
- `expunge_folders` (default empty = deny all) is an allowlist for
  `expunge` and `delete_folder`.

## `$PendingReview` flag

In `draft-safe` and above, `create_draft` appends messages to the
Drafts folder with the `\Draft` flag and a `$PendingReview` keyword.
This acts as a human-in-the-loop gate: the agent can compose a draft,
but a human must review and send it from their mail client.
