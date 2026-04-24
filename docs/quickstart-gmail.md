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

A successful run prints the posture matrix, the active tool allowlist,
and the IMAP server's capability list (after a TLS handshake), then
exits. It does not authenticate.

**If it fails:**

| Error | Cause | Fix |
|-------|-------|-----|
| `ERR_AUTH` | Wrong password | Re-run `rusty-imap-mcp login` with the correct App Password |
| `ERR_TLS` | TLS handshake failure | Verify your network allows connections to imap.gmail.com:993 |
| `ERR_CONFIG` | Config parse error | Check TOML syntax and field names against the [configuration reference](configuration.md) |
| Config not found | Wrong file location | Verify the path matches your platform (see Step 2) or use `--config <path>` |

## Step 5: Start the daemon and add to your MCP client

Start the daemon once using your platform's service manager (see
README.md's "Running the daemon" section).

### Claude Desktop

Edit your Claude Desktop config
(`~/Library/Application Support/Claude/claude_desktop_config.json` on
macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "email": {
      "command": "rusty-imap-mcp",
      "args": ["shim"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add email rusty-imap-mcp --args shim
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
