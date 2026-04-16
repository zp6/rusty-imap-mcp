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
