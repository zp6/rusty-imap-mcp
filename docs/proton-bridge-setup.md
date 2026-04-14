# Proton Bridge Setup

rusty-imap-mcp's primary target is Proton Mail via
[Proton Bridge](https://proton.me/mail/bridge), which exposes a local
IMAP/SMTP server on `127.0.0.1` with a self-signed TLS certificate.

## Prerequisites

1. Install Proton Bridge from <https://proton.me/mail/bridge>
2. Sign in and enable Bridge IMAP
3. Note the bridge password (displayed in Bridge settings -- this is
   not your Proton account password)

## Capture the TLS fingerprint

Proton Bridge uses a self-signed certificate. Pin the certificate
fingerprint in the config file so the server can verify it.

```bash
openssl s_client -connect 127.0.0.1:1143 < /dev/null 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}'
```

This prints a 64-character hex string. Copy it into your config file.

The fingerprint changes when Proton Bridge regenerates its certificate
(e.g. after a Bridge update or reinstall). If the server fails to
connect with `ERR_TLS`, recapture the fingerprint.

## Store credentials

Store the IMAP password:

```bash
rusty-imap-mcp login
```

This prompts for the IMAP password interactively and stores it in the
OS keychain under service `rusty-imap-mcp`, account
`<username>@127.0.0.1`. Use the bridge password from step 3, not your
Proton account password.

For SMTP (if using `send_email` in `full` posture), the same bridge
password is used. Store it for the SMTP host:

```bash
RUSTY_IMAP_MCP_PASSWORD=<bridge-password> rusty-imap-mcp login
```

Alternatively, set `RUSTY_IMAP_MCP_PASSWORD` for headless environments
(applies to both IMAP and SMTP).

## Config file

### Single-account

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "dave@proton.me"
tls_fingerprint_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

[smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "dave@proton.me"

[security]
posture = "draft-safe"

[audit]
path = "/home/dave/.local/state/rusty-imap-mcp/audit.jsonl"
```

### Multi-account

```toml
[[accounts]]
name = "proton"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "dave@proton.me"
tls_fingerprint_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

[accounts.smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "dave@proton.me"

[audit]
path = "/home/dave/.local/state/rusty-imap-mcp/audit.jsonl"
```

Replace `username` with your Proton email address and
`tls_fingerprint_sha256` with the output from the openssl command above.

## Verify with --dry-run

Test the configuration without starting the MCP server:

```bash
rusty-imap-mcp --dry-run
```

This validates the config, resolves credentials, and attempts an IMAP
connection (including TLS fingerprint verification), then exits. A
successful run prints the account summary and server capabilities.

## Known quirks

### Self-signed certificate

Proton Bridge generates a self-signed TLS certificate. Without
`tls_fingerprint_sha256`, the server will reject the connection because
the certificate is not in the system trust store. Fingerprint pinning
is required.

### Folder naming

Proton Bridge maps Proton's label system to IMAP folders. Folder names
may differ from what you see in the Proton web interface. Use
`list_folders` to discover the actual IMAP folder names.

Common mappings:
- `INBOX` -- Inbox
- `Drafts` -- Drafts
- `Sent` -- Sent
- `Trash` -- Trash
- `Archive` -- Archive
- `Spam` -- Spam
- Labels appear as top-level folders under `Labels/`
- Subfolders appear under `Folders/`

### MOVE support

Proton Bridge supports the IMAP MOVE extension. `move_message` uses
MOVE directly rather than the COPY+STORE+EXPUNGE fallback.

### Bridge password vs. account password

The IMAP/SMTP password is the bridge-specific password displayed in
Proton Bridge settings, not your Proton account password. Using the
wrong password results in `ERR_AUTH`.

### SMTP port

Proton Bridge typically uses port 1025 for SMTP with STARTTLS. The
exact port is shown in Bridge settings.

### Timeouts

The default `connect_timeout_seconds` of 10 and
`command_timeout_seconds` of 30 work well with Proton Bridge. If
Bridge is slow to start or your mailbox is large, you may need to
increase `command_timeout_seconds`.
