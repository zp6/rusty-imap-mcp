# rusty-imap-mcp

A security-first [Model Context Protocol](https://modelcontextprotocol.io/)
server for IMAP email, written in Rust. Primary target: Proton Mail via
Proton Bridge. Compatible with standard IMAP servers (Dovecot, Cyrus,
Gmail via app password, etc.).

## Why

LLM agents reading email are a target for prompt injection. A single
crafted message can contain hidden instructions that induce the agent to
send mail, leak data, or pivot to other tools. rusty-imap-mcp treats
every byte of email content as untrusted input: aggressive sanitization,
structural tagging, Unicode normalization, look-alike detection, content
provenance tracking, and posture-based authorization.

## Quick start

1. Build from source (see below) or download a binary from the
   [releases page](https://github.com/randomparity/rusty-imap-mcp/releases).

2. Create a config file:

   ```toml
   [imap]
   host = "127.0.0.1"
   port = 1143
   username = "you@proton.me"
   tls_fingerprint_sha256 = "..."  # see docs/quickstart-proton-bridge.md

   [audit]
   path = "~/.local/state/rusty-imap-mcp/audit.jsonl"
   ```

   Place it at `~/.config/rusty-imap-mcp/config.toml` (Linux) or
   `~/Library/Application Support/rusty-imap-mcp/config.toml` (macOS).

3. Store the IMAP password:

   ```bash
   rusty-imap-mcp login
   ```

4. Test the connection:

   ```bash
   rusty-imap-mcp --dry-run
   ```

5. Add to your MCP client (e.g. Claude Desktop):

   ```json
   {
     "mcpServers": {
       "email": {
         "command": "rusty-imap-mcp"
       }
     }
   }
   ```

## Security postures

Four tiers control which tools are available. The default is
`draft-safe`.

| Posture | Scope |
|---------|-------|
| `readonly` | List, search, fetch, download. No mutations. |
| `draft-safe` | Read + flags, moves, labels, drafts with `$PendingReview`. No SMTP. Default. |
| `full` | All above + send, delete, folder management, HTML bodies, advanced search. |
| `destructive` | All above + expunge, delete_folder. |

Tools denied by the active posture are not advertised via `list_tools`
and are rejected at dispatch. Per-tool `"allow"` / `"deny"` overrides
are supported.

See [docs/security-model.md](docs/security-model.md) for the full
22-tool x 4-posture matrix and threat model.

## Multi-account

Multiple accounts are supported in a single server process:

```toml
[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
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
path = "~/.local/state/rusty-imap-mcp/audit.jsonl"
```

Agents discover accounts via MCP resources
(`rimap://accounts/<name>`) and select them with the `use_account`
tool or per-call `account` parameter. Each account has independent
posture, rate limits, and circuit breaker.

Existing single-account configs work unchanged.

See [docs/multi-account.md](docs/multi-account.md).

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

## Build from source

```bash
# Clone and build
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo build --release

# Binary at target/release/rusty-imap-mcp
```

Requires Rust 1.88.0+ and `libdbus-1-dev` (Linux) or equivalent.

### Development

```bash
just setup    # install required tooling and pre-commit hooks
just ci       # run the full local-CI equivalent (fmt, clippy, test, MSRV, deny, typos)
```

MSRV is 1.88.0, verified independently in CI. Dev toolchain is 1.94.0,
pinned in `rust-toolchain.toml`.

## Pre-built binaries

Binaries are published for five targets on each
[release](https://github.com/randomparity/rusty-imap-mcp/releases):

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `aarch64-apple-darwin`
- `powerpc64le-unknown-linux-gnu`
- `s390x-unknown-linux-gnu`

SHA256 checksums are included with each release.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Multi-account support](docs/multi-account.md)
- [Security model and posture matrix](docs/security-model.md)
- [Proton Bridge quick start](docs/quickstart-proton-bridge.md)
- [Audit log format](docs/audit-log.md)

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and
`LICENSE-APACHE`.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure and the
threat model summary.
