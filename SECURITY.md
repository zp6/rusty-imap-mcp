# Security Policy

## Reporting a vulnerability

Please report security issues by opening a private security advisory on GitHub:
<https://github.com/randomparity/rusty-imap-mcp/security/advisories/new>

Do not report security issues in public issues, discussions, or pull requests.

You can expect an initial response within one week. Coordinated disclosure is
appreciated — we will work with you to understand the issue, prepare a fix, and
credit you in the release notes if you want credit.

## Threat model summary

The primary adversary is a crafted email that, when read by an agent through this
MCP server, attempts to induce the agent to take a harmful action: exfiltrate data,
send mail on the attacker's behalf, modify mailbox state, or pivot to other tools.
Secondary adversaries include a hostile IMAP server (MITM, malformed responses)
and local malware with the user's file-system privileges.

**The server does not trust:** email bodies, headers, sender addresses, display
names, attachment filenames, link targets, or any server-provided content. These
are parsed, sanitized, tagged, and structurally separated from server-controlled
metadata before being returned to an MCP client.

**The server does trust:** its own configuration file, its own keychain entries,
its own audit log, and (within limits defined by fingerprint pinning) the TLS
identity of its configured IMAP server.

For the full threat model and defenses, see
[`docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`](docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md),
especially Sections 1, 6, 7, 8, 9, and 10.

## Supported versions

During pre-v1 development, only the latest commit on `main` is supported. Once
v1.0.0 ships, a supported-versions table will appear here.
