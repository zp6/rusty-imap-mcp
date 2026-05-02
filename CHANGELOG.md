# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **audit (security, minor-breaking):** `AuditWriter::open` now rejects a
  symlinked, wrong-owned, or non-`0700` audit parent directory. Operators
  whose deployment scripts symlink the audit dir or relied on the previous
  best-effort chmod must migrate to a real `0700` directory owned by the
  running user before upgrade. The strict TOCTOU-safe check is the same
  primitive the daemon already enforces on its socket directory (#147).
- **Breaking (keyring):** Credential keyring entries are now namespaced by
  account id (`<account-id>/<username>@<host>`) to prevent collisions in
  multi-account deployments (#77). Existing entries under the legacy
  `<username>@<host>` key continue to resolve via a transparent fallback
  that emits a `tracing::warn!` — run
  `rusty-imap-mcp migrate-keyring --account <id> --host <h> --username <u>`
  once per account to migrate.
- `rusty-imap-mcp login` gains a `--account <id>` argument (default
  `default`), so multi-account deployments can store credentials under
  the correct namespaced key. Single-account invocations remain
  unchanged.
- `ConfigError::NoCredential` and `ConfigError::Keychain` Display strings no
  longer include the username; they now show the host and a short
  `account_tag` hash for log correlation (#76).
- **Breaking — MCP client config.** Update your MCP server config from
  `command = ".../rusty-imap-mcp"` to
  `command = ".../rusty-imap-mcp", args = ["shim"]`. Bare invocation
  (previously ran the stdio server) now prints help and exits non-zero.
- **Rate limits are now per-account, shared across all sessions on that
  account.** Previously two simultaneous stdio processes each got the full
  `commands_per_second` budget; now they share it — matching the limit's
  intent of protecting the IMAP server.
- Circuit breaker state is likewise shared per-account across sessions.

### Added

- `[defaults.credentials]` / `[[accounts.credentials]]` TOML section with a
  `fallback` knob (`keyring-only` vs `keyring-then-env`, default
  `keyring-then-env`). Setting `keyring-only` disables the
  `RUSTY_IMAP_MCP_PASSWORD` env-var fallback for multi-account deployments
  where a shared fallback would cross account boundaries (#78).
- Audit records of kind `auth` now include a `credential_source` field
  (`keyring` / `legacy_keyring` / `env_var`) for post-incident analysis.
- `rusty-imap-mcp migrate-keyring` CLI subcommand to migrate credentials
  from the legacy keyring key format to the new namespaced format.
- **Multi-client daemon.** `rusty-imap-mcp daemon` runs a long-lived server;
  `rusty-imap-mcp shim` is the new stdio↔socket adapter that MCP clients
  (Claude Code, Codex, etc.) invoke via `args = ["shim"]`. Multiple MCP
  clients on the same user can now coexist without fighting for the audit lock.
- New audit record kinds `session_start` and `session_end`; `tool_start` /
  `tool_end` / `auth` gain `session_id` where session-scoped.
- Packaging: systemd user unit and macOS launchd plist under
  `scripts/packaging/`. Windows uses the built-in
  `rusty-imap-mcp service install` subcommand (registers a User Service
  Template via SCM; requires Administrator).

### Migration

Start the daemon once (systemd/launchd on Linux/macOS,
`rusty-imap-mcp service install` on Windows — see `README.md`'s
"Running the daemon" section), then update every MCP client's config
to invoke the shim. No config-file changes required.

## [1.0.0] - 2026-04-13

### Added

#### Multi-account support

- Multiple IMAP/SMTP accounts in a single server process via `[[accounts]]`
  config array with per-account posture, rate limits, and SMTP settings.
- `use_account` tool to set the session-scoped default account.
- `list_accounts` tool to enumerate configured accounts with posture and
  SMTP status.
- MCP resource discovery: `rimap://accounts/<name>` exposes account
  metadata (host, posture, available tools) without credentials.
- Account resolution: explicit `account` parameter > session default >
  auto-select (single account) > error.
- Full backward compatibility: existing single-account `[imap]` configs
  work unchanged as a synthetic `"default"` account.

#### MCP tools (22 posture-gated + 2 infrastructure)

**Read operations (all postures):**

- `list_folders` -- IMAP folder listing with message counts
- `search` -- structured query builder (from, to, subject, date range)
- `fetch_message` -- message fetch with text body extraction
- `list_attachments` -- attachment metadata for a message
- `download_attachment` -- download attachment by part index
- `list_labels` -- list custom IMAP keyword flags on a message

**Mutation operations (draft-safe and above):**

- `mark_read` / `mark_unread` -- set or clear `\Seen` flag
- `flag` / `unflag` -- set or clear `\Flagged` flag
- `add_label` / `remove_label` -- add or remove custom IMAP keyword flags
- `move_message` -- move message between folders
- `create_draft` -- append to Drafts with `$PendingReview` keyword

**Full posture operations:**

- `search_advanced` -- raw IMAP SEARCH query passthrough
- `fetch_message_html` -- sanitized HTML body alongside text
- `send_email` -- SMTP send with Sent folder copy
- `delete_message` -- flag `\Deleted` and move to Trash
- `create_folder` / `rename_folder` -- IMAP folder management

**Destructive posture operations:**

- `expunge` -- permanently remove `\Deleted` messages (folder allowlist)
- `delete_folder` -- permanently remove folder (folder allowlist +
  protected folder check)

**Infrastructure tools (always available):**

- `use_account` -- switch active account context
- `list_accounts` -- list configured accounts

#### Security postures

Four authorization tiers with per-tool overrides:

| Posture | Scope |
|---------|-------|
| `readonly` | Read-only: list, search, fetch, download |
| `draft-safe` | Read + safe mutations: flags, moves, drafts (default) |
| `full` | All above + send, delete, folder management, HTML, advanced search |
| `destructive` | All above + expunge, delete_folder |

Tools denied by the active posture are not advertised via `list_tools`.
Per-tool `"allow"` / `"deny"` overrides merge on top of the posture.

#### Content pipeline

- RFC 5322 / MIME parsing via `mail-parser`
- Charset decoding via `encoding_rs`
- NFKC Unicode normalization
- Invisible/ambiguous codepoint stripping (zero-width chars, bidi
  overrides, C0/C1 controls)
- HTML-to-text conversion with hidden-content stripping (CSS
  `display:none`, `visibility:hidden`, `opacity:0`, white-on-white)
- Sanitized HTML output via `ammonia` (conservative allowlist)
- Link text/href domain mismatch detection
- Look-alike detection: mixed-script, confusable skeleton matching,
  display-name spoofing, reply-to domain mismatch, filename bidi tricks
- Attachment filename sanitization (path separators, leading dots,
  Windows reserved names, length truncation)
- Structured response envelope: `meta` (trusted), `untrusted`
  (sanitized), `security_warnings` (server assessment)

#### SMTP sending

- `rimap-smtp` crate wrapping `lettre` with rustls TLS
- STARTTLS (port 587), implicit TLS (port 465), and plaintext modes
- Per-send connection lifecycle (no pooling)
- Automatic Sent folder copy via IMAP APPEND after send
- `sends_per_minute` rate limit (default 3)

#### Audit log

- Append-only JSONL audit log with exclusive OS advisory file lock
- Every tool call produces `tool_start` + `tool_end` records linked by
  sequence number
- Content provenance ring buffer: recently-read message IDs snapshotted
  into every `tool_end` record
- Account name tagged on every record in multi-account configs
- Size-based rotation with configurable count and time-based retention
- `audit merge` subcommand with `--account` filter and `--since` /
  `--until` time range
- `fail_open = false` default: audit write failures fail the tool call

#### Folder safety

- `protected_folders` list (default: INBOX, Sent, Drafts, Trash) --
  blocks rename and delete on protected folders
- `expunge_folders` allowlist (default empty = deny all) -- required for
  `expunge` and `delete_folder`
- `create_folder` rejects names colliding with protected folders

#### Rate limiting and circuit breaker

- Token-bucket rate limiter: `commands_per_second` (default 10) with
  burst of 20
- Separate `drafts_per_minute` (default 5) and `sends_per_minute`
  (default 3) limits
- Sliding-window circuit breaker: closed > open > half-open state
  machine
- Auth failures trip immediately (single failure opens for 60s)
- Exponential backoff cooldown (doubled per re-trip, capped at 5 min)

#### TLS fingerprint pinning

- SHA-256 certificate fingerprint pinning for self-signed certs (e.g.
  Proton Bridge)
- Verified before any application data flows
- Hard failure on mismatch -- no fallback to system trust store when
  pinning is configured

#### Labels

- IMAP keyword-based labels via `STORE +FLAGS` / `-FLAGS`
- `add_label`, `remove_label`, `list_labels` tools
- Label validation: max 256 bytes, IMAP atom charset, no system flag
  namespace (`\` prefix rejected)

#### Platform support

Pre-built binaries for five targets:

- `x86_64-unknown-linux-gnu` (native)
- `aarch64-unknown-linux-gnu` (cross-compiled)
- `aarch64-apple-darwin` (native macOS)
- `powerpc64le-unknown-linux-gnu` (QEMU emulation)
- `s390x-unknown-linux-gnu` (QEMU emulation)

#### Development toolchain

- Cargo workspace with 8 member crates
- MSRV 1.88.0 (edition 2024), dev toolchain 1.94.0
- SHA-pinned GitHub Actions CI (fmt, clippy, test, MSRV, cargo-deny,
  zizmor, SonarQube)
- Release workflow triggered on `v*` tags with SHA256 checksums
- `prek` pre-commit hooks (fmt, clippy, shellcheck, actionlint, zizmor,
  typos)
- `cargo-deny` supply-chain audit (advisories, licenses, bans, sources)
- `cargo-nextest` test runner
- Property-based tests via `proptest`, snapshot tests via `insta`
- Adversarial email injection corpus
- `justfile` with `just ci` as the local-CI equivalent
- Dual MIT / Apache-2.0 license

### Security Hardening (post-review)

- Namespace MCP tool names per account (`<account>.<tool>`) in multi-account
  configs to prevent cross-account posture bypass. Single-account configs
  with the synthetic `"default"` account keep bare tool names.
- Emit `tool_start` and `tool_end` audit records for every dispatch with
  account attribution, redacted arguments, and duration metadata.
- Populate `account` field on `Auth` audit records for multi-account
  attribution of login events.
- Wrap resolved credentials in `secrecy::SecretString` to limit in-memory
  exposure of IMAP and SMTP passwords.
- Redact IMAP/SMTP usernames from `anyhow` error contexts so they no longer
  leak into tracing output.
- Reject IMAP/SMTP usernames containing CR, LF, or NUL bytes at config load.
- Rate-limit infrastructure tools (`use_account`, `list_accounts`) to
  prevent session-state flip-flap attacks.
- Validate account names via `AccountId::new` before echoing them in
  MCP error messages to prevent reflected-content amplification.
- Drop `posture` from `read_resource` body and `imap_host` from
  `list_accounts` response to reduce attack-surface fingerprinting.
- Require labels to be ASCII (RFC 3501 atom syntax) and reject `[`
  consistently at both validator layers to prevent homograph/bidi spoofing.
- Digest-pin the Rust Docker base image used for ppc64le/s390x release
  builds to resist tag-repointing supply-chain attacks.
- Pin `cross` version in release workflow.
- Embed SBOMs in native release binaries via `cargo-auditable`.
- Add SLSA build provenance attestation to release artifacts and
  `SHA256SUMS.txt` via `actions/attest-build-provenance`.
- Extract per-tag release notes from `CHANGELOG.md` rather than attaching
  the entire changelog to every release.
- Document GitHub tag protection and release environment setup.
- Create per-process attachment tempdir with `0700` permissions on Unix
  to close a symlink/TOCTOU race on shared `/tmp`.
- Replace `Mutex<Option<AccountId>>` in the account registry with
  `ArcSwapOption` to eliminate async-refactor footguns and mutex poisoning.
