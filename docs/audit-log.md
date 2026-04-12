# Audit Log

rusty-imap-mcp maintains an append-only JSONL audit log at the path
configured in `[audit].path`. Every tool invocation, authentication
attempt, and process lifecycle event is recorded.

## Format

One JSON object per line (JSONL). Every record shares a common header:

```json
{
  "seq": 42,
  "ts": "2026-04-07T14:22:01.234Z",
  "process_id": "01JX...",
  "kind": "tool_start"
}
```

| Field | Description |
|---|---|
| `seq` | Per-process monotonic sequence number, starting at 1 |
| `ts` | RFC 3339 timestamp, millisecond precision, UTC |
| `process_id` | ULID generated at process start, stable for the process lifetime |
| `kind` | Record type discriminator |

## Record types

### `process_start`

First record of every process invocation.

| Field | Description |
|---|---|
| `version` | Semver of the running binary |
| `git_commit` | Build-time git SHA (empty until wired) |
| `posture` | Effective base posture at startup |
| `config_path` | Absolute path of the loaded config file |
| `config_hash_sha256` | SHA-256 hex of the config file contents at load time |
| `previous_last_seq` | Last `seq` found in the file at startup (null if empty) |
| `previous_process_id` | Process ID of the previous run (null if empty) |
| `previous_file_inode` | Inode of the audit file as observed at open time |
| `audit_file_inode_changed` | True if the inode differs from the prior `process_start`'s inode (tamper signal) |

### `process_end`

Best-effort record on SIGINT, SIGTERM, or stdin EOF. A hard crash
leaves no `process_end` -- the last record will be whatever was most
recently flushed.

| Field | Description |
|---|---|
| `reason` | One of `signal_int`, `signal_term`, `eof`, `error` |
| `total_tool_calls` | Number of tool calls dispatched in this process |

### `auth`

IMAP authentication attempt.

| Field | Description |
|---|---|
| `result` | `success` or `failure` |
| `host` | IMAP host attempted |
| `port` | IMAP port attempted |
| `username` | Login identity (never contains credentials) |
| `tls_fingerprint_sha256` | Observed TLS certificate fingerprint (null if handshake did not complete) |
| `fingerprint_match` | Whether observed fingerprint matched config (null if no pin configured) |
| `error_code` | Stable error code on failure (e.g. `ERR_TLS`, `ERR_AUTH`); null on success |

### `tool_start`

Recorded before dispatch begins. If the process crashes mid-call, this
record survives as a breadcrumb.

| Field | Description |
|---|---|
| `tool` | Tool name (e.g. `fetch_message`) |
| `posture_effective` | Effective posture at dispatch time |
| `arguments_redacted` | Redacted arguments (untrusted content replaced with `"<redacted:length>"`, recipient addresses hashed, passwords never logged) |
| `arguments_hash_sha256` | SHA-256 hex of the unredacted arguments for integrity |

### `tool_end`

Recorded after dispatch completes.

| Field | Description |
|---|---|
| `start_seq` | `seq` of the paired `tool_start` record |
| `tool` | Tool name (duplicated for self-contained log lines) |
| `status` | `ok` or `error` |
| `error_code` | Stable error code on failure; null on success |
| `duration_ms` | Wall-clock duration in milliseconds |
| `result_summary.message_ids_returned` | Message-ID values returned to the caller |
| `result_summary.bytes_returned` | Approximate bytes returned (post-truncation) |
| `result_summary.truncated` | Whether the result was truncated |
| `result_summary.security_warnings_emitted` | Warning codes emitted (e.g. `LOOKALIKE_SENDER_MIXED_SCRIPT`) |
| `provenance.window_seconds` | Configured provenance window |
| `provenance.message_ids_recently_read` | Message IDs read by this process within the window |

### `config`

Config-related event. Declared for future use.

| Field | Description |
|---|---|
| `path` | Config file path |
| `hash_sha256` | SHA-256 hex of the config file contents |

## File handling

- **Permissions:** audit file is created with mode `0600`. Parent
  directory is created with mode `0700` if missing.
- **Exclusive lock:** the process acquires a non-blocking exclusive
  advisory lock (`flock(LOCK_EX | LOCK_NB)`) on the audit file at
  startup. A second process against the same path fails immediately
  with `ERR_CONFIG`. The lock is held for the full process lifetime
  and released on exit.
- **Write discipline:** each record is one `write_all` + buffer flush.
  `fsync` is called after `process_start`, `process_end`, `auth`, and
  `config` records. `tool_start` and `tool_end` are flushed but not
  fsync'd (a crash may lose a few trailing entries).
- **Write failure:** fails the tool call with `ERR_INTERNAL` by
  default. Set `audit.fail_open = true` to suppress write failures
  and continue (not recommended -- audit records will be lost).

## Rotation

When the active file exceeds `audit.rotate_bytes` (default 10 MiB),
rotation occurs under the exclusive lock:

1. The active file is renamed (e.g. `audit.jsonl.1`)
2. A new active file is created and locked
3. Excess rotated files beyond `audit.rotate_keep` (default 5) are
   deleted

`rotate_keep` is a count-based cap. Under low write volumes a single
rotated file may span a long time period. Operators needing time-based
retention should configure external log rotation as well.

Set `rotate_bytes = 0` to disable rotation entirely.

## `audit merge` subcommand

```
rusty-imap-mcp audit merge [options] <path>
```

Reads the audit file with a shared lock and streams JSONL to stdout.
Output is canonical JSON (re-serialized via `serde_json`) and can be
piped to `jq`.

### Filters

| Flag | Description |
|---|---|
| `--since <RFC3339>` | Only records at or after this timestamp |
| `--until <RFC3339>` | Only records at or before this timestamp |
| `--tool <name>` | Only `tool_start`/`tool_end` records for this tool |
| `--kind <kind>` | Only records of this kind (e.g. `auth`, `tool_end`) |
| `--process <ulid>` | Only records from this process ID |

Trailing malformed lines (from a mid-record crash) produce a stderr
warning and are skipped.

### Example

```bash
rusty-imap-mcp audit merge \
  --since 2026-04-07T00:00:00Z \
  --tool fetch_message \
  ~/.local/state/rusty-imap-mcp/audit.jsonl \
  | jq '.result_summary'
```

### File permissions for merged output

`audit merge` writes to stdout. When redirected to a file, the output
inherits the shell's umask, which is typically `0022` (producing
world-readable `0644`). The source audit file is `0600`, so the merged
output may have weaker permissions than expected.

Recommended patterns:

```bash
# Set a tight umask in the same shell invocation (the && is required)
umask 077 && rusty-imap-mcp audit merge ... > dump.jsonl

# Preferred in scripts: atomic mode-set via install, no umask dependency
rusty-imap-mcp audit merge ... \
  | install -m 0600 /dev/stdin /target/dump.jsonl
```

## Startup self-check

Before writing the first `process_start` record, the server:

1. Verifies the audit file is writable (creates it if missing)
2. Reads the last line of the existing file and extracts `seq` and
   `process_id`, recording them as `previous_last_seq` and
   `previous_process_id` in the new `process_start` (chains history
   across restarts)
3. Records the file's current inode. If the file was deleted and
   recreated between runs, the inode differs and
   `audit_file_inode_changed` is set to `true` as a tamper signal

## What is not logged

- Full message bodies or HTML
- Passwords, tokens, keychain internals
- Config file contents (only path + hash)
- IMAP wire-level traffic (use `tracing` stderr logs for debugging)
