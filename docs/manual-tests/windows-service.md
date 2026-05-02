# Manual smoke checklist — Windows Service (issue #129)

Run on a Windows 10 (1703+) or Windows 11 host with a logged-in user.

## Setup

- Install the daemon binary at a stable path, e.g.
  `%LOCALAPPDATA%\Programs\rusty-imap-mcp\rusty-imap-mcp.exe`.
- Have a valid config file at a stable path, e.g.
  `%LOCALAPPDATA%\rusty-imap-mcp\config.toml`.
- Open an **elevated** PowerShell (Run as Administrator).

## Install

- [ ] `rusty-imap-mcp service install --config %LOCALAPPDATA%\rusty-imap-mcp\config.toml`
- [ ] `services.msc` shows **Rusty IMAP MCP** with status **Running** under
      the current user's account.
- [ ] `Get-Service RustyImapMcp | Format-List Name, Status, StartType` shows
      `Running` and `Automatic`.

## Lifecycle

- [ ] Connect a shim client; run a tool call. Confirm
      `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` contains tracing events
      and the audit log records a `tool_start` / `tool_end` pair.
- [ ] `sc.exe stop RustyImapMcp` returns with the service in **Stopped**
      state inside ~10 seconds.
- [ ] The audit log contains `session_end` for every active session
      and a final `process_end` record.

## Recovery

- [ ] Force a crash (kill the process from Task Manager). SCM restarts
      it within 30 s; `services.msc` returns to **Running**.

## Uninstall

- [ ] `rusty-imap-mcp service uninstall`
- [ ] `services.msc` no longer lists the service.
- [ ] `rusty-imap-mcp service uninstall` (idempotent) prints
      `service not registered; uninstall is a no-op` and exits 0.

## Cleanup

- [ ] Remove `%LOCALAPPDATA%\rusty-imap-mcp\daemon.log` and any test
      audit logs.

## Failure modes worth confirming once

- [ ] Run `rusty-imap-mcp service install` from a **non-elevated**
      shell. Expect a clear "ERROR_ACCESS_DENIED — re-run from an
      elevated shell" message.
- [ ] Run `rusty-imap-mcp service run` directly from an interactive
      shell. Expect "this verb is for the Service Control Manager — see
      `rusty-imap-mcp daemon` for foreground use" and a non-zero exit
      code.
