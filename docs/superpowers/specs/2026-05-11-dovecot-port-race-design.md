# Dovecot Integration Test Port-Race Fix

Date: 2026-05-11
Status: Approved (pending implementation plan)

## Summary

The dovecot integration suite in `crates/rimap-imap/tests/integration/`
flakes under nextest parallelism because `pick_free_port` releases its
TCP listener before docker can bind the kernel-assigned port. CI run
`25691882071` failed with `Bind for 127.0.0.1:35615 failed: port is
already allocated` mid-suite. The author flagged the race in a doc
comment but accepted it; the observed failure rate disproves the
acceptance.

This change closes the race by holding the listener until the moment
docker is invoked, and adds a bounded retry loop that handles the
residual collision window. A `ComposeRunner` trait makes the retry
logic unit-testable without a real docker.

## Goals

- Eliminate the bind race that produces the recurrent CI failure.
- Keep the change small and local to the integration harness — no
  changes to production code or to other test suites.
- Add deterministic test coverage so the retry logic survives future
  refactors.
- Improve diagnostic output for failed `compose up` calls (stderr was
  previously discarded).

## Non-goals

- Tightening `STALE_PROJECT_AGE` (30 min). The current threshold
  protects parallel runs; changing it needs measurement.
- Wiring the dormant SMTP compose harness — it has no Rust consumer
  yet. When it lands, it should reuse `ReservedPort` and the retry
  wrapper.
- A process-wide port-lease file. Brainstormed as option C; deferred
  unless the retry pattern still flakes.
- Reducing nextest's parallelism floor. Orthogonal to the bind race.
- Changes to the `restart()` code path. It reuses an already-bound
  port and does not traverse the race.

## Architecture

### ReservedPort

Replace `pick_free_port() -> Result<u16, HarnessError>` with a
`ReservedPort` type that owns the listener for the lifetime of the
reservation:

```rust
struct ReservedPort {
    port: u16,
    listener: Option<TcpListener>,
}

impl ReservedPort {
    fn acquire() -> Result<Self, HarnessError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| HarnessError::PortReadFailed(format!("bind: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| HarnessError::PortReadFailed(format!("local_addr: {e}")))?
            .port();
        Ok(Self { port, listener: Some(listener) })
    }

    fn port(&self) -> u16 { self.port }

    /// Release the kernel-level port lease. After this, docker can
    /// bind the port. Idempotent.
    fn release(&mut self) { self.listener.take(); }
}
```

The harness holds two `ReservedPort` values across the call to
`compose_up_with_retry`. The wrapper releases both immediately before
invoking docker — narrowing the race window from indefinite to a few
microseconds.

### Retry wrapper

```rust
fn compose_up_with_retry(
    runner: &dyn ComposeRunner,
    project: &str,
    compose_dir: &Path,
    tls: &mut ReservedPort,
    starttls: &mut ReservedPort,
) -> Result<(), HarnessError> {
    const BACKOFF_MS: [u64; 2] = [50, 250];
    let mut last_collision: Option<String> = None;

    for attempt in 0..=BACKOFF_MS.len() {
        tls.release();
        starttls.release();
        let result = runner.up(project, compose_dir, tls.port(), starttls.port());
        match result {
            Ok(()) => return Ok(()),
            Err(HarnessError::DockerCommandFailed(s)) if is_port_collision(&s) => {
                last_collision = Some(s);
                if attempt == BACKOFF_MS.len() {
                    break;
                }
                // Tear down partial project + back off + reacquire fresh ports.
                compose_down(project, compose_dir);
                std::thread::sleep(Duration::from_millis(BACKOFF_MS[attempt]));
                *tls = ReservedPort::acquire()?;
                *starttls = ReservedPort::acquire()?;
            }
            Err(e) => return Err(e),
        }
    }
    Err(HarnessError::DockerCommandFailed(format!(
        "compose up: exhausted {} attempts on port collision; last error: {}",
        BACKOFF_MS.len() + 1,
        last_collision.unwrap_or_else(|| "<no error captured>".into()),
    )))
}
```

Three attempts total (initial + 2 retries). Backoffs of 50 ms and 250 ms
cover the typical kernel-scheduling gap. After the loop, the most
recent collision error is replaced with a clearer
"exhausted retries" message; non-collision errors propagate unchanged
on the first failure.

The `unreachable!()` form is avoided so the workspace's
`clippy::unreachable = "deny"` lint stays clean.

### Stderr capture

`compose_up` currently uses `Command::...status()`, which discards
stdout/stderr. To classify a collision the wrapper needs stderr text.

Switch to `Command::...output()` and fold stderr into the error
payload:

```rust
let output = Command::new(runtime())
    .arg("compose").arg("-p").arg(project).arg("up").arg("-d")
    .env("RIMAP_DOVECOT_HOST_PORT", host_port.to_string())
    .env("RIMAP_DOVECOT_HOST_PORT_STARTTLS", host_starttls_port.to_string())
    .current_dir(compose_dir)
    .output()
    .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))?;
if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    return Err(HarnessError::DockerCommandFailed(
        format!("compose up exit {}: {stderr}", output.status),
    ));
}
```

This is an unconditional improvement to diagnostics independent of the
race fix.

### ComposeRunner trait

```rust
trait ComposeRunner {
    fn up(
        &self,
        project: &str,
        compose_dir: &Path,
        tls_port: u16,
        starttls_port: u16,
    ) -> Result<(), HarnessError>;
}

struct DockerComposeRunner;

impl ComposeRunner for DockerComposeRunner {
    fn up(&self, project: &str, compose_dir: &Path, tls: u16, starttls: u16)
        -> Result<(), HarnessError>
    {
        // Body is the current compose_up function logic, with the
        // stderr-capturing change from above.
        ...
    }
}
```

`try_start` instantiates `DockerComposeRunner` and passes it to
`compose_up_with_retry`. The trait exists solely so unit tests can
substitute a flaky double.

### Port-collision classifier

```rust
fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for")
}
```

The three substrings cover the docker engine error (the one observed
in CI), the standard libc EADDRINUSE message, and podman's variant.

## Data flow

```
ReservedPort::acquire (TLS)
ReservedPort::acquire (STARTTLS)
              │
              ▼
   compose_up_with_retry(runner, project, dir, &mut tls, &mut starttls)
   ┌───────────────────────────────┐
   │ loop:                         │
   │   tls.release();              │
   │   starttls.release();         │
   │   runner.up(...)              │
   │   ┌── Ok → return Ok          │
   │   ├── Err(collision)          │
   │   │   ├── compose_down        │
   │   │   ├── sleep(backoff)      │
   │   │   └── reacquire ports     │
   │   └── Err(other) → return Err │
   └───────────────────────────────┘
              │
              ▼
   wait_for_ready → returns harness
```

## Error handling

| Path                                        | Outcome                                |
|---------------------------------------------|----------------------------------------|
| First `compose up` succeeds                 | Return Ok; reservations dropped        |
| 1st attempt fails (port collision)          | Tear down, sleep 50 ms, retry          |
| 2nd attempt fails (port collision)          | Tear down, sleep 250 ms, retry         |
| 3rd attempt fails (port collision)          | Return "exhausted attempts" + last stderr |
| Any attempt fails (non-collision error)     | Return immediately, original payload   |
| `ReservedPort::acquire` fails inside retry  | Propagate as `PortReadFailed`          |

`compose_down` between retries uses the existing helper, which is
already best-effort silent.

## Testing strategy

Three unit tests in `crates/rimap-imap/tests/integration/support/container.rs`
(behind `#[cfg(test)]`), driven by a `FlakyComposeRunner` double.

1. **Retry-then-succeed.** Runner fails the first two attempts with a
   collision message, succeeds on the third. Assert: result is `Ok`;
   runner saw three distinct attempts; each attempt used a fresh
   `(tls_port, starttls_port)` pair (proves the reacquire path).

2. **Give up after max attempts.** Runner always fails with a
   collision message. Assert: result is `Err(DockerCommandFailed)`
   whose message contains both "exhausted" and the underlying stderr
   substring; runner saw exactly three attempts.

3. **Non-collision errors don't retry.** Runner fails with a generic
   "unrelated docker error" message. Assert: result is `Err`; runner
   saw exactly one attempt.

The tests live in the same `support/container.rs` module so they
run under `cargo test -p rimap-imap` without requiring docker.
`FlakyComposeRunner` records every observed call in a
`Mutex<Vec<(u16, u16)>>` for assertion.

`#[expect(clippy::expect_used, reason = "tests")]` /
`#[expect(clippy::unwrap_used, reason = "tests")]` at module scope
already cover the test-time `.expect()` / `.unwrap()` calls these
tests will use.

## Migration / rollout

Single PR. The change is local to one file (`support/container.rs`).
The dovecot integration suite continues to skip silently on hosts
without docker (`HarnessError::DockerUnavailable`) — that path is
untouched.

Order within the PR (informs the implementation plan):

1. Switch `compose_up` to `Command::...output()` and fold stderr into
   the error payload.
2. Add `is_port_collision`.
3. Introduce `ReservedPort` with `release()`; migrate `try_start` to
   hold listeners across `compose_up`.
4. Extract the compose-up logic into a `ComposeRunner` trait with
   `DockerComposeRunner` production impl.
5. Implement `compose_up_with_retry`; wire it into `try_start`.
6. Add `FlakyComposeRunner` and the three unit tests.
7. Run `just ci` locally; push; verify the MSRV lane goes green over
   multiple consecutive runs.

Each step is independently committable.

## Open questions

None at design time. The implementation plan will address the exact
placement of the `ComposeRunner` trait (whether it sits next to
`DovecotHarness` or in a small sub-module), and the wording of the
final "exhausted retries" error message.
