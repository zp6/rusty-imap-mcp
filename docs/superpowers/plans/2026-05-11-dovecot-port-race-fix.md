# Dovecot Integration Test Port-Race Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the docker `compose up` port-bind race in the dovecot integration harness so `case_05_list_returns_seeded_folders` (and every other dovecot case) stops flaking under nextest parallelism.

**Architecture:** A new `ReservedPort` type owns its `TcpListener` until the moment docker is invoked, narrowing the bind race from indefinite to microseconds. A `ComposeRunner` trait abstracts the `docker compose up` shell-out so a `FlakyComposeRunner` test double can drive a bounded retry wrapper (`compose_up_with_retry`) deterministically. The wrapper handles the residual collision window with 50ms/250ms backoff and gives up after three attempts, preserving the underlying stderr.

**Tech Stack:** Rust 1.88.0 MSRV (edition 2024), `std::process::Command`, `std::net::TcpListener`, nextest, docker/podman compose.

**Spec:** [`docs/superpowers/specs/2026-05-11-dovecot-port-race-design.md`](../specs/2026-05-11-dovecot-port-race-design.md)

---

## File Map

**Modify (single file):**
- `crates/rimap-imap/tests/integration/support/container.rs` — all changes land here. The file has one responsibility (driving the dovecot compose lifecycle); the new pieces (port reservation, runner trait, retry wrapper, test double, unit tests) all serve that responsibility and do not warrant a split.

**No new files. No changes outside `container.rs`. No production-code changes.**

---

## Task 1: Capture stderr in `compose_up`

The current `compose_up` uses `Command::...status()`, which discards stdout/stderr. The retry wrapper in later tasks needs the stderr text to classify port collisions. This task does the strictly-additive diagnostic improvement first, in isolation, so the diff is clear and bisectable.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs:273-299`

- [ ] **Step 1: Switch `compose_up` to `output()` and fold stderr into the error payload**

Replace the body of `fn compose_up` (currently at lines 273–299) with:

```rust
fn compose_up(
    project: &str,
    compose_dir: &Path,
    host_port: u16,
    host_starttls_port: u16,
) -> Result<(), HarnessError> {
    let output = Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("up")
        .arg("-d")
        .env("RIMAP_DOVECOT_HOST_PORT", host_port.to_string())
        .env(
            "RIMAP_DOVECOT_HOST_PORT_STARTTLS",
            host_starttls_port.to_string(),
        )
        .current_dir(compose_dir)
        .output()
        .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HarnessError::DockerCommandFailed(format!(
            "compose up exit {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}
```

The signature is unchanged. Only the body switches from `.status()` to `.output()` and includes the trimmed stderr in the error message.

- [ ] **Step 2: Verify the workspace still compiles**

Run from the repo root:

```bash
cargo check -p rimap-imap --tests --locked
```

Expected: clean. No clippy or fmt warnings.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): capture compose-up stderr in error payload

Switch the integration-test harness's compose_up from Command::status()
to Command::output() and fold the captured stderr into the
DockerCommandFailed payload. Previously a compose failure produced an
exit-code-only message, hiding the actual docker engine error (e.g.
'port is already allocated'). Strictly additive diagnostic improvement;
no behavior change on the happy path."
```

---

## Task 2: Add `is_port_collision` classifier

The retry wrapper needs a small predicate that inspects a stderr string and decides whether it represents a port-bind collision. This is the smallest atomic unit; landing it standalone keeps the retry-wrapper task focused on control flow.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` (append a private fn near `compose_up`)

- [ ] **Step 1: Write the failing test**

Add the following test inside an existing test module in `container.rs`, OR if no such module exists yet, create one at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]
    #![expect(clippy::expect_used, reason = "tests")]
    #![expect(clippy::panic, reason = "test failure path")]

    use super::*;

    #[test]
    fn is_port_collision_matches_docker_engine_error() {
        let stderr = "Error response from daemon: failed to set up container networking: \
            driver failed programming external connectivity on endpoint rimap-it-abc-dovecot \
            (...): Bind for 127.0.0.1:35615 failed: port is already allocated";
        assert!(is_port_collision(stderr));
    }

    #[test]
    fn is_port_collision_matches_libc_eaddrinuse() {
        assert!(is_port_collision("bind: address already in use"));
    }

    #[test]
    fn is_port_collision_matches_podman_variant() {
        assert!(is_port_collision("Error: rootlessport listen tcp 127.0.0.1:1234: bind: address already in use"));
    }

    #[test]
    fn is_port_collision_rejects_unrelated_error() {
        assert!(!is_port_collision("no such image: docker.io/dovecot/dovecot:9.9.9"));
        assert!(!is_port_collision("dovecot exited with non-zero status"));
    }

    #[test]
    fn is_port_collision_is_case_insensitive() {
        assert!(is_port_collision("PORT IS ALREADY ALLOCATED"));
        assert!(is_port_collision("Bind FOR 127.0.0.1:80 failed"));
    }
}
```

Check whether `container.rs` already has a `#[cfg(test)] mod tests` block. If so, add only the five `#[test] fn` items inside that block. If not, add the whole module at the bottom of the file.

- [ ] **Step 2: Run tests to confirm they fail with "is_port_collision not defined"**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests::is_port_collision -- --nocapture 2>&1 | tail -20
```

Expected: compile error mentioning `is_port_collision` cannot be found.

- [ ] **Step 3: Add the `is_port_collision` function**

Insert this private function immediately after `fn compose_up` (it will sit near line ~300 in `container.rs`):

```rust
/// Classify a stderr blob from a failed `compose up`: `true` when the
/// failure looks like a host-port bind collision, `false` otherwise.
///
/// Covers three observed phrasings:
///   - docker engine: "Bind for 127.0.0.1:NNNN failed: port is already allocated"
///   - libc EADDRINUSE: "address already in use"
///   - podman rootlessport: "Bind for ..."
fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for")
}
```

- [ ] **Step 4: Run tests to confirm all five pass**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests::is_port_collision -- --nocapture 2>&1 | tail -15
```

Expected: `test result: ok. 5 passed; 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): is_port_collision stderr classifier + tests

Adds a small private predicate that decides whether a compose-up stderr
blob represents a host-port bind collision. Covers docker engine,
libc EADDRINUSE, and podman rootlessport phrasings; case-insensitive.
Used by the upcoming retry wrapper to decide when to retry vs.
propagate the original error."
```

---

## Task 3: Introduce `ReservedPort`

Replace the racy `pick_free_port -> u16` with a `ReservedPort` value that owns its `TcpListener` lease. The harness keeps the listeners alive across the compose-up call; the retry wrapper (Task 5) releases them at the last possible moment.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs:107-127,487-494`

- [ ] **Step 1: Write the failing tests**

Append these tests to the `#[cfg(test)] mod tests` block added in Task 2:

```rust
    #[test]
    fn reserved_port_acquires_distinct_ports() {
        let a = ReservedPort::acquire().expect("acquire a");
        let b = ReservedPort::acquire().expect("acquire b");
        assert_ne!(a.port(), b.port(), "two reservations must yield different ports");
    }

    #[test]
    fn reserved_port_release_drops_lease() {
        let mut p = ReservedPort::acquire().expect("acquire");
        let port = p.port();
        p.release();
        // After release, another bind on the same port should succeed.
        let bound_again = std::net::TcpListener::bind(("127.0.0.1", port));
        assert!(
            bound_again.is_ok(),
            "should be able to bind {port} after release: {:?}",
            bound_again.err()
        );
    }

    #[test]
    fn reserved_port_release_is_idempotent() {
        let mut p = ReservedPort::acquire().expect("acquire");
        p.release();
        p.release(); // must not panic
    }
```

- [ ] **Step 2: Run tests to confirm they fail with "ReservedPort not defined"**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests::reserved_port 2>&1 | tail -15
```

Expected: compile error.

- [ ] **Step 3: Replace `pick_free_port` with `ReservedPort`**

Locate `fn pick_free_port` (currently at lines 487–494) and replace it with the type definition below. Move it to live next to `is_port_collision` for proximity to its users.

Delete this current block:

```rust
/// Bind to `127.0.0.1:0`, read the kernel-assigned port, and drop the
/// listener. Technically racy (another process could claim the same port
/// in the gap before docker binds it) but acceptable for integration
/// tests — the port is passed immediately to `docker compose up`.
fn pick_free_port() -> Result<u16, HarnessError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| HarnessError::PortReadFailed(format!("bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| HarnessError::PortReadFailed(format!("local_addr: {e}")))?;
    Ok(addr.port())
}
```

Insert this replacement somewhere logically reasonable — placing it directly above `fn is_port_collision` works well:

```rust
/// A host port reserved by binding `127.0.0.1:0` and reading the
/// kernel-assigned number. The `TcpListener` is kept open until
/// `release()` is called, holding the kernel-level lease so docker
/// (or any other process) cannot bind the same port in the meantime.
///
/// Lifecycle: callers acquire two `ReservedPort`s, then pass `&mut`
/// references to the retry wrapper, which releases them just before
/// invoking `docker compose up`. If `compose up` fails with a port
/// collision (the residual race window), the wrapper drops the
/// reservations and acquires fresh ones for the next attempt.
struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    fn acquire() -> Result<Self, HarnessError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| HarnessError::PortReadFailed(format!("bind: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| HarnessError::PortReadFailed(format!("local_addr: {e}")))?
            .port();
        Ok(Self {
            port,
            listener: Some(listener),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Drop the underlying `TcpListener`, releasing the kernel-level
    /// port lease. Idempotent.
    fn release(&mut self) {
        self.listener.take();
    }
}
```

- [ ] **Step 4: Update `try_start` to use `ReservedPort`**

Locate the `try_start` body around lines 107–112:

```rust
let project = format!("rimap-it-{}", uuid_like());
let host_port = pick_free_port()?;
let host_starttls_port = pick_free_port()?;

compose_up(&project, &compose_dir, host_port, host_starttls_port)?;
```

Replace with:

```rust
let project = format!("rimap-it-{}", uuid_like());
let mut host_port = ReservedPort::acquire()?;
let mut host_starttls_port = ReservedPort::acquire()?;

// Release the kernel-level port leases just before docker binds them.
// The retry wrapper (next task) will move this release into a tighter
// loop; for now, release explicitly and call the plain compose_up.
host_port.release();
host_starttls_port.release();
compose_up(&project, &compose_dir, host_port.port(), host_starttls_port.port())?;
```

And update the subsequent `wait_for_ready` call and the `Ok(Self { ... })` block that uses the port numbers — replace `host_port` (now a `ReservedPort` rather than `u16`) in those expressions with `host_port.port()`:

```rust
let result = wait_for_ready(&project, &compose_dir, host_port.port(), host_starttls_port.port());
match result {
    Ok((fingerprint, port)) => Ok(Self {
        project,
        compose_dir,
        fingerprint,
        port,
        starttls_port: host_starttls_port.port(),
    }),
    Err(e) => {
        compose_down(&project, &compose_dir);
        Err(e)
    }
}
```

(The comment about "the retry wrapper (next task)" stays in the code only briefly; Task 5 removes it when wiring the wrapper in.)

- [ ] **Step 5: Verify compile + run the three reservation tests**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests::reserved_port 2>&1 | tail -10
```

Expected: 3 passed.

- [ ] **Step 6: Verify the full unit-test suite still passes**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests 2>&1 | tail -10
```

Expected: all tests pass (5 from Task 2 + 3 from Task 3 = 8 passing).

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): ReservedPort owns TcpListener until release

Replace pick_free_port (which dropped its listener before returning)
with a ReservedPort type that keeps the kernel-level port lease until
release() is called explicitly. try_start now releases just before
invoking compose_up; the next commit moves that release into a retry
loop. Three unit tests cover acquire (distinct ports), release (port
is bindable again), and idempotency."
```

---

## Task 4: Add `ComposeRunner` trait + production impl

Extract the compose-up shell-out behind a trait so the retry wrapper (next task) can be exercised by a deterministic test double. The production runner does exactly what `compose_up` does today; the difference is only that it's reached through a trait object.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs`

- [ ] **Step 1: Add the trait and the production implementation**

Insert above `fn compose_up` (around line ~273):

```rust
/// Minimal interface over `docker compose up` so the retry wrapper
/// can be unit-tested without a real docker.
trait ComposeRunner {
    fn up(
        &self,
        project: &str,
        compose_dir: &Path,
        tls_port: u16,
        starttls_port: u16,
    ) -> Result<(), HarnessError>;
}

/// Production runner: shells out to `docker compose up -d` (or podman).
struct DockerComposeRunner;

impl ComposeRunner for DockerComposeRunner {
    fn up(
        &self,
        project: &str,
        compose_dir: &Path,
        tls_port: u16,
        starttls_port: u16,
    ) -> Result<(), HarnessError> {
        compose_up(project, compose_dir, tls_port, starttls_port)
    }
}
```

Keep the existing free `fn compose_up` exactly as it is (with the stderr capture from Task 1). The trait impl delegates to it so behavior is provably identical.

- [ ] **Step 2: Verify compile**

```bash
cargo check -p rimap-imap --tests --locked
```

Expected: clean.

`DockerComposeRunner` may trigger `dead_code` because nothing constructs it yet — Task 5 wires it in. The workspace bans `#[allow]` (via `clippy::allow_attributes = "deny"`), so the only sanctioned suppression is `#[expect]`. If `cargo check` fails on the struct, add a scoped expectation directly above the `struct DockerComposeRunner;` line:

```rust
#[expect(dead_code, reason = "wired up in the next commit (compose_up_with_retry)")]
struct DockerComposeRunner;
```

Task 5 removes the attribute as part of wiring the struct into `try_start`. (`#[expect]` self-cleans: once the struct is used, the unfulfilled-expectation lint fires, surfacing the leftover attribute as a clean diagnostic.)

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): ComposeRunner trait + DockerComposeRunner impl

Extracts the compose-up shell-out behind a one-method trait so the
upcoming retry wrapper can be unit-tested with a flaky test double.
DockerComposeRunner delegates to the existing free fn compose_up so
production behavior is byte-identical; the wire-up lands in the next
commit."
```

---

## Task 5: Implement `compose_up_with_retry` and wire it in

Add the retry wrapper, swap `try_start` over to it, and remove the temporary "release explicitly" comment / dead-code expect.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs`

- [ ] **Step 1: Add the retry wrapper**

Insert immediately after the `DockerComposeRunner` impl (or anywhere between `compose_up` and `try_start`'s call site):

```rust
/// Drive `runner.up(...)` with a bounded retry on host-port collisions.
///
/// Three attempts total (initial + 2 retries). Each retry tears down
/// the partial compose project, sleeps with jittered backoff, and
/// acquires fresh `ReservedPort`s. Non-collision errors propagate
/// immediately on the first failure. If all three attempts hit
/// collisions, the most recent stderr is preserved in the error
/// message.
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

- [ ] **Step 2: Update `try_start` to use the wrapper**

The `try_start` body currently looks like (after Task 3):

```rust
let project = format!("rimap-it-{}", uuid_like());
let mut host_port = ReservedPort::acquire()?;
let mut host_starttls_port = ReservedPort::acquire()?;

// Release the kernel-level port leases just before docker binds them.
// The retry wrapper (next task) will move this release into a tighter
// loop; for now, release explicitly and call the plain compose_up.
host_port.release();
host_starttls_port.release();
compose_up(&project, &compose_dir, host_port.port(), host_starttls_port.port())?;
```

Replace with:

```rust
let project = format!("rimap-it-{}", uuid_like());
let mut host_port = ReservedPort::acquire()?;
let mut host_starttls_port = ReservedPort::acquire()?;

let runner = DockerComposeRunner;
compose_up_with_retry(
    &runner,
    &project,
    &compose_dir,
    &mut host_port,
    &mut host_starttls_port,
)?;
```

The wrapper releases the ports internally. Note: after `compose_up_with_retry` succeeds, `host_port.port()` still returns the correct value (we kept the `u16` in the struct even after `release()` consumed the listener).

- [ ] **Step 3: Remove the `#[expect(dead_code)]` from `DockerComposeRunner`**

If Task 4 added an `#[expect(dead_code, reason = "wired up in next commit")]` attribute to `DockerComposeRunner`, remove it now — the struct is in use.

- [ ] **Step 4: Verify the whole crate compiles and existing tests still pass**

```bash
cargo check -p rimap-imap --tests --locked
cargo test -p rimap-imap --test dovecot support::container::tests 2>&1 | tail -10
```

Expected: clean compile, 8 unit tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): compose_up_with_retry closes the port-bind race

Wire DovecotHarness::try_start through a bounded retry wrapper that
releases the kernel-level port leases just before invoking docker, and
retries with fresh ports on EADDRINUSE-style stderr signatures. Three
attempts total, 50ms then 250ms backoff. Non-collision errors
propagate immediately. The author's previously-acknowledged race
(see the doc comment now removed from pick_free_port) is closed:
the race window shrinks from indefinite to microseconds, and the
residual gap is self-healing."
```

---

## Task 6: `FlakyComposeRunner` and retry tests

Add a deterministic test double and the three unit tests that exercise the retry behavior end-to-end. No docker required.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` (extend the `#[cfg(test)] mod tests` block)

- [ ] **Step 1: Add `FlakyComposeRunner` inside the test module**

Inside the existing `#[cfg(test)] mod tests` block, add:

```rust
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test double for `ComposeRunner`. Records every observed
    /// `(tls_port, starttls_port)` pair and returns a programmable
    /// sequence of results.
    struct FlakyComposeRunner {
        fail_first_n: AtomicU32,
        observed_ports: Mutex<Vec<(u16, u16)>>,
        port_collision_stderr: String,
        terminal_error: Option<String>,
    }

    impl FlakyComposeRunner {
        /// Fail the first `n` attempts with a port-collision stderr;
        /// succeed afterward.
        fn fail_first_n_with_port_collision(n: u32) -> Self {
            Self {
                fail_first_n: AtomicU32::new(n),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: "Bind for 127.0.0.1:12345 failed: \
                                        port is already allocated"
                    .into(),
                terminal_error: None,
            }
        }

        /// Always fail with a port-collision stderr.
        fn always_fail_with_port_collision() -> Self {
            Self {
                fail_first_n: AtomicU32::new(u32::MAX),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: "Bind for 127.0.0.1:12345 failed: \
                                        port is already allocated"
                    .into(),
                terminal_error: None,
            }
        }

        /// Always fail with a non-collision stderr.
        fn always_fail_with(msg: &str) -> Self {
            Self {
                fail_first_n: AtomicU32::new(u32::MAX),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: String::new(),
                terminal_error: Some(msg.into()),
            }
        }

        fn observed_ports(&self) -> Vec<(u16, u16)> {
            self.observed_ports.lock().unwrap().clone()
        }

        fn attempts(&self) -> usize {
            self.observed_ports.lock().unwrap().len()
        }
    }

    impl ComposeRunner for FlakyComposeRunner {
        fn up(
            &self,
            _project: &str,
            _compose_dir: &Path,
            tls_port: u16,
            starttls_port: u16,
        ) -> Result<(), HarnessError> {
            self.observed_ports
                .lock()
                .unwrap()
                .push((tls_port, starttls_port));

            if let Some(msg) = self.terminal_error.as_ref() {
                return Err(HarnessError::DockerCommandFailed(msg.clone()));
            }

            let remaining = self.fail_first_n.load(Ordering::SeqCst);
            if remaining > 0 {
                self.fail_first_n.fetch_sub(1, Ordering::SeqCst);
                return Err(HarnessError::DockerCommandFailed(
                    self.port_collision_stderr.clone(),
                ));
            }
            Ok(())
        }
    }
```

Note: `Path` is already imported at the top of `container.rs`; if the test module doesn't see it, add `use super::*;` near the top of the module — which is already there from Task 2.

The `.unwrap()` calls on the `Mutex` are inside `#[cfg(test)]` code, which the workspace allows.

- [ ] **Step 2: Write the three retry-behavior tests**

Append these inside the same test module:

```rust
    fn dummy_compose_dir() -> &'static Path {
        Path::new("/tmp/rimap-it-test")
    }

    #[test]
    fn compose_up_retries_on_port_collision_then_succeeds() {
        let runner = FlakyComposeRunner::fail_first_n_with_port_collision(2);
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        assert!(result.is_ok(), "should succeed on third attempt: {:?}", result.err());
        let ports = runner.observed_ports();
        assert_eq!(ports.len(), 3, "should have attempted three times");
        // Each retry uses a fresh port pair (proves the reacquire path).
        assert_ne!(ports[0], ports[1], "attempt 1 vs 2 ports identical");
        assert_ne!(ports[1], ports[2], "attempt 2 vs 3 ports identical");
    }

    #[test]
    fn compose_up_gives_up_after_max_attempts() {
        let runner = FlakyComposeRunner::always_fail_with_port_collision();
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        let Err(HarnessError::DockerCommandFailed(msg)) = result else {
            panic!("expected DockerCommandFailed, got: {result:?}");
        };
        assert!(msg.contains("exhausted"), "missing 'exhausted' in {msg:?}");
        assert!(
            msg.contains("port is already allocated"),
            "underlying stderr should be preserved in {msg:?}"
        );
        assert_eq!(runner.attempts(), 3, "should have attempted three times");
    }

    #[test]
    fn compose_up_propagates_non_port_errors_immediately() {
        let runner = FlakyComposeRunner::always_fail_with("no such image: dovecot:9.9.9");
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        assert!(result.is_err());
        assert_eq!(runner.attempts(), 1, "non-collision errors should not retry");
    }
```

Caveat: `compose_up_with_retry` calls `compose_down` between collision retries. `compose_down` in this codebase silently discards errors from `Command::...status()` (line 396 of the file), so it will be a no-op when called against a project that doesn't have a real docker behind it. The tests run cleanly even though no docker is involved.

- [ ] **Step 3: Run the three retry tests**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests::compose_up 2>&1 | tail -15
```

Expected: 3 passed.

- [ ] **Step 4: Run the full unit-test module**

```bash
cargo test -p rimap-imap --test dovecot support::container::tests 2>&1 | tail -10
```

Expected: 11 passed (5 classifier + 3 ReservedPort + 3 retry).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): unit tests for compose_up_with_retry

A FlakyComposeRunner test double records every observed port pair and
returns a programmable sequence of results. Three tests cover the
retry path end-to-end without requiring docker: (a) two failures then
success exercises the reacquire-fresh-ports path, (b) three failures
asserts the 'exhausted' error preserves the underlying stderr, (c)
non-collision errors propagate without retrying. These tests catch
regressions in the retry logic that the dovecot suite would only
surface as an intermittent CI flake."
```

---

## Task 7: Run local CI, push, and confirm CI is green

Validate the fix end-to-end and update the existing PR.

**Files:** none (no further code changes)

- [ ] **Step 1: Run the full local-CI suite**

```bash
just ci
```

Expected: all stages pass — `fmt-check`, `lint`, `test`, `test-msrv`, `deny`, `typos`.

The dovecot integration tests themselves are not exercised by `just test` (they require docker and silently skip otherwise via `HarnessError::DockerUnavailable`). The new unit tests inside the integration test crate do execute under `cargo nextest` and verify the retry logic.

- [ ] **Step 2: Run pre-commit hooks across all files**

```bash
just hooks
```

Expected: every hook passes.

- [ ] **Step 3: Push the branch**

```bash
git push origin feat/release-versioning
```

The branch already has an open PR (#257); pushing updates it.

- [ ] **Step 4: Watch CI**

```bash
gh pr checks 257 --watch
```

Or, if you don't want to block on the terminal, poll periodically:

```bash
gh pr checks 257
```

Expected: every check is `pass`, including the `test (MSRV 1.88.0)` lane that previously failed.

- [ ] **Step 5: If CI is green, leave a brief PR comment summarizing the fix**

```bash
gh pr comment 257 --body "$(cat <<'EOF'
Fix for the MSRV-lane port-bind race landed in commits ${COMMITS}. Summary:

- `ReservedPort` keeps the `TcpListener` lease open until docker is invoked.
- `compose_up_with_retry` handles the residual collision window with 50ms/250ms backoff and propagates the underlying stderr on exhausted retries.
- A `ComposeRunner` trait + `FlakyComposeRunner` test double cover the retry logic in unit tests (no docker needed).
- `compose_up` now captures stderr so failures are diagnosable on first inspection.

Spec: `docs/superpowers/specs/2026-05-11-dovecot-port-race-design.md`.
EOF
)"
```

Replace `${COMMITS}` with the SHAs of Tasks 1–6 commits (`git log --oneline -7` of the new commits).

- [ ] **Step 6: If CI is still red, capture the failing log and report DONE_WITH_CONCERNS**

If a different test now fails (e.g. a real bug exposed by the new diagnostic, or an unrelated flake): do NOT propose re-running the job. Investigate the failure, escalate to the user with the captured log, and decide whether to fix in this PR or open a follow-up.

If the same test still fails: the retry policy may be insufficient (e.g. CI is under heavier collision pressure than expected). Capture the run URL, the failed-job log, and any new "exhausted attempts" error message, then escalate to the user. The fix path would be to widen the retry policy or switch to option C (file-locked port allocator) from the brainstorm.

---

## Verification checklist

After all tasks complete and CI is green:

- [ ] `pick_free_port` is gone; `ReservedPort` is its replacement (`grep -n 'pick_free_port' crates/rimap-imap/tests/integration/support/container.rs` returns nothing).
- [ ] `compose_up` captures stderr; failing `compose up` errors include the underlying docker message.
- [ ] `compose_up_with_retry` is called from `DovecotHarness::try_start`.
- [ ] The `#[cfg(test)] mod tests` block in `container.rs` has 11 passing tests.
- [ ] PR #257's `test (MSRV 1.88.0)` lane is green across at least two consecutive runs (a single green run proves nothing about flakiness — two consecutive proves the bound).
- [ ] No production-code or other-crate files are touched in this PR.

---

## Out of scope (do not touch in this PR)

- `STALE_PROJECT_AGE` (currently 30 min). Touching it requires measuring parallel-run wall time first.
- SMTP integration harness wiring (the dormant compose file). When SMTP grows a Rust consumer, it should reuse `ReservedPort` + `compose_up_with_retry`.
- File-locked process-wide port allocator (option C). Deferred unless the retry pattern still flakes.
- `restart()` code path. It reuses an already-bound port and doesn't traverse the race.
- Nextest parallelism tuning (e.g. `test-threads` override for the integration lane). Orthogonal to the bind race.
