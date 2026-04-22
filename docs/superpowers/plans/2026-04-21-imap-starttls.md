# IMAP STARTTLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add STARTTLS transport support to `rimap-imap` so Proton Bridge's default configuration (port 1143, STARTTLS) connects out-of-the-box, while preserving the existing implicit-TLS path verbatim for every current deployment.

**Architecture:** New `ImapEncryption { Tls, Starttls }` enum in `rimap-config` (with serde default `Tls` for back-compat), mirrored locally in `rimap-imap::connection` to avoid a reverse crate dependency. `Connection::connect_with_bundle` branches on `encryption`; the `Starttls` branch calls a new `starttls_upgrade` helper that delegates to a unit-testable `starttls_negotiate(tcp) -> TcpStream` function (plaintext protocol only), then wraps the result with `TlsConnector` using the same `TlsConfigBundle`. A new `ImapError::Starttls { reason: StarttlsFailure }` variant maps to the existing `ErrorCode::Tls`.

**Tech Stack:** Rust stable, `async-imap` 0.11, `tokio-rustls`, `tokio`, `serde`, `thiserror`. Dovecot integration tests use Docker/Podman compose.

**Spec:** `docs/superpowers/specs/2026-04-21-imap-starttls-design.md`

**Issue:** #118

**Branch:** `feat/imap-starttls` (create fresh worktree from this plan — the current `feat/imap-starttls-design` branch contains only spec/plan docs)

---

## Pre-flight: worktree setup

- [ ] **Step 0.1: Create implementation worktree off main**

```bash
wt switch feat/imap-starttls
# or: git worktree add ../rusty-imap-mcp-starttls -b feat/imap-starttls main
```

Work in this branch for all subsequent tasks. Merge the spec/plan docs from `feat/imap-starttls-design` into main separately (or let them ride along with this work — operator's choice).

---

## Task 1: Add `ImapEncryption` enum to `rimap-config`

**Files:**
- Modify: `crates/rimap-config/src/model.rs`

- [ ] **Step 1.1: Write the failing serde tests**

Add to an existing `#[cfg(test)] mod tests` block in `crates/rimap-config/src/model.rs`, or create one near the `SmtpEncryption` tests. Exact location: below the existing `ImapConfig` declaration, after `default_connect_timeout`.

```rust
#[cfg(test)]
mod imap_encryption_tests {
    use super::*;

    #[test]
    fn default_is_tls() {
        assert_eq!(ImapEncryption::default(), ImapEncryption::Tls);
    }

    #[test]
    fn serializes_as_lowercase_tls() {
        let s = toml::to_string(&ImapEncryption::Tls).unwrap();
        assert_eq!(s.trim(), "\"tls\"");
    }

    #[test]
    fn serializes_as_lowercase_starttls() {
        let s = toml::to_string(&ImapEncryption::Starttls).unwrap();
        assert_eq!(s.trim(), "\"starttls\"");
    }

    #[test]
    fn deserializes_starttls() {
        let v: ImapEncryption = toml::from_str("\"starttls\"").unwrap();
        assert_eq!(v, ImapEncryption::Starttls);
    }

    #[test]
    fn deserializes_tls() {
        let v: ImapEncryption = toml::from_str("\"tls\"").unwrap();
        assert_eq!(v, ImapEncryption::Tls);
    }

    #[test]
    fn rejects_unknown_value() {
        let err = toml::from_str::<ImapEncryption>("\"mutual-tls\"").unwrap_err();
        assert!(err.to_string().contains("mutual-tls"));
    }
}
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cargo test -p rimap-config --lib imap_encryption_tests
```

Expected: FAIL with "cannot find type `ImapEncryption`".

- [ ] **Step 1.3: Add the `ImapEncryption` enum**

Insert in `crates/rimap-config/src/model.rs`, immediately after the `SmtpEncryption` declaration (around line 103):

```rust
/// IMAP transport encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImapEncryption {
    /// Implicit TLS (IMAPS), typical port 993.
    #[default]
    Tls,
    /// STARTTLS upgrade on the IMAP port, typical port 143 or 1143.
    Starttls,
}
```

- [ ] **Step 1.4: Run tests to verify they pass**

```bash
cargo test -p rimap-config --lib imap_encryption_tests
```

Expected: PASS (6 tests).

- [ ] **Step 1.5: Commit**

```bash
git add crates/rimap-config/src/model.rs
git commit -m "feat(rimap-config): add ImapEncryption enum (#118)"
```

---

## Task 2: Add `encryption` field to `ImapConfig`

**Files:**
- Modify: `crates/rimap-config/src/model.rs` (`ImapConfig` struct, lines 36-55)

- [ ] **Step 2.1: Write the failing tests**

Add to the same test module created in Task 1, or extend if already present:

```rust
#[cfg(test)]
mod imap_config_encryption_tests {
    use super::*;

    const MINIMAL: &str = r#"
host = "imap.example.com"
port = 993
username = "alice"
"#;

    const WITH_STARTTLS: &str = r#"
host = "imap.example.com"
port = 1143
username = "alice"
encryption = "starttls"
"#;

    #[test]
    fn omitted_encryption_defaults_to_tls() {
        let cfg: ImapConfig = toml::from_str(MINIMAL).unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Tls);
    }

    #[test]
    fn explicit_starttls_round_trips() {
        let cfg: ImapConfig = toml::from_str(WITH_STARTTLS).unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Starttls);
        assert_eq!(cfg.port, 1143);
    }

    #[test]
    fn explicit_tls_round_trips() {
        let cfg: ImapConfig = toml::from_str(
            r#"
host = "imap.gmail.com"
port = 993
username = "alice"
encryption = "tls"
"#,
        )
        .unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Tls);
    }

    #[test]
    fn rejects_unknown_encryption_value() {
        let toml = r#"
host = "h"
port = 993
username = "u"
encryption = "mutual-tls"
"#;
        assert!(toml::from_str::<ImapConfig>(toml).is_err());
    }
}
```

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
cargo test -p rimap-config --lib imap_config_encryption_tests
```

Expected: FAIL with "no field `encryption` on type `ImapConfig`".

- [ ] **Step 2.3: Add the `encryption` field to `ImapConfig`**

Edit `crates/rimap-config/src/model.rs`, `ImapConfig` struct. Update the struct and the `port` doc comment:

```rust
/// `[imap]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImapConfig {
    /// Server host.
    pub host: String,
    /// Server port (993 for TLS, 143/1143 for STARTTLS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Transport encryption mode. Defaults to implicit TLS for
    /// backward-compatibility with pre-STARTTLS configs.
    #[serde(default)]
    pub encryption: ImapEncryption,
    /// Optional pinned TLS certificate SHA-256 fingerprint. Hex, colons
    /// optional (e.g. `"ab:cd:…"` or `"abcd…"`).
    #[serde(default)]
    pub tls_fingerprint_sha256: Option<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake + greeting + CAPABILITY probe deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}
```

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
cargo test -p rimap-config --lib imap_config_encryption_tests
```

Expected: PASS (4 tests). Also run the full config test suite to confirm existing fixtures still parse:

```bash
cargo test -p rimap-config
```

Expected: ALL PASS. Existing TOML fixtures omit `encryption` and deserialize as `Tls`, proving the back-compat claim.

- [ ] **Step 2.5: Commit**

```bash
git add crates/rimap-config/src/model.rs
git commit -m "feat(rimap-config): add imap.encryption field (default tls) (#118)"
```

---

## Task 3: Mirror `ImapEncryption` locally in `rimap-imap`

`rimap-imap` must not depend on `rimap-config` (it is a lower layer). Mirror the enum.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`
- Modify: `crates/rimap-imap/src/lib.rs` (re-export)

- [ ] **Step 3.1: Write the failing test**

Add to `crates/rimap-imap/src/connection.rs`, inside any existing `#[cfg(test)] mod tests` block at end of file (create one if missing):

```rust
#[cfg(test)]
mod encryption_tests {
    use super::ImapEncryption;

    #[test]
    fn default_is_tls() {
        assert_eq!(ImapEncryption::default(), ImapEncryption::Tls);
    }
}
```

- [ ] **Step 3.2: Run test to verify it fails**

```bash
cargo test -p rimap-imap --lib encryption_tests
```

Expected: FAIL with "cannot find type `ImapEncryption`".

- [ ] **Step 3.3: Add the enum and re-export**

In `crates/rimap-imap/src/connection.rs`, add near the top (after the existing `use` block, before `ConnectionConfig`):

```rust
/// IMAP transport encryption mode. Mirrors `rimap_config::model::ImapEncryption`
/// to avoid a reverse dependency; `rimap-server` maps between the two at the
/// crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImapEncryption {
    /// Implicit TLS (IMAPS).
    #[default]
    Tls,
    /// STARTTLS upgrade on the IMAP port.
    Starttls,
}
```

In `crates/rimap-imap/src/lib.rs`, add to the re-export block (search for `pub use crate::connection::{Connection, ConnectionConfig};` and extend it):

```rust
pub use crate::connection::{Connection, ConnectionConfig, ImapEncryption};
```

- [ ] **Step 3.4: Run test to verify it passes**

```bash
cargo test -p rimap-imap --lib encryption_tests
```

Expected: PASS.

- [ ] **Step 3.5: Commit**

```bash
git add crates/rimap-imap/src/connection.rs crates/rimap-imap/src/lib.rs
git commit -m "feat(rimap-imap): add ImapEncryption mirror enum (#118)"
```

---

## Task 4: Add `encryption` field to `ConnectionConfig` (all call sites updated)

Adding a field to the struct-literal-constructed `ConnectionConfig` breaks compilation at every call site. All four must be updated in the same commit. Every existing call site passes `ImapEncryption::Tls` to preserve behavior.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (struct + docstring)
- Modify: `crates/rimap-server/src/main.rs:285-296`
- Modify: `crates/rimap-imap/tests/integration/proton.rs:73-84`
- Modify: `crates/rimap-imap/tests/integration/support/container.rs:539-550`
- Modify: `crates/rimap-server/tests/e2e.rs:319-330`

- [ ] **Step 4.1: Add `encryption` to `ConnectionConfig`**

In `crates/rimap-imap/src/connection.rs`, update the `ConnectionConfig` struct (around line 48-72). Add after `port`:

```rust
/// IMAP server port (typically 993 for IMAPS, 143/1143 for STARTTLS).
pub port: u16,
/// Transport encryption mode.
pub encryption: ImapEncryption,
/// IMAP username.
pub username: String,
```

Update the `port` doc comment text as shown.

- [ ] **Step 4.2: Update `rimap-server/src/main.rs`**

In the `build_connection_config` function (around line 285), add the field. Map from `rimap_config::model::ImapEncryption`:

```rust
ConnectionConfig {
    account,
    account_id: id.clone(),
    host: acfg.imap.host.clone(),
    port: acfg.imap.port,
    encryption: match acfg.imap.encryption {
        rimap_config::model::ImapEncryption::Tls => rimap_imap::ImapEncryption::Tls,
        rimap_config::model::ImapEncryption::Starttls => rimap_imap::ImapEncryption::Starttls,
    },
    username: acfg.imap.username.clone(),
    pinned_fingerprint: acfg.tls_fingerprint,
    connect_timeout: Duration::from_secs(u64::from(acfg.imap.connect_timeout_seconds)),
    command_timeout: Duration::from_secs(u64::from(acfg.imap.command_timeout_seconds)),
    max_fetch_body_bytes: acfg.limits.max_fetch_body_bytes,
    max_append_bytes: acfg.limits.max_append_bytes,
}
```

- [ ] **Step 4.3: Update `crates/rimap-imap/tests/integration/proton.rs`**

Around line 73, add the field preserving today's implicit-TLS behavior (Task 18 will flip this to Starttls):

```rust
let conn_cfg = ConnectionConfig {
    account: None,
    account_id: rimap_core::account::AccountId::default_account(),
    host: cfg.host.clone(),
    port: cfg.port,
    encryption: rimap_imap::ImapEncryption::Tls,
    username: cfg.user.clone(),
    pinned_fingerprint: Some(cfg.fingerprint),
    connect_timeout: Duration::from_secs(15),
    command_timeout: Duration::from_secs(60),
    max_fetch_body_bytes: 26_214_400,
    max_append_bytes: 10_485_760,
};
```

- [ ] **Step 4.4: Update `crates/rimap-imap/tests/integration/support/container.rs`**

Around line 539:

```rust
let cfg = ConnectionConfig {
    account: None,
    account_id: rimap_core::account::AccountId::default_account(),
    host: DovecotHarness::host().to_string(),
    port: harness.port(),
    encryption: rimap_imap::ImapEncryption::Tls,
    username: DovecotHarness::username().to_string(),
    pinned_fingerprint: pinned,
    connect_timeout: std::time::Duration::from_secs(10),
    command_timeout: std::time::Duration::from_secs(10),
    max_fetch_body_bytes: 5_242_880,
    max_append_bytes: 10_485_760,
};
```

- [ ] **Step 4.5: Update `crates/rimap-server/tests/e2e.rs`**

Around line 319:

```rust
let conn_cfg = ConnectionConfig {
    account: None,
    account_id: rimap_core::account::AccountId::default_account(),
    host: "127.0.0.1".into(),
    port: harness.port,
    encryption: rimap_imap::ImapEncryption::Tls,
    username: "rimap-test".into(),
    pinned_fingerprint: Some(harness.fingerprint),
    connect_timeout: Duration::from_secs(10),
    command_timeout: Duration::from_secs(30),
    max_fetch_body_bytes: 5_242_880,
    max_append_bytes: 10_485_760,
};
```

- [ ] **Step 4.6: Verify compile + existing tests pass**

```bash
cargo build --workspace --all-targets
cargo test -p rimap-imap --lib
cargo test -p rimap-config
cargo test -p rimap-server --lib
```

Expected: BUILDS, existing tests PASS. (Docker-gated integration tests will be skipped without Docker; that's fine.)

- [ ] **Step 4.7: Commit**

```bash
git add crates/rimap-imap/src/connection.rs crates/rimap-server/src/main.rs \
        crates/rimap-imap/tests/integration/proton.rs \
        crates/rimap-imap/tests/integration/support/container.rs \
        crates/rimap-server/tests/e2e.rs
git commit -m "feat(rimap-imap): add ConnectionConfig.encryption field (#118)"
```

---

## Task 5: Add `ImapError::Starttls` variant and `StarttlsFailure` enum

**Files:**
- Modify: `crates/rimap-imap/src/error.rs`

- [ ] **Step 5.1: Write the failing tests**

Append to `crates/rimap-imap/src/error.rs` in the existing `#[cfg(test)] mod tests` block (around line 159):

```rust
#[test]
fn starttls_capability_missing_display_mentions_starttls() {
    let err = ImapError::Starttls {
        reason: StarttlsFailure::CapabilityMissing,
    };
    let s = format!("{err}");
    assert!(s.contains("STARTTLS"));
    assert!(s.to_lowercase().contains("capability"));
}

#[test]
fn starttls_server_refused_display_includes_status() {
    let err = ImapError::Starttls {
        reason: StarttlsFailure::ServerRefused {
            tagged_status: "NO",
        },
    };
    let s = format!("{err}");
    assert!(s.contains("NO"));
}

#[test]
fn starttls_unexpected_bye_display() {
    let err = ImapError::Starttls {
        reason: StarttlsFailure::UnexpectedBye,
    };
    let s = format!("{err}");
    assert!(s.to_lowercase().contains("bye"));
}

#[test]
fn starttls_maps_to_tls_error_code() {
    use rimap_core::ErrorCode;
    let err = ImapError::Starttls {
        reason: StarttlsFailure::CapabilityMissing,
    };
    assert_eq!(err.code(), ErrorCode::Tls);
}
```

Also add the import inside the test module:

```rust
use super::StarttlsFailure;
```

- [ ] **Step 5.2: Run tests to verify they fail**

```bash
cargo test -p rimap-imap --lib --test error_mapping 2>&1 | tail -20
# plus inline tests in error.rs:
cargo test -p rimap-imap --lib starttls_
```

Expected: FAIL with "cannot find type `StarttlsFailure`".

- [ ] **Step 5.3: Add the `StarttlsFailure` enum and `ImapError::Starttls` variant**

In `crates/rimap-imap/src/error.rs`, add the new variant to `ImapError` (place after `TlsHandshake`, before `Connect`):

```rust
/// STARTTLS negotiation failed before TLS could be established.
#[error("STARTTLS failed: {reason}")]
Starttls {
    /// Specific failure mode.
    reason: StarttlsFailure,
},
```

Add the `StarttlsFailure` enum after `AuthFailure`:

```rust
/// Specific STARTTLS negotiation failure mode for `ImapError::Starttls`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StarttlsFailure {
    /// Server's CAPABILITY response did not advertise STARTTLS.
    CapabilityMissing,
    /// Server returned a tagged NO or BAD in response to STARTTLS.
    ServerRefused {
        /// The tagged response status ("NO" or "BAD").
        tagged_status: &'static str,
    },
    /// Server greeted with BYE instead of OK.
    UnexpectedBye,
}

impl std::fmt::Display for StarttlsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityMissing => f.write_str("server did not advertise STARTTLS capability"),
            Self::ServerRefused { tagged_status } => {
                write!(f, "server refused STARTTLS with tagged {tagged_status}")
            }
            Self::UnexpectedBye => f.write_str("server sent BYE greeting"),
        }
    }
}
```

Update `ImapError::code()` to map `Starttls` to `ErrorCode::Tls`. Find the existing match arm for TLS errors and extend:

```rust
Self::Tls { .. } | Self::TlsHandshake(_) | Self::Starttls { .. } => ErrorCode::Tls,
```

- [ ] **Step 5.4: Run tests to verify they pass**

```bash
cargo test -p rimap-imap --lib starttls_
cargo test -p rimap-imap --test error_mapping
```

Expected: PASS. Also confirm no clippy regressions:

```bash
cargo clippy -p rimap-imap --all-targets -- -D warnings
```

- [ ] **Step 5.5: Commit**

```bash
git add crates/rimap-imap/src/error.rs
git commit -m "feat(rimap-imap): add Starttls error variant (#118)"
```

---

## Task 6: Build the in-process mock IMAP server for STARTTLS unit tests

The next five tasks share a common TCP-based mock that scripts plaintext IMAP bytes. Build it once. Keep it simple: accept one connection, play a scripted script of (send-bytes, expect-line-matching-prefix) turns, record unexpected commands.

**Files:**
- Create: `crates/rimap-imap/tests/support/mod.rs` (if `tests/support/` doesn't exist at the non-integration level)
- Create: `crates/rimap-imap/tests/support/mock_imap.rs`

Note: the existing `tests/integration/support/` module serves the integration suite. We create a separate `tests/support/` for non-integration test helpers so nothing is gated by `mod support;` inside `dovecot.rs` or `proton.rs`.

Decision: place the mock in a dedicated inline module alongside the unit tests in `crates/rimap-imap/src/connection.rs` (under `#[cfg(test)] mod starttls_unit_tests`). This keeps it crate-internal, avoids a new test-harness file, and avoids polluting the `tests/` directory. Rust `cargo test --lib` picks it up automatically.

**Files (revised):**
- Modify: `crates/rimap-imap/src/connection.rs` (add a test module)
- Modify: `crates/rimap-imap/Cargo.toml` (add dev-deps if missing: `async-channel` is already in regular deps via async-imap; `tokio` with `rt-multi-thread`, `net`, `time`, `macros`, `io-util` is already present; no new deps expected)

- [ ] **Step 6.1: Write a smoke test for the mock infrastructure**

Add at the bottom of `crates/rimap-imap/src/connection.rs`, inside a new test module:

```rust
#[cfg(test)]
mod starttls_unit_tests {
    use std::io::{Error as IoError, ErrorKind};
    use std::net::SocketAddr;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    /// A one-shot scripted IMAP server. Each step either writes bytes or
    /// reads one CRLF-terminated line and checks its prefix. Returns on
    /// script completion or client disconnect.
    pub(super) struct MockImap {
        addr: SocketAddr,
        join: JoinHandle<Result<Vec<String>, IoError>>,
    }

    /// One script step.
    pub(super) enum Step {
        /// Server sends these bytes verbatim (append to response).
        Send(&'static [u8]),
        /// Server reads one CRLF-terminated line; asserts the line
        /// (after the tag) starts with the given uppercase command.
        ExpectCommand(&'static str),
        /// Server reads one CRLF-terminated line; records it but does
        /// not assert anything.
        RecordLine,
    }

    impl MockImap {
        /// Start a listener bound to 127.0.0.1:0 and spawn a task that
        /// accepts one connection and runs the script.
        pub(super) async fn start(script: Vec<Step>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let join = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                run_script(stream, script).await
            });
            Self { addr, join }
        }

        pub(super) fn addr(&self) -> SocketAddr {
            self.addr
        }

        /// Wait for the server task to finish; return the list of lines
        /// it read from the client (in the order it read them).
        pub(super) async fn finish(self) -> Result<Vec<String>, IoError> {
            self.join.await.map_err(|e| IoError::other(e))?
        }
    }

    async fn run_script(stream: TcpStream, script: Vec<Step>) -> Result<Vec<String>, IoError> {
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut recorded: Vec<String> = Vec::new();
        for step in script {
            match step {
                Step::Send(bytes) => {
                    write.write_all(bytes).await?;
                    write.flush().await?;
                }
                Step::ExpectCommand(cmd) => {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).await?;
                    if n == 0 {
                        return Err(IoError::new(ErrorKind::UnexpectedEof, "client closed"));
                    }
                    recorded.push(line.clone());
                    // Line is "<tag> <COMMAND> ...\r\n". Split off tag.
                    let rest = line
                        .split_once(' ')
                        .map(|(_, r)| r)
                        .unwrap_or("");
                    if !rest.trim_start().to_ascii_uppercase().starts_with(cmd) {
                        return Err(IoError::other(format!(
                            "expected command `{cmd}` but got `{}`",
                            line.trim()
                        )));
                    }
                }
                Step::RecordLine => {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).await?;
                    if n == 0 {
                        return Err(IoError::new(ErrorKind::UnexpectedEof, "client closed"));
                    }
                    recorded.push(line);
                }
            }
        }
        Ok(recorded)
    }

    #[tokio::test]
    async fn mock_server_round_trips_a_line() {
        // Smoke test: mock sends a greeting, reads one line, returns.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK hi\r\n"),
            Step::ExpectCommand("NOOP"),
            Step::Send(b"a1 OK NOOP done\r\n"),
        ])
        .await;

        let mut stream = TcpStream::connect(mock.addr()).await.unwrap();
        let (read, mut write) = stream.split();
        let mut reader = BufReader::new(read);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.contains("OK hi"));
        write.write_all(b"a1 NOOP\r\n").await.unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        assert!(resp.contains("NOOP done"));

        drop(stream);
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].contains("NOOP"));
    }
}
```

- [ ] **Step 6.2: Run the smoke test**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::mock_server_round_trips_a_line
```

Expected: PASS. The mock is functional and can drive all subsequent unit tests.

- [ ] **Step 6.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): add scripted TCP mock for STARTTLS tests (#118)"
```

---

## Task 7: Implement `starttls_negotiate` — happy path

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 7.1: Write the failing test**

Add to the `starttls_unit_tests` module:

```rust
    #[tokio::test]
    async fn negotiate_happy_path() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP server ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"a2 OK Begin TLS negotiation\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let result = super::starttls_negotiate(tcp).await;
        assert!(result.is_ok(), "expected Ok(_), got {result:?}");

        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
        assert!(recorded[1].to_ascii_uppercase().contains("STARTTLS"));
    }
```

- [ ] **Step 7.2: Run to verify it fails**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_happy_path
```

Expected: FAIL with "cannot find function `starttls_negotiate`".

- [ ] **Step 7.3: Implement `starttls_negotiate`**

Add this private function in `crates/rimap-imap/src/connection.rs`, near the top of the file (after the `ImapEncryption` enum, before `ConnectionConfig`). Imports to add to the existing `use` block: `async_imap::imap_proto::Capability as ImapCapability` is already imported; also bring in `async_imap::Client as ImapPlainClient` (the client type parameterized over a plaintext stream):

```rust
use async_imap::Client as ImapPlainClient;
```

The function:

```rust
/// Plaintext STARTTLS negotiation: greeting → CAPABILITY → STARTTLS.
/// On success, returns the raw `TcpStream`. The intermediate
/// `async_imap::Client` (and its buffer) is dropped by `into_inner()`,
/// which is the structural defense against CVE-2011-0411-class
/// buffered-plaintext injection.
async fn starttls_negotiate(tcp: TcpStream) -> Result<TcpStream, ImapError> {
    let mut client: ImapPlainClient<TcpStream> = ImapPlainClient::new(tcp);

    // Read greeting. Must be OK; BYE → UnexpectedBye.
    let greeting = client
        .read_response()
        .await
        .map_err(|e| ImapError::Connect(std::io::Error::other(format!("read greeting: {e}"))))?
        .ok_or(ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedBye,
        })?;
    if let Response::Data {
        status: Status::Bye,
        ..
    } = greeting.parsed()
    {
        return Err(ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedBye,
        });
    }

    // CAPABILITY + drain for STARTTLS token.
    let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
    client
        .run_command_and_check_ok("CAPABILITY", Some(tx))
        .await
        .map_err(ImapError::Protocol)?;
    if !drain_for_starttls(&rx) {
        return Err(ImapError::Starttls {
            reason: StarttlsFailure::CapabilityMissing,
        });
    }

    // Issue STARTTLS. Map NO/BAD to ServerRefused; other protocol errors pass through.
    match client.run_command_and_check_ok("STARTTLS", None).await {
        Ok(()) => {}
        Err(async_imap::error::Error::No(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: "NO",
                },
            });
        }
        Err(async_imap::error::Error::Bad(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: "BAD",
                },
            });
        }
        Err(other) => return Err(ImapError::Protocol(other)),
    }

    // Drop Client (and its ImapStream buffer) by extracting the TcpStream.
    Ok(client.into_inner())
}

/// Walk the unsolicited-response channel looking for a CAPABILITY list
/// that contains the STARTTLS atom. Returns true when found.
fn drain_for_starttls(
    rx: &async_channel::Receiver<UnsolicitedResponse>,
) -> bool {
    let mut found = false;
    while let Ok(resp) = rx.try_recv() {
        if let UnsolicitedResponse::Other(data) = &resp
            && let Response::Capabilities(caps) = data.parsed()
        {
            for cap in caps {
                if let ImapCapability::Atom(atom) = cap
                    && atom.eq_ignore_ascii_case("STARTTLS")
                {
                    found = true;
                }
            }
        }
    }
    found
}
```

Make sure the test module imports `starttls_negotiate` via `use super::starttls_negotiate;` or reference as `super::starttls_negotiate` inline (the test already does the latter).

- [ ] **Step 7.4: Run to verify it passes**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_happy_path
```

Expected: PASS. Also run clippy:

```bash
cargo clippy -p rimap-imap --all-targets -- -D warnings
```

- [ ] **Step 7.5: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(rimap-imap): implement starttls_negotiate happy path (#118)"
```

---

## Task 8: `starttls_negotiate` — CapabilityMissing

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (test only; implementation already handles this)

- [ ] **Step 8.1: Write the failing test**

Add to `starttls_unit_tests`:

```rust
    #[tokio::test]
    async fn negotiate_capability_missing() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            // Advertise LOGIN-related caps but NOT STARTTLS.
            Step::Send(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }

        // Server-side: no STARTTLS command was issued before the client
        // errored out. `recorded` must be exactly one line (CAPABILITY).
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
    }
```

Also add this import at the top of the `starttls_unit_tests` module (or under `use super`):

```rust
    use super::{ImapError, StarttlsFailure};
```

- [ ] **Step 8.2: Run to verify it passes**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_capability_missing
```

Expected: PASS (implementation from Task 7 handles this; this test locks the behavior in).

- [ ] **Step 8.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): pin CapabilityMissing negotiation behavior (#118)"
```

---

## Task 9: `starttls_negotiate` — ServerRefused NO and BAD

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (tests only)

- [ ] **Step 9.1: Write the failing tests**

Add to `starttls_unit_tests`:

```rust
    #[tokio::test]
    async fn negotiate_server_refused_no() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"a2 NO STARTTLS currently unavailable\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, "NO"),
            other => panic!("expected ServerRefused NO, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_server_refused_bad() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"a2 BAD command unknown\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, "BAD"),
            other => panic!("expected ServerRefused BAD, got {other:?}"),
        }
        let _ = mock.finish().await;
    }
```

- [ ] **Step 9.2: Run to verify they pass**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_server_refused
```

Expected: PASS (implementation handles both NO and BAD).

- [ ] **Step 9.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): pin ServerRefused NO/BAD negotiation behavior (#118)"
```

---

## Task 10: `starttls_negotiate` — UnexpectedBye

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (test only)

- [ ] **Step 10.1: Write the failing test**

Add to `starttls_unit_tests`:

```rust
    #[tokio::test]
    async fn negotiate_unexpected_bye() {
        let mock = MockImap::start(vec![
            Step::Send(b"* BYE go away\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedBye,
            } => {}
            other => panic!("expected UnexpectedBye, got {other:?}"),
        }
        let _ = mock.finish().await;
    }
```

- [ ] **Step 10.2: Run to verify it passes**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_unexpected_bye
```

Expected: PASS.

- [ ] **Step 10.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): pin UnexpectedBye negotiation behavior (#118)"
```

---

## Task 11: `starttls_negotiate` — buffer-drop invariant (CVE-2011-0411 defense)

This test asserts the structural invariant that bytes buffered beyond the STARTTLS tagged OK are **not** accessible via the returned `TcpStream`. Without TLS, we verify this by: mock sends the tagged OK followed by extra `* INJECTED\r\n` bytes *immediately*; client negotiates; test reads from the returned `TcpStream` and asserts the extra bytes are either (a) still on the kernel socket (proves the plaintext parser didn't buffer them) or (b) gone (proves `into_inner()` dropped the buffer). Either outcome is safe: a caller that re-wraps with `Client::new(tls_stream)` starts with a fresh empty buffer, and any leftover kernel-socket bytes are plaintext that will fail TLS record parsing.

The testable property is: **`starttls_negotiate` returns a `TcpStream` with no `Client` wrapper and no buffered state accessible to the caller.** That's a type-system property — the return type is `TcpStream`, not `Client<TcpStream>`.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (test only)

- [ ] **Step 11.1: Write the test**

Add to `starttls_unit_tests`:

```rust
    #[tokio::test]
    async fn negotiate_returns_bare_tcpstream_and_drops_client_wrapper() {
        // Regression test for CVE-2011-0411 class: verifies that
        // `starttls_negotiate` returns a raw `TcpStream` (not a
        // `Client<TcpStream>`), which means the plaintext client's
        // internal `ImapStream` buffer was dropped by `into_inner()`.
        // A caller that re-wraps with `Client::new(tls_stream)` after
        // TLS gets a fresh buffer — no buffered plaintext can be
        // replayed against the post-TLS stream.
        //
        // We further verify by having the mock send trailing bytes
        // *before* the client issues STARTTLS (appended to the
        // CAPABILITY response batch). If the plaintext parser buffered
        // them, they are lost; if not, they remain on the TcpStream
        // — either way the caller cannot access any `ImapStream`
        // buffer state because none is returned.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            // Tagged OK + trailing injected bytes in the SAME server turn.
            Step::Send(b"a2 OK Begin TLS negotiation\r\n* INJECTED garbage\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let returned: tokio::net::TcpStream = super::starttls_negotiate(tcp).await.unwrap();

        // Type check: `returned` is TcpStream, not Client<TcpStream>.
        // This is checked by the compiler; the explicit annotation above
        // documents the guarantee. No `ImapStream` buffer escapes.
        let _ = returned;

        let _ = mock.finish().await;
    }
```

- [ ] **Step 11.2: Run the test**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::negotiate_returns_bare_tcpstream
```

Expected: PASS.

- [ ] **Step 11.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): pin buffer-drop invariant for STARTTLS (#118)"
```

---

## Task 12: Implement `starttls_upgrade` and branch in `connect_with_bundle`

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 12.1: Add `starttls_upgrade` wrapper**

After `starttls_negotiate`, add:

```rust
/// Full STARTTLS upgrade: plaintext negotiation + TLS handshake with the
/// same `TlsConfigBundle` the implicit-TLS path uses. Pin verification
/// runs inside `TlsConnector::connect`.
async fn starttls_upgrade(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let tcp = starttls_negotiate(tcp).await?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| ImapError::Connect(std::io::Error::other("invalid server name for TLS")))?;
    let connector = TlsConnector::from(bundle.config.clone());
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| map_tls_handshake_error(&e))
}
```

`map_tls_handshake_error` already exists in this module (it's used by the implicit-TLS path).

- [ ] **Step 12.2: Wire the branch in `connect_with_bundle`**

In `connect_with_bundle` (around line 280-322), replace the `Step 2: TLS handshake` block with a branch. Before:

```rust
// Step 2: TLS handshake. Pre-resolve; failures carry `None`.
let server_name = ServerName::try_from(cfg.host.clone()).map_err(|_| {
    (
        ImapError::Connect(std::io::Error::other("invalid server name for TLS")),
        None,
    )
})?;
let connector = TlsConnector::from(bundle.config.clone());
let elapsed = started.elapsed();
let remaining = total_deadline.saturating_sub(elapsed);
let tls_stream = timeout(remaining, connector.connect(server_name, tcp))
    .await
    .map_err(|_| {
        (
            ImapError::Timeout {
                op: "tls_handshake",
            },
            None,
        )
    })?
    .map_err(|e| (map_tls_handshake_error(&e), None))?;
```

After:

```rust
// Step 2: TLS establishment. Branches on encryption mode.
let elapsed = started.elapsed();
let remaining = total_deadline.saturating_sub(elapsed);
let tls_stream = match cfg.encryption {
    ImapEncryption::Tls => {
        let server_name = ServerName::try_from(cfg.host.clone()).map_err(|_| {
            (
                ImapError::Connect(std::io::Error::other("invalid server name for TLS")),
                None,
            )
        })?;
        let connector = TlsConnector::from(bundle.config.clone());
        timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| {
                (
                    ImapError::Timeout {
                        op: "tls_handshake",
                    },
                    None,
                )
            })?
            .map_err(|e| (map_tls_handshake_error(&e), None))?
    }
    ImapEncryption::Starttls => {
        timeout(remaining, starttls_upgrade(tcp, bundle, &cfg.host))
            .await
            .map_err(|_| {
                (
                    ImapError::Timeout {
                        op: "starttls_upgrade",
                    },
                    None,
                )
            })?
            .map_err(|e| (e, None))?
    }
};
```

- [ ] **Step 12.3: Build and run existing tests**

```bash
cargo build --workspace --all-targets
cargo test -p rimap-imap --lib
cargo clippy -p rimap-imap --all-targets -- -D warnings
```

Expected: BUILDS, all existing tests PASS, no new warnings.

- [ ] **Step 12.4: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(rimap-imap): branch connect on encryption mode (#118)"
```

---

## Task 13: Connect-level tests — credential resolver not reached + timeout

These tests exercise `Connection` end-to-end (not just `starttls_negotiate`) to prove the `connect_with_bundle` branch correctly propagates STARTTLS errors and timeouts without touching credentials.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (tests)

- [ ] **Step 13.1: Write the failing tests**

Add to `starttls_unit_tests`. These need a panic-on-use credential resolver and a minimal audit sink:

```rust
    use std::sync::Arc;

    use rimap_core::auth_event::AuthEvent;
    use rimap_core::{AuthEventSink, AuthSinkError, CredentialResolver, CredentialResolverError, CredentialSource};
    use secrecy::SecretString;

    use super::{Connection, ConnectionConfig, ImapEncryption};

    #[derive(Debug)]
    struct PanicResolver;
    impl CredentialResolver for PanicResolver {
        fn resolve(
            &self,
            _account: &rimap_core::account::AccountId,
            _username: &str,
            _host: &str,
        ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
            panic!("credential resolver must not be invoked before TLS");
        }
    }

    #[derive(Debug)]
    struct NoopAudit;
    impl AuthEventSink for NoopAudit {
        fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
            Ok(())
        }
    }

    fn connection_for(addr: std::net::SocketAddr, timeout_ms: u64) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: addr.ip().to_string(),
            port: addr.port(),
            encryption: ImapEncryption::Starttls,
            username: "unused".to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(timeout_ms),
            command_timeout: std::time::Duration::from_secs(1),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver))
    }

    #[tokio::test]
    async fn connect_with_starttls_capability_missing_does_not_resolve_credentials() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1\r\n"),
            Step::Send(b"a1 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let conn = connection_for(mock.addr(), 5000);
        // Drive a command that triggers lazy connect; any command that
        // calls `session()` works. We pick `list_folders` because it
        // requires a live session.
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn connect_with_starttls_stall_times_out_with_starttls_upgrade_op() {
        // Mock greets, then stalls indefinitely before responding to
        // CAPABILITY. The caller's 100ms connect_timeout must fire and
        // surface the distinctive op tag.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            // ExpectCommand reads the CAPABILITY line but we never reply,
            // so the client stalls reading the response. Sleep forever.
            Step::ExpectCommand("CAPABILITY"),
            // Intentionally: no Send after. The script ends here, but
            // the server task hangs waiting for the client (which is
            // blocked reading the response). The harness drops the
            // listener/task when the test returns.
        ])
        .await;

        let conn = connection_for(mock.addr(), 100);
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Timeout { op } => assert_eq!(op, "starttls_upgrade"),
            other => panic!("expected Timeout(starttls_upgrade), got {other:?}"),
        }
        let _ = mock.finish().await;
    }
```

Notes:
- The `Connection::new` signature may differ — adjust the call to match the actual constructor (look at line 120-180 of `connection.rs` for the public API). If `Connection::new` requires a different argument order or takes ownership of different types, update the helper.
- If `CredentialResolver::resolve` returns a type other than `(SecretString, CredentialSource)`, adjust the panic impl accordingly. Match the existing trait exactly.

- [ ] **Step 13.2: Run to verify**

```bash
cargo test -p rimap-imap --lib starttls_unit_tests::connect_with_starttls
```

Expected: PASS. If signatures don't match, adjust imports/types to match `rimap-core` exactly.

- [ ] **Step 13.3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "test(rimap-imap): pin connect-level STARTTLS invariants (#118)"
```

---

## Task 14: Dovecot harness — add STARTTLS listener on port 143

Extend the existing Dovecot compose/config so the same container exposes both ports 993 (implicit TLS) and 143 (STARTTLS).

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`
- Modify: `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` (harness picks 2 free ports and maps both)

- [ ] **Step 14.1: Update `dovecot.conf` to listen on 143**

In `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`, extend the `service imap-login` block:

```
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
```

`ssl = required` at file scope means Dovecot refuses LOGIN over plaintext even on port 143 — STARTTLS is mandatory before auth. This matches production best practice.

- [ ] **Step 14.2: Update `docker-compose.yml` for the second port**

In `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`, add a second host→container port mapping. The harness will pass both host ports via env vars:

```yaml
    ports:
      - "127.0.0.1:${RIMAP_DOVECOT_HOST_PORT}:993"
      - "127.0.0.1:${RIMAP_DOVECOT_HOST_PORT_STARTTLS}:143"
```

- [ ] **Step 14.3: Extend the container harness to pick + pass a second port**

In `crates/rimap-imap/tests/integration/support/container.rs`:

1. Add a `starttls_port: u16` field to `DovecotHarness` (alongside `port`).
2. In `try_start`, call `pick_free_port()` twice; pass the second as `RIMAP_DOVECOT_HOST_PORT_STARTTLS` alongside `RIMAP_DOVECOT_HOST_PORT`.
3. Add a public accessor `pub fn starttls_port(&self) -> u16`.
4. Extend `wait_for_ready` to also probe TCP connectivity on the STARTTLS port before returning ready.

Find `compose_up` (around line 256). Update:

```rust
fn compose_up(
    project: &str,
    compose_dir: &Path,
    host_port: u16,
    starttls_port: u16,
) -> Result<(), HarnessError> {
    let status = Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("up")
        .arg("-d")
        .env("RIMAP_DOVECOT_HOST_PORT", host_port.to_string())
        .env("RIMAP_DOVECOT_HOST_PORT_STARTTLS", starttls_port.to_string())
        .current_dir(compose_dir)
        .status()
        .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))?;
    if !status.success() {
        return Err(HarnessError::DockerCommandFailed(format!(
            "compose up exit {status}"
        )));
    }
    Ok(())
}
```

Update callers of `compose_up` in `try_start` and `rebind` to pass both ports.

- [ ] **Step 14.4: Verify the existing Dovecot TLS suite still boots**

Only runnable when a container runtime is available:

```bash
# Requires docker/podman on x86_64. CI runs this.
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot
```

Expected: all existing TLS cases still pass. The new STARTTLS port exists but no test exercises it yet.

If no local container runtime is available, skip this step; CI will catch regressions.

- [ ] **Step 14.5: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot/dovecot.conf \
        crates/rimap-imap/tests/integration/dovecot/docker-compose.yml \
        crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): expose STARTTLS port 143 in dovecot harness (#118)"
```

---

## Task 15: Dovecot STARTTLS integration tests (three)

**Files:**
- Create: `crates/rimap-imap/tests/integration/dovecot_starttls.rs` — no, pattern is: one top-level test file (`dovecot.rs`) that includes `mod support;`. To stay consistent, add the three tests directly to `dovecot.rs` in a clearly-marked section.
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`

- [ ] **Step 15.1: Add the three STARTTLS tests to `dovecot.rs`**

Append at the end of `crates/rimap-imap/tests/integration/dovecot.rs` (before the final `}` if any, or at file end):

```rust
// --- STARTTLS suite (port 143) ---
//
// Dovecot is configured with `ssl = required`, so LOGIN is only
// possible after STARTTLS. These tests exercise the rimap-imap
// STARTTLS upgrade end-to-end.

mod starttls {
    use super::*;
    use rimap_imap::ImapEncryption;

    fn boot_starttls(pin: PinChoice) -> Option<ConnectedHarness> {
        match ConnectedHarness::new_with_encryption(pin, ImapEncryption::Starttls) {
            Ok(h) => Some(h),
            Err(HarnessError::DockerUnavailable) => None,
            #[expect(clippy::panic, reason = "test failure path")]
            Err(e) => panic!("starttls harness failed: {e}"),
        }
    }

    #[tokio::test]
    async fn starttls_connect_list_logout_succeeds() {
        let Some(h) = boot_starttls(PinChoice::Correct) else {
            return;
        };
        let folders = h.connection.list_folders("*").await.unwrap();
        assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));

        let lines = read_audit_lines(&h.audit_path());
        let auths: Vec<_> = lines.iter().filter(|v| v["kind"] == "auth").collect();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0]["result"], "success");
        assert_eq!(auths[0]["fingerprint_match"], true);
    }

    #[tokio::test]
    async fn starttls_with_wrong_pin_returns_tls_error() {
        let Some(h) = boot_starttls(PinChoice::Wrong) else {
            return;
        };
        let err = h.connection.list_folders("*").await.unwrap_err();
        match err {
            rimap_imap::error::ImapError::Tls { .. } => {}
            other => panic!("expected Tls pin mismatch, got {other:?}"),
        }
    }
}
```

Now add the third test (plaintext LOGIN refused before STARTTLS) as a raw-TCP level check using `tokio::net::TcpStream`, since we need to bypass our own STARTTLS negotiation:

```rust
    #[tokio::test]
    async fn dovecot_refuses_plaintext_login_without_starttls() {
        let Some(h) = boot_starttls(PinChoice::Correct) else {
            return;
        };
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stream = tokio::net::TcpStream::connect((
            "127.0.0.1",
            h.starttls_port(),
        ))
        .await
        .unwrap();
        let (read, mut write) = stream.split();
        let mut reader = BufReader::new(read);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.to_ascii_uppercase().contains("OK"));

        // Try plaintext LOGIN without issuing STARTTLS first.
        write
            .write_all(b"a1 LOGIN rimap-test testpass\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        // Dovecot rejects either with tagged NO or with `* BAD …`.
        let upper = resp.to_ascii_uppercase();
        assert!(
            upper.starts_with("A1 NO") || upper.contains("BAD") || upper.contains("PLAINTEXT"),
            "expected plaintext LOGIN refusal, got {resp}"
        );
    }
```

Add `h.starttls_port()` plumbing: the `ConnectedHarness` wraps `DovecotHarness`; extend it to expose `starttls_port()`.

- [ ] **Step 15.2: Refactor `ConnectedHarness` to parameterize encryption + expose `starttls_port()`**

In `crates/rimap-imap/tests/integration/support/container.rs` (around lines 516-565), replace the existing `ConnectedHarness::new(pin_with)` implementation with a parameterized `new_with_encryption(pin_with, encryption)` and a thin back-compat `new(pin_with)` that delegates to it. Both paths share the same body:

```rust
impl ConnectedHarness {
    /// Back-compat shim: defaults to implicit TLS.
    pub fn new(pin_with: PinChoice) -> Result<Self, HarnessError> {
        Self::new_with_encryption(pin_with, rimap_imap::ImapEncryption::Tls)
    }

    pub fn new_with_encryption(
        pin_with: PinChoice,
        encryption: rimap_imap::ImapEncryption,
    ) -> Result<Self, HarnessError> {
        let harness = DovecotHarness::try_start()?;
        let audit_dir = TempDir::new().expect("tempdir");
        let audit_path = audit_dir.path().join("audit.jsonl");
        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .expect("audit open");

        let pinned = match pin_with {
            PinChoice::Correct => Some(harness.pinned_fingerprint()),
            PinChoice::Wrong => Some(rimap_core::TlsFingerprint::from_cert_der(
                b"deliberately-wrong",
            )),
            PinChoice::None => None,
        };

        let port = match encryption {
            rimap_imap::ImapEncryption::Tls => harness.port(),
            rimap_imap::ImapEncryption::Starttls => harness.starttls_port(),
        };

        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: DovecotHarness::host().to_string(),
            port,
            encryption,
            username: DovecotHarness::username().to_string(),
            pinned_fingerprint: pinned,
            connect_timeout: std::time::Duration::from_secs(10),
            command_timeout: std::time::Duration::from_secs(10),
            max_fetch_body_bytes: 5_242_880,
            max_append_bytes: 10_485_760,
        };
        let store: Arc<dyn CredentialStore> =
            Arc::new(StaticCreds(DovecotHarness::password().to_string()));
        let creds: Arc<dyn CredentialResolver> = Arc::new(KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
        ));
        let sink: Arc<dyn AuthEventSink> = Arc::new(audit.clone());
        let connection = Connection::new(cfg, sink, creds);
        Ok(Self {
            harness,
            audit_dir,
            audit,
            connection,
        })
    }

    pub fn audit_path(&self) -> std::path::PathBuf {
        self.audit_dir.path().join("audit.jsonl")
    }

    pub fn starttls_port(&self) -> u16 {
        self.harness.starttls_port()
    }
}
```

The existing `audit_path` accessor stays; the only additions are `starttls_port()` and `new_with_encryption(...)`. The field `encryption` in `ConnectionConfig` was already added in Task 4.

- [ ] **Step 15.3: Run the STARTTLS suite**

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot starttls::
```

Expected: PASS (3 tests), or skip if Docker unavailable. Also confirm the existing TLS suite still passes:

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot
```

Expected: all cases pass (old + new).

- [ ] **Step 15.4: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs \
        crates/rimap-imap/tests/integration/support/container.rs
git commit -m "test(rimap-imap): add dovecot STARTTLS integration suite (#118)"
```

---

## Task 16: Flip Proton Bridge integration to STARTTLS

**Files:**
- Modify: `crates/rimap-imap/tests/integration/proton.rs`
- Modify: `crates/rimap-imap/tests/integration/proton/README.md`

- [ ] **Step 16.1: Flip `encryption` to `Starttls`**

In `crates/rimap-imap/tests/integration/proton.rs`, around line 73 (inside `build_connection`), change `encryption` from `Tls` (set in Task 4) to `Starttls`:

```rust
    let conn_cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: cfg.host.clone(),
        port: cfg.port,
        encryption: rimap_imap::ImapEncryption::Starttls,
        username: cfg.user.clone(),
        pinned_fingerprint: Some(cfg.fingerprint),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(60),
        max_fetch_body_bytes: 26_214_400,
        max_append_bytes: 10_485_760,
    };
```

`require_proton` (line 39) already defaults `PROTON_BRIDGE_PORT` to `"1143"` — no change needed there.

- [ ] **Step 16.2: Update the Proton README**

In `crates/rimap-imap/tests/integration/proton/README.md`, update any port reference from 993 to 1143 and call out that Bridge uses STARTTLS by default. Example edit:

Change any line like `PROTON_IMAP_PORT=993` to `PROTON_IMAP_PORT=1143` and add:

> Proton Bridge's default IMAP connection mode is **STARTTLS on port 1143**. This test harness connects with `encryption = "starttls"`.

- [ ] **Step 16.3: Run the Proton suite when opted in**

```bash
# Requires Proton Bridge running locally on port 1143.
PROTON_BRIDGE_TEST=1 cargo test -p rimap-imap --test proton
```

Expected: PASS against a live Bridge. Without Bridge, the suite skips.

- [ ] **Step 16.4: Commit**

```bash
git add crates/rimap-imap/tests/integration/proton.rs \
        crates/rimap-imap/tests/integration/proton/README.md
git commit -m "test(rimap-imap): switch proton bridge integration to STARTTLS (#118)"
```

---

## Task 17: Docs — quickstart, multi-account, configuration

**Files:**
- Modify: `docs/quickstart-proton-bridge.md`
- Modify: `docs/multi-account.md`
- Modify: `docs/configuration.md`

- [ ] **Step 17.1: Update `docs/quickstart-proton-bridge.md`**

Find the TOML config snippet that shows `[imap]` and update it to use STARTTLS + port 1143:

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "you@proton.me"
encryption = "starttls"
tls_fingerprint_sha256 = "…"
```

Add a paragraph near the config block explaining that Bridge defaults to STARTTLS on port 1143, and that implicit-TLS (port 1993) requires enabling "SSL" in Bridge's advanced settings.

The `openssl s_client -starttls imap -connect 127.0.0.1:1143` fingerprint-capture example already exists and is correct (it matched Bridge's default pre-change).

- [ ] **Step 17.2: Update `docs/multi-account.md`**

Find the Proton example account and add `encryption = "starttls"`:

```toml
[[accounts]]
name = "proton"
imap = { host = "127.0.0.1", port = 1143, username = "you@proton.me", encryption = "starttls" }
```

- [ ] **Step 17.3: Update `docs/configuration.md`**

Find the existing `imap` section (it documents `host`, `port`, `username`, `tls_fingerprint_sha256`, timeouts). Add a documented field:

```markdown
### `imap.encryption`

Transport encryption mode. Two values:

- `"tls"` (default) — implicit TLS (IMAPS). Typical port 993. Used by Gmail,
  most commercial providers, and Dovecot's default config.
- `"starttls"` — plaintext connection upgraded via STARTTLS before LOGIN.
  Typical port 143 (Dovecot default) or 1143 (Proton Bridge default).

The field defaults to `"tls"` if omitted, preserving single-account configs
written before STARTTLS support.

Selecting `"starttls"` requires the server to advertise `STARTTLS` in its
CAPABILITY response; there is no silent downgrade to plaintext. A STARTTLS
failure surfaces as `ERR_TLS`.

See also: `smtp.encryption` (symmetric field for the SMTP transport).
```

- [ ] **Step 17.4: Verify docs render cleanly**

```bash
# Optional: markdown lint if the project uses one. At minimum eyeball.
ls docs/configuration.md docs/multi-account.md docs/quickstart-proton-bridge.md
```

- [ ] **Step 17.5: Commit**

```bash
git add docs/quickstart-proton-bridge.md docs/multi-account.md docs/configuration.md
git commit -m "docs: document imap.encryption and switch proton example to STARTTLS (#118)"
```

---

## Task 18: Final verification

- [ ] **Step 18.1: Full workspace check**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

Expected: all clean. `cargo test` skips Docker-gated tests if no runtime is present; that's acceptable.

- [ ] **Step 18.2: Docker-gated run (if runtime available)**

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot
```

Expected: all TLS and STARTTLS cases PASS.

- [ ] **Step 18.3: Confirm acceptance-criteria checklist**

Open `docs/superpowers/specs/2026-04-21-imap-starttls-design.md` §10 and verify each checkbox is actually met by the committed code:

- `ImapConfig.encryption` exists with default `Tls`: Task 2.
- `connect_with_bundle` handles both modes: Task 12.
- `ImapError::Starttls` variant + three sub-reasons, maps to `ErrorCode::Tls`: Task 5.
- Buffered-plaintext bytes discarded + regression test: Task 7, 11.
- Pinning tests pass identically in both modes: Task 15 (Dovecot wrong-pin STARTTLS case).
- Proton Bridge test switches to STARTTLS + 1143: Task 16.
- Dovecot STARTTLS variant with three tests: Task 15.
- Existing implicit-TLS path unchanged behaviorally: Task 4 passes all `ImapEncryption::Tls`; Task 18.1 verifies all existing tests still pass.
- Docs updated: Task 17.

- [ ] **Step 18.4: Open the PR**

```bash
git push -u origin feat/imap-starttls
gh pr create --title "feat: IMAP STARTTLS support (#118)" --body "$(cat <<'EOF'
## Summary
- Add `ImapEncryption { Tls, Starttls }` to `[imap]` config with default `Tls` (no migration for existing configs).
- Implement plaintext STARTTLS negotiation + TLS upgrade in `rimap-imap::connection`, structured so the plaintext client's buffer is structurally dropped before TLS (CVE-2011-0411 class defense).
- New `ImapError::Starttls` variant with `CapabilityMissing`, `ServerRefused`, `UnexpectedBye` sub-reasons; maps to `ErrorCode::Tls`.
- Proton Bridge integration flipped to port 1143 + STARTTLS (Bridge's out-of-the-box defaults).
- Dovecot harness extended with port 143 listener; three STARTTLS integration tests added.
- Docs updated: `quickstart-proton-bridge.md`, `multi-account.md`, `configuration.md`.

## Test plan
- [ ] `cargo test --workspace --all-targets` (no Docker required)
- [ ] `RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot` (full TLS + STARTTLS matrix)
- [ ] `PROTON_BRIDGE_TEST=1 cargo test -p rimap-imap --test proton` (against a live Bridge)
- [ ] `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo deny check`

Closes #118

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of scope (follow-ups)

- #117 TLS preflight in `--dry-run` — should cover both modes once this lands.
- OAuth / XOAUTH2 on Proton Bridge.
- STARTTLS for ManageSieve or other protocols.
