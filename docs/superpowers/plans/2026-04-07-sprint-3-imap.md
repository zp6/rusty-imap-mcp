# Sprint 3 — IMAP Connection, TLS Pinning, Read Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `rimap-imap` crate body — `Connection` over `async-imap` with custom TLS fingerprint pinning, read-only IMAP operations, `Auth` audit emission on every connect attempt, and a Dovecot-in-Docker integration suite.

**Architecture:** Single `tokio::sync::Mutex<Option<Session>>` per `Connection` (one IMAP session per account, lazy-connect, TCP-half-open detection without auto-retry). Custom `rustls::ServerCertVerifier` does SHA-256 leaf-DER fingerprint pinning when configured, falls back to webpki-roots otherwise. The verifier captures the observed fingerprint into a `OnceLock` for the `Auth` audit record, which is emitted via `tokio::task::spawn_blocking` so the std-mutex audit lock never crosses an `.await`.

**Tech Stack:** Rust 2024 (MSRV 1.88.0), tokio 1.42, async-imap 0.10, tokio-rustls 0.26, rustls 0.23, webpki-roots 0.26, subtle 2 (constant-time fingerprint eq), existing workspace crates `rimap-core`, `rimap-config`, `rimap-audit`.

**Spec:** [`docs/superpowers/specs/2026-04-07-sprint-3-imap-design.md`](../specs/2026-04-07-sprint-3-imap-design.md)

**Branch:** `feat/sprint-3-implementation` (already created, currently at `ce80835`).

**Hard-won context to surface to every implementer:**

- Workspace pins `rand = "0.8"` — `rand::thread_rng()`, NOT `rand::rng()`. Do not bump.
- `ulid = "=1.1.4"` exact pin — must not change.
- `fs4 = "0.13"` — `fs4::fs_std::FileExt` is the trait import for `std::fs::File`.
- Internal crate deps use `path = "..."` + `version = "0.0.0"`, NOT workspace deps (cargo-deny wildcard ban).
- `Timestamp::from_offset` clamps leap-second nanoseconds to 999_999_999 — preserve.
- `crates/rimap-audit/src/fs_ext.rs::writer_open_options()` — every audit file open in the audit crate goes through this helper. Do not bypass.
- Audit lock (`std::sync::Mutex` inside `AuditWriter::Inner`) MUST NEVER be held across an `.await`. Sprint 3 calls into `AuditWriter::log_*` from async code via `tokio::task::spawn_blocking`.
- Stdout is reserved for MCP transport. Tracing → stderr.
- `cargo deny check` is part of CI. Existing skips: `hashbrown 0.14`, `windows-sys 0.48/0.52/0.59`. Do NOT add new skips — `cargo update` first.
- Workspace clippy lints: `unwrap_used = "deny"`, `expect_used = "warn"`, `panic = "deny"`, `print_stdout = "deny"`, `print_stderr = "deny"`, `await_holding_lock = "deny"`, no `_ =>` wildcards, no `matches!` macro, no `dbg!`/`todo!`. `unreachable!` is allowed. Tests use `#[expect(clippy::unwrap_used, reason = "tests")]` on the test module.
- 100-line function limit (`too_many_lines`).
- `let _ = write!(...)` is the canonical way to discard an infallible write result.
- Pre-commit: `prek` runs on every commit. NEVER use `--no-verify`. `end-of-file-fixer` may force a re-stage.
- Branch protection requires 7 checks: rustfmt, clippy, test (stable), test (MSRV 1.88.0), cargo-deny, zizmor, SonarQube.

---

## Task 1: TlsFingerprint newtype in rimap-core

**Goal:** Pure type addition. Closes #21.

**Files:**
- Create: `crates/rimap-core/src/tls.rs`
- Modify: `crates/rimap-core/src/lib.rs`
- Modify: `crates/rimap-core/Cargo.toml`
- Modify: `Cargo.toml` (workspace deps: add `subtle`, `sha2`, `hex`)

- [ ] **Step 1: Add `subtle`, `sha2`, `hex` to workspace dependencies if missing**

`sha2` and `hex` are already in `[workspace.dependencies]` (used by `rimap-audit`). Add `subtle` only.

Edit `Cargo.toml`, after the `hex = "0.4"` line in `[workspace.dependencies]`:

```toml
subtle = "2"
```

- [ ] **Step 2: Add `subtle`, `sha2`, `hex`, `serde` to rimap-core deps**

Edit `crates/rimap-core/Cargo.toml`, in `[dependencies]`:

```toml
subtle = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
serde = { workspace = true }
```

(Check existing `[dependencies]` block first; `serde` may already be present.)

- [ ] **Step 3: Write the failing test for `TlsFingerprint::from_hex`**

Create `crates/rimap-core/src/tls.rs`:

```rust
//! SHA-256 TLS certificate fingerprint newtype. Used by `rimap-config` to
//! parse the configured pin, by `rimap-imap` to compare against the observed
//! cert during the TLS handshake, and by `rimap-audit` to record both.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256 fingerprint of a TLS leaf certificate (DER bytes).
///
/// Equality is constant-time. There is intentionally no `Debug` impl that
/// dumps the bytes as hex; use `Display` (`to_hex`) at the explicit point
/// of need.
#[derive(Clone, Copy, Eq)]
pub struct TlsFingerprint([u8; 32]);

/// Failure modes for parsing a hex-encoded fingerprint string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintParseError {
    /// Wrong number of hex characters (expected 64, optionally separated by colons).
    WrongLength {
        /// Number of hex chars after stripping colons.
        got: usize,
    },
    /// Encountered a non-hex character.
    NonHex {
        /// The offending character.
        ch: char,
    },
}

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => {
                write!(f, "fingerprint must be 64 hex chars, got {got}")
            }
            Self::NonHex { ch } => write!(f, "non-hex character `{ch}` in fingerprint"),
        }
    }
}

impl std::error::Error for FingerprintParseError {}

impl TlsFingerprint {
    /// Parse a hex-encoded fingerprint, ignoring colon separators.
    /// Accepts both `"AB:CD:..."` and `"abcd..."` forms; case-insensitive.
    ///
    /// # Errors
    /// Returns `FingerprintParseError` on length or character violations.
    pub fn from_hex(s: &str) -> Result<Self, FingerprintParseError> {
        let cleaned: String = s.chars().filter(|c| *c != ':').collect();
        if cleaned.len() != 64 {
            return Err(FingerprintParseError::WrongLength { got: cleaned.len() });
        }
        for c in cleaned.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(FingerprintParseError::NonHex { ch: c });
            }
        }
        let bytes = hex::decode(&cleaned).unwrap_or_else(|_| {
            unreachable!("validated 64 ascii hex chars above")
        });
        let arr: [u8; 32] = bytes
            .try_into()
            .unwrap_or_else(|_| unreachable!("64 hex chars decode to 32 bytes"));
        Ok(Self(arr))
    }

    /// Compute the fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn from_cert_der(der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(der);
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Borrow the raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, no separators (matches the audit log on-disk format).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Uppercase hex with colon separators (matches `openssl x509 -fingerprint -sha256`).
    #[must_use]
    pub fn to_hex_colon(&self) -> String {
        let hex_str = hex::encode_upper(self.0);
        let mut out = String::with_capacity(95);
        for (i, c) in hex_str.chars().enumerate() {
            if i > 0 && i.is_multiple_of(2) {
                out.push(':');
            }
            out.push(c);
        }
        out
    }
}

impl PartialEq for TlsFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking the bytes in arbitrary debug logs; surface only that
        // a fingerprint is present.
        f.write_str("TlsFingerprint(<redacted>)")
    }
}

impl Serialize for TlsFingerprint {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for TlsFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(de)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{FingerprintParseError, TlsFingerprint};

    const SAMPLE_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn from_hex_accepts_lowercase_no_separators() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        assert_eq!(fp.to_hex(), SAMPLE_HEX);
    }

    #[test]
    fn from_hex_accepts_uppercase_with_colons() {
        let with_colons =
            "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:\
             01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF";
        let fp = TlsFingerprint::from_hex(with_colons).unwrap();
        assert_eq!(fp.to_hex(), SAMPLE_HEX);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let err = TlsFingerprint::from_hex("abcd").unwrap_err();
        assert_eq!(err, FingerprintParseError::WrongLength { got: 4 });
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        let bad = "g".repeat(64);
        let err = TlsFingerprint::from_hex(&bad).unwrap_err();
        assert_eq!(err, FingerprintParseError::NonHex { ch: 'g' });
    }

    #[test]
    fn from_cert_der_matches_known_sha256() {
        // sha256("hello") in lowercase hex.
        let fp = TlsFingerprint::from_cert_der(b"hello");
        assert_eq!(
            fp.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn equality_is_constant_time_in_observable_behavior() {
        let a = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let b = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let c = TlsFingerprint::from_hex(&"f".repeat(64)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn to_hex_colon_matches_openssl_format() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let colon = fp.to_hex_colon();
        assert_eq!(colon.len(), 64 + 31, "32 bytes + 31 colons");
        assert!(colon.starts_with("01:23:45"));
        assert!(colon.chars().all(|c| c == ':' || c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let debug = format!("{fp:?}");
        assert!(!debug.contains("0123"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn serde_round_trips_as_lowercase_hex_string() {
        let fp = TlsFingerprint::from_hex(SAMPLE_HEX).unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, format!("\"{SAMPLE_HEX}\""));
        let back: TlsFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fp);
    }
}
```

> **Note for implementer:** This test file uses `serde_json` in tests, which may not yet be a dev-dep of `rimap-core`. If the build fails with "unresolved import", add `serde_json = { workspace = true }` under `[dev-dependencies]` in `crates/rimap-core/Cargo.toml`.

- [ ] **Step 4: Wire `tls` module into rimap-core lib.rs**

Edit `crates/rimap-core/src/lib.rs`. After the existing `pub mod tool;` line, add:

```rust
pub mod tls;
```

After the existing `pub use crate::tool::{...}` line, add:

```rust
pub use crate::tls::{FingerprintParseError, TlsFingerprint};
```

- [ ] **Step 5: Run the tests**

```bash
cargo test -p rimap-core --lib tls::tests
```

Expected: 8 tests pass.

If `serde_json` is missing as a dev-dep, the error will be `unresolved import 'serde_json'`. Add it to `[dev-dependencies]` and retry.

- [ ] **Step 6: Run clippy on the new code**

```bash
cargo clippy -p rimap-core --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/rimap-core/Cargo.toml crates/rimap-core/src/tls.rs crates/rimap-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(core): add TlsFingerprint newtype with constant-time eq

SHA-256 leaf-DER fingerprint type used by rimap-config (parses the
configured pin), rimap-imap (compares against the observed cert), and
rimap-audit (serializes into the Auth record). Uses `subtle` for
constant-time equality and intentionally redacts in Debug to avoid
leaking the bytes through unrelated trace logs.

Closes #21.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: rimap-config — parse fingerprint into TlsFingerprint, add connect_timeout_seconds

**Goal:** `ValidatedConfig` carries a parsed `Option<TlsFingerprint>`. New `imap.connect_timeout_seconds` field with a 10-second serde default.

**Files:**
- Modify: `crates/rimap-config/Cargo.toml` (add `rimap-core` dep if missing)
- Modify: `crates/rimap-config/src/model.rs` — add `connect_timeout_seconds`
- Modify: `crates/rimap-config/src/validate.rs` — return `Option<TlsFingerprint>`
- Modify: `crates/rimap-config/src/lib.rs` — re-export the parsed type

- [ ] **Step 1: Verify `rimap-core` is already a dep of `rimap-config`**

```bash
grep -n "rimap-core" crates/rimap-config/Cargo.toml
```

Expected: one match. If absent, add under `[dependencies]`:

```toml
rimap-core = { path = "../rimap-core", version = "0.0.0" }
```

- [ ] **Step 2: Add `connect_timeout_seconds` to `ImapConfig`**

Edit `crates/rimap-config/src/model.rs`. In the `ImapConfig` struct (around line 35), add a field after `command_timeout_seconds`:

```rust
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake + greeting + CAPABILITY probe deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}
```

And add a default function next to the existing `default_command_timeout`:

```rust
fn default_command_timeout() -> u32 {
    30
}

fn default_connect_timeout() -> u32 {
    10
}
```

- [ ] **Step 3: Write the failing test in validate.rs**

Edit `crates/rimap-config/src/validate.rs`. In the existing test module (find it via `grep -n "mod tests" crates/rimap-config/src/validate.rs`), add:

```rust
#[test]
fn validate_returns_parsed_tls_fingerprint() {
    let mut cfg = sample_valid_config();
    cfg.imap.tls_fingerprint_sha256 = Some(
        "0123456789abcdef0123456789abcdef\
         0123456789abcdef0123456789abcdef"
            .to_string(),
    );
    let validated = validate(cfg).unwrap();
    let fp = validated.tls_fingerprint.expect("fingerprint should be set");
    assert_eq!(
        fp.to_hex(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn validate_returns_none_when_fingerprint_absent() {
    let cfg = sample_valid_config();
    let validated = validate(cfg).unwrap();
    assert!(validated.tls_fingerprint.is_none());
}

#[test]
fn validate_uses_default_connect_timeout_when_unset() {
    let cfg = sample_valid_config();
    let validated = validate(cfg).unwrap();
    assert_eq!(validated.config.imap.connect_timeout_seconds, 10);
}
```

If `sample_valid_config()` doesn't already exist as a test helper in this module, look for whatever the existing tests use to construct a valid `Config` and reuse it. If nothing exists, define one at the top of the test module — read three or four existing tests in the file first to copy the pattern.

- [ ] **Step 4: Extend `ValidatedConfig` to carry the parsed fingerprint**

Edit the struct definition in `crates/rimap-config/src/validate.rs`:

```rust
use rimap_core::tls::TlsFingerprint;

/// Validated config: a `Config` plus the resolved per-tool override map
/// keyed by `ToolName`, plus the parsed TLS fingerprint (if any).
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The underlying parsed config (untouched).
    pub config: Config,
    /// Resolved per-tool overrides.
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
    /// Parsed pinned TLS fingerprint, if `imap.tls_fingerprint_sha256` was set.
    pub tls_fingerprint: Option<TlsFingerprint>,
}
```

- [ ] **Step 5: Replace `validate_fingerprint` with a parsing version**

Replace the existing `validate_fingerprint` function and its call site in `validate()`:

```rust
pub fn validate(config: Config) -> Result<ValidatedConfig, ConfigError> {
    let tls_fingerprint = parse_fingerprint(config.imap.tls_fingerprint_sha256.as_deref())?;
    validate_limits(&config)?;
    validate_paths(&config)?;
    let tool_overrides = resolve_tool_overrides(&config)?;
    Ok(ValidatedConfig {
        config,
        tool_overrides,
        tls_fingerprint,
    })
}

fn parse_fingerprint(maybe_fp: Option<&str>) -> Result<Option<TlsFingerprint>, ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(None);
    };
    let fp = TlsFingerprint::from_hex(raw).map_err(|e| ConfigError::TlsFingerprint {
        reason: e.to_string(),
    })?;
    Ok(Some(fp))
}
```

Delete the old `validate_fingerprint` function entirely. The error variant `ConfigError::TlsFingerprint { reason }` already exists from Sprint 1; do not change it.

- [ ] **Step 6: Re-export `TlsFingerprint` from rimap-config lib.rs (convenience)**

Edit `crates/rimap-config/src/lib.rs`. Find the existing `pub use rimap_core::...` if any, or just add a fresh re-export under the existing module declarations:

```rust
pub use rimap_core::tls::{FingerprintParseError, TlsFingerprint};
```

(If `rimap_core` is not yet imported at this scope, the line above is sufficient — Rust resolves through the dep graph.)

- [ ] **Step 7: Run the tests**

```bash
cargo test -p rimap-config
```

Expected: all existing tests still pass plus the three new ones.

If the existing fingerprint validation tests fail with a different error message, update them to match the new error path produced by `TlsFingerprint::from_hex`. The error variants are still `ConfigError::TlsFingerprint`, only the `reason` string changes.

- [ ] **Step 8: Run clippy**

```bash
cargo clippy -p rimap-config --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-config/Cargo.toml crates/rimap-config/src/model.rs crates/rimap-config/src/validate.rs crates/rimap-config/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(config): parse tls_fingerprint into TlsFingerprint, add connect_timeout

ValidatedConfig now carries a parsed Option<TlsFingerprint> alongside
the raw config, replacing the previous format-only check. Adds
imap.connect_timeout_seconds with a 10-second serde default — covers
TCP + TLS handshake + greeting + CAPABILITY in Sprint 3's
Connection::ensure_connected.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: AuditWriter per-process state (process_id, next_seq, initial_seq option)

**Goal:** `AuditWriter` tracks a per-process `ProcessId` set at open and an internal `next_seq` counter. Adds `initial_seq` to `AuditOptions` so callers can resume sequence numbering after a prior run. Existing `write_record` continues to accept caller-supplied seq for tests.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs` — add `process_id`, `next_seq`, `initial_seq`
- Existing tests in `writer.rs` continue to work — `write_record` still takes a fully-populated `AuditRecord`.

- [ ] **Step 1: Write the failing test for `process_id()` accessor**

Add to the existing `mod tests` in `crates/rimap-audit/src/writer.rs`:

```rust
#[test]
fn writer_holds_a_stable_process_id() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();
    let pid_a = writer.process_id();
    let pid_b = writer.process_id();
    assert_eq!(pid_a, pid_b);
}

#[test]
fn writer_allocates_sequential_seqs() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();
    let s1 = writer.allocate_seq().unwrap();
    let s2 = writer.allocate_seq().unwrap();
    let s3 = writer.allocate_seq().unwrap();
    assert_eq!(s1, crate::ids::Seq::FIRST);
    assert_eq!(s2, crate::ids::Seq(2));
    assert_eq!(s3, crate::ids::Seq(3));
}

#[test]
fn writer_resumes_seq_from_initial_seq_option() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq(42),
    })
    .unwrap();
    assert_eq!(writer.allocate_seq().unwrap(), crate::ids::Seq(42));
    assert_eq!(writer.allocate_seq().unwrap(), crate::ids::Seq(43));
}
```

- [ ] **Step 2: Add `initial_seq` to `AuditOptions`**

In `crates/rimap-audit/src/writer.rs`, modify `AuditOptions`:

```rust
/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
    /// First `Seq` value this writer will allocate. Callers compute this
    /// from `read_trailing_state(path).last_seq.map(Seq::next).unwrap_or(Seq::FIRST)`
    /// before calling `open`.
    pub initial_seq: crate::ids::Seq,
}
```

- [ ] **Step 3: Update existing tests in writer.rs that construct `AuditOptions`**

Run:

```bash
grep -n "AuditOptions {" crates/rimap-audit/src/writer.rs
```

Every existing match in the test module needs `initial_seq: crate::ids::Seq::FIRST` appended. Use sed-style mental edits — there should be ~7 matches. For each:

```rust
AuditOptions {
    path: path.clone(),
    rotate_bytes: 0,
    initial_seq: crate::ids::Seq::FIRST,  // ADD
}
```

Also check other files that may construct `AuditOptions`:

```bash
grep -rn "AuditOptions {" crates/ tests/ 2>/dev/null
```

Update every call site.

- [ ] **Step 4: Add `process_id` field and `next_seq` to writer state**

Modify `AuditWriter` and `Inner`:

```rust
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    process_id: crate::ids::ProcessId,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    pub(crate) bytes_written: u64,
    /// Next `Seq` value to hand out via `allocate_seq`.
    pub(crate) next_seq: crate::ids::Seq,
}
```

- [ ] **Step 5: Initialize `process_id` and `next_seq` in `AuditWriter::open`**

Find the `Ok(Self {` block in `open()` and replace it with:

```rust
        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            process_id: crate::ids::ProcessId::new_now(),
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
                next_seq: opts.initial_seq,
            })),
        })
```

- [ ] **Step 6: Add the `process_id()` and `allocate_seq()` accessors**

Add to `impl AuditWriter` (place near `path()` and `rotate_bytes()`):

```rust
    /// The process ID this writer was opened with. Stable for the lifetime
    /// of the writer.
    #[must_use]
    pub fn process_id(&self) -> crate::ids::ProcessId {
        self.process_id
    }

    /// Allocate the next monotonic `Seq` value. Locks the inner mutex
    /// briefly; never crosses an `.await`.
    ///
    /// # Errors
    /// Returns `AuditError::Write` if the internal mutex is poisoned.
    pub fn allocate_seq(&self) -> Result<crate::ids::Seq, AuditError> {
        let mut guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })?;
        let seq = guard.next_seq;
        guard.next_seq = seq.next();
        Ok(seq)
    }
```

- [ ] **Step 7: Run the tests**

```bash
cargo test -p rimap-audit --lib writer::tests
```

Expected: all tests pass, including the three new ones.

- [ ] **Step 8: Find and fix all out-of-crate `AuditOptions` callers**

```bash
grep -rn "AuditOptions {" crates/ 2>/dev/null
```

Likely matches: `crates/rimap-server/src/...`. Update each to include `initial_seq: rimap_audit::Seq::FIRST` (or `crate::ids::Seq::FIRST` inside `rimap-audit`). For Sprint 2 callers in `rimap-server` that don't yet do trailing-state lookup, `Seq::FIRST` is the right value — Task 6 will replace it with the proper trailing-state-derived value.

Run:

```bash
cargo build --workspace
```

Fix any compile errors by adding `initial_seq: ...` to `AuditOptions` constructions.

- [ ] **Step 9: Run the full audit test suite + workspace build**

```bash
cargo test -p rimap-audit
cargo build --workspace
```

Expected: green.

- [ ] **Step 10: Commit**

```bash
git add crates/rimap-audit/src/writer.rs crates/rimap-server/src/
git commit -m "$(cat <<'EOF'
feat(audit): per-process state on AuditWriter

AuditWriter now holds a stable ProcessId set at open time and a
next_seq counter inside Inner. AuditOptions gains an initial_seq field
so callers can resume from a prior run's trailing state. Existing
write_record stays caller-supplied for tests; Sprint 3 adds typed
helpers (log_auth, log_process_start) on top.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: AuditWriter::log_auth helper

**Goal:** Typed emission helper that allocates seq, stamps timestamp, wraps `Auth` payload, and writes via `write_record`.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs` — add `log_auth`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/rimap-audit/src/writer.rs`:

```rust
#[test]
fn log_auth_writes_one_record_with_allocated_seq() {
    use crate::record::{Auth, AuthResult};

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();

    let seq = writer
        .log_auth(Auth {
            result: AuthResult::Success,
            host: "127.0.0.1".to_string(),
            port: 993,
            username: "alice@example.test".to_string(),
            tls_fingerprint_sha256: Some("ab".repeat(32)),
            fingerprint_match: Some(true),
            error_code: None,
        })
        .unwrap();

    assert_eq!(seq, crate::ids::Seq::FIRST);
    drop(writer);

    let contents = std::fs::read_to_string(&path).unwrap();
    let line = contents.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["kind"], "auth");
    assert_eq!(v["seq"], 1);
    assert_eq!(v["result"], "success");
    assert_eq!(v["host"], "127.0.0.1");
    assert_eq!(v["fingerprint_match"], true);
}

#[test]
fn log_auth_uses_writer_process_id_for_every_record() {
    use crate::record::{Auth, AuthResult};

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();
    let pid = writer.process_id();

    let make = || Auth {
        result: AuthResult::Failure,
        host: "h".into(),
        port: 1,
        username: "u".into(),
        tls_fingerprint_sha256: None,
        fingerprint_match: None,
        error_code: Some("ERR_TLS".into()),
    };
    writer.log_auth(make()).unwrap();
    writer.log_auth(make()).unwrap();
    drop(writer);

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<serde_json::Value> = contents
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["process_id"], pid.to_string());
    assert_eq!(lines[1]["process_id"], pid.to_string());
    assert_eq!(lines[0]["seq"], 1);
    assert_eq!(lines[1]["seq"], 2);
}
```

- [ ] **Step 2: Implement `log_auth`**

Add to `impl AuditWriter` in `crates/rimap-audit/src/writer.rs`:

```rust
    /// Build an `auth` record from `payload`, allocate a seq, and write it.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_auth(&self, payload: crate::record::Auth) -> Result<crate::ids::Seq, AuditError> {
        let seq = self.allocate_seq()?;
        let record = crate::record::AuditRecord {
            seq,
            ts: crate::ids::Timestamp::now(),
            process_id: self.process_id,
            payload: crate::record::Payload::Auth(payload),
        };
        self.write_record(&record)?;
        Ok(seq)
    }
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p rimap-audit --lib writer::tests
```

Expected: all tests pass.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/writer.rs
git commit -m "$(cat <<'EOF'
feat(audit): log_auth helper on AuditWriter

Typed helper that allocates a seq, stamps Timestamp::now(), uses the
writer's stable process_id, and delegates to write_record. The first
production emission path for the Auth record variant — Sprint 3
rimap-imap calls this from spawn_blocking.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: AuditWriter::log_process_start helper

**Goal:** Typed helper for the chain-of-history process_start emission. Closes #24.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs` — add `log_process_start`, `ProcessStartInputs`
- Modify: `crates/rimap-audit/src/lib.rs` — re-export `ProcessStartInputs`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/rimap-audit/src/writer.rs`:

```rust
#[test]
fn log_process_start_populates_chain_of_history_fields() {
    use crate::record::Payload;
    use crate::self_check::TrailingState;
    use crate::writer::ProcessStartInputs;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();

    let prior_pid = crate::ids::ProcessId::new_now();
    let inputs = ProcessStartInputs {
        version: "0.0.0".to_string(),
        git_commit: String::new(),
        posture: "draft-safe".to_string(),
        config_path: std::path::PathBuf::from("/tmp/config.toml"),
        config_hash_sha256: "ab".repeat(32),
        trailing: TrailingState {
            last_seq: Some(crate::ids::Seq(99)),
            last_process_id: Some(prior_pid),
            last_recorded_inode: Some(7777),
        },
        current_inode: 8888,
    };
    let seq = writer.log_process_start(inputs).unwrap();
    assert_eq!(seq, crate::ids::Seq::FIRST);
    drop(writer);

    let contents = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
    assert_eq!(v["kind"], "process_start");
    assert_eq!(v["previous_last_seq"], 99);
    assert_eq!(v["previous_process_id"], prior_pid.to_string());
    assert_eq!(v["previous_file_inode"], 8888);
    assert_eq!(v["audit_file_inode_changed"], true);
}

#[test]
fn log_process_start_marks_inode_unchanged_when_matching() {
    use crate::self_check::TrailingState;
    use crate::writer::ProcessStartInputs;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
        initial_seq: crate::ids::Seq::FIRST,
    })
    .unwrap();

    let inputs = ProcessStartInputs {
        version: "0.0.0".to_string(),
        git_commit: String::new(),
        posture: "draft-safe".to_string(),
        config_path: std::path::PathBuf::from("/tmp/c.toml"),
        config_hash_sha256: "00".repeat(32),
        trailing: TrailingState {
            last_seq: None,
            last_process_id: None,
            last_recorded_inode: Some(4242),
        },
        current_inode: 4242,
    };
    writer.log_process_start(inputs).unwrap();
    drop(writer);

    let contents = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
    assert_eq!(v["audit_file_inode_changed"], false);
}
```

- [ ] **Step 2: Implement `ProcessStartInputs` and `log_process_start`**

Add near the bottom of `crates/rimap-audit/src/writer.rs`, before the `#[cfg(test)]` block:

```rust
/// Inputs to [`AuditWriter::log_process_start`]. Caller computes the
/// inode-tamper signal by passing the trailing state from
/// [`crate::self_check::read_trailing_state`] (run before `open`) and the
/// current inode (run after `open`, via [`crate::self_check::current_inode`]).
#[derive(Debug, Clone)]
pub struct ProcessStartInputs {
    /// `CARGO_PKG_VERSION` of the running binary.
    pub version: String,
    /// Git commit SHA at build time. Empty string until `vergen` lands in Sprint 5.
    pub git_commit: String,
    /// Effective base posture at startup.
    pub posture: String,
    /// Absolute path of the loaded config file.
    pub config_path: std::path::PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Trailing state read from the audit file BEFORE this writer was opened.
    pub trailing: crate::self_check::TrailingState,
    /// Inode of the audit file as observed AFTER this writer was opened
    /// (call `crate::self_check::current_inode` on the path).
    pub current_inode: u64,
}

impl AuditWriter {
    /// Build a `process_start` record from `inputs` and the writer's own
    /// `process_id`, allocate a seq, and write it. Computes the
    /// `audit_file_inode_changed` tamper signal from
    /// `inputs.trailing.last_recorded_inode` vs `inputs.current_inode`.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_process_start(
        &self,
        inputs: ProcessStartInputs,
    ) -> Result<crate::ids::Seq, AuditError> {
        let inode_changed = inputs
            .trailing
            .last_recorded_inode
            .is_some_and(|prior| prior != inputs.current_inode);
        let payload = crate::record::ProcessStart {
            version: inputs.version,
            git_commit: inputs.git_commit,
            posture: inputs.posture,
            config_path: inputs.config_path,
            config_hash_sha256: inputs.config_hash_sha256,
            previous_last_seq: inputs.trailing.last_seq,
            previous_process_id: inputs.trailing.last_process_id,
            previous_file_inode: inputs.current_inode,
            audit_file_inode_changed: inode_changed,
        };
        let seq = self.allocate_seq()?;
        let record = crate::record::AuditRecord {
            seq,
            ts: crate::ids::Timestamp::now(),
            process_id: self.process_id,
            payload: crate::record::Payload::ProcessStart(payload),
        };
        self.write_record(&record)?;
        Ok(seq)
    }
}
```

- [ ] **Step 3: Re-export `ProcessStartInputs` from the audit crate**

Edit `crates/rimap-audit/src/lib.rs`. Find the existing `pub use crate::writer::{AuditOptions, AuditWriter};` line and change it to:

```rust
pub use crate::writer::{AuditOptions, AuditWriter, ProcessStartInputs};
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p rimap-audit --lib writer::tests
```

Expected: all tests pass.

- [ ] **Step 5: Run clippy**

```bash
cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-audit/src/writer.rs crates/rimap-audit/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(audit): log_process_start helper closes the chain-of-history loop

ProcessStartInputs takes the pre-open TrailingState and post-open
current_inode; the helper computes audit_file_inode_changed and
populates previous_* fields so the chain of history is unbroken across
restarts. The first production emission path for process_start —
rimap-server::main calls this once before any other emission.

Closes #24.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: rimap-server emits process_start at startup

**Goal:** `rimap-server::main` runs `read_trailing_state` → `AuditWriter::open(initial_seq)` → `current_inode` → `log_process_start(...)` in that order. The existing audit-merge round-trip test asserts the first record on a fresh log is `process_start`.

**Files:**
- Modify: `crates/rimap-server/src/main.rs` (or wherever the audit writer is currently opened)
- Modify: `crates/rimap-server/Cargo.toml` (add `sha2`/`hex` if not present, for config hash)
- Modify: any existing test that opens an audit writer in this crate

- [ ] **Step 1: Locate the audit-writer open site in rimap-server**

```bash
grep -rn "AuditWriter::open\|AuditOptions" crates/rimap-server/src/
```

Note the file and line of the existing open call. The Sprint 2 audit-merge end-to-end test (`test(server): end-to-end audit merge round-trip`, commit `fb7d205`) lives in `crates/rimap-server/tests/`.

- [ ] **Step 2: Read the current main.rs structure**

```bash
cat crates/rimap-server/src/main.rs 2>/dev/null || cat crates/rimap-server/src/lib.rs
```

Find where the audit writer is opened and what wraps it. The new sequence below replaces a single `AuditWriter::open(...)` call with the four-step ritual.

- [ ] **Step 3: Build a helper that opens the writer with full chain-of-history wiring**

Create `crates/rimap-server/src/audit_init.rs`:

```rust
//! Initialize the audit writer for a long-running process: pre-scan trailing
//! state, open the writer, capture the current inode, emit process_start.

use std::path::Path;

use rimap_audit::{
    AuditOptions, AuditWriter, ProcessStartInputs,
    self_check::{current_inode, read_trailing_state},
};
use rimap_audit::{AuditError, Seq};
use rimap_config::ValidatedConfig;
use sha2::{Digest, Sha256};

/// Open the audit writer, run the pre-flight self-check, and emit the
/// `process_start` record. Returns the writer ready for production use.
///
/// # Errors
/// Propagates any `AuditError` from the trailing-state read, open, inode
/// fetch, or `process_start` write.
///
/// `config_file_path` is the path to the TOML config file the user loaded
/// (NOT the audit log path). `ValidatedConfig` does not carry its own
/// source path, so callers must thread it through explicitly. The
/// `process_start` record hashes this file's contents — getting this
/// wrong means every startup record names and hashes the audit log
/// instead of the config.
pub fn init_audit_writer(
    cfg: &ValidatedConfig,
    config_file_path: &Path,
) -> Result<AuditWriter, AuditError> {
    let audit_path = &cfg.config.audit.path;
    let trailing = read_trailing_state(audit_path)?;
    let initial_seq = trailing
        .last_seq
        .map(Seq::next)
        .unwrap_or(Seq::FIRST);

    let writer = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
        rotate_bytes: cfg.config.audit.rotate_bytes,
        initial_seq,
    })?;

    let current = current_inode(audit_path)?;
    let config_hash = compute_config_hash(config_file_path);

    writer.log_process_start(ProcessStartInputs {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: String::new(),
        posture: cfg.config.security.posture.to_string(),
        config_path: config_file_path.to_path_buf(),
        config_hash_sha256: config_hash,
        trailing,
        current_inode: current,
    })?;

    Ok(writer)
}

fn compute_config_hash(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}
```

> Note: `unwrap_or_default()` here is intentional — if the config file disappears between load and hash, we record an empty hash rather than panic. This is a startup hot path; the config was already successfully loaded earlier.

- [ ] **Step 4: Wire `audit_init` into main.rs**

In `crates/rimap-server/src/main.rs` (or `lib.rs` if main delegates), find the existing `AuditWriter::open(...)` call and replace it with:

```rust
let audit = crate::audit_init::init_audit_writer(&validated_config, &config_file_path)?;
```

Where `validated_config` is the `ValidatedConfig` produced earlier in the boot sequence, and `config_file_path` is the `PathBuf`/`&Path` pointing at the TOML file the user loaded (the argument you passed to `rimap_config::load(...)` or equivalent). Adjust the variable names to match what's already there. **Do NOT pass `cfg.config.audit.path` as the second argument** — that's the audit log, not the config file, and the whole point of the two-argument signature is to keep them distinct.

Add `pub mod audit_init;` near the top of `main.rs` or `lib.rs` (wherever modules are declared).

- [ ] **Step 5: Add `sha2` and `hex` to rimap-server deps**

```bash
grep -n "sha2\|hex" crates/rimap-server/Cargo.toml
```

If absent, add under `[dependencies]`:

```toml
sha2 = { workspace = true }
hex = { workspace = true }
```

- [ ] **Step 6: Update the existing audit-merge round-trip test**

```bash
grep -rn "audit_merge\|audit merge" crates/rimap-server/tests/
```

Find the test that asserts on the JSONL contents. Add assertions that the first line is a `process_start` record AND that it records the config file (not the audit log):

```rust
// Existing assertion may parse the file as JSONL; insert this near the top:
let first_line = contents.lines().next().expect("at least one record");
let first: serde_json::Value = serde_json::from_str(first_line).unwrap();
assert_eq!(first["kind"], "process_start");
assert_eq!(first["seq"], 1);

// Regression guard: config_path must be the TOML file, not the audit log.
assert_eq!(
    first["config_path"].as_str().unwrap(),
    config_path.to_str().unwrap(),
);

// And config_hash_sha256 must hash the config file contents.
use sha2::{Digest, Sha256};
let config_bytes = std::fs::read(&config_path).unwrap();
let mut hasher = Sha256::new();
hasher.update(&config_bytes);
let expected_hash = hex::encode(hasher.finalize());
assert_eq!(first["config_hash_sha256"].as_str().unwrap(), expected_hash);
```

If the test currently runs `audit merge` against a file that the test itself populated via `write_record`, the assertion above will fail because `process_start` was never written. In that case, change the test setup to use `init_audit_writer` (or `log_process_start` directly) instead of synthesizing records.

- [ ] **Step 7: Build and test**

```bash
cargo test -p rimap-server
cargo build --workspace
```

Expected: green.

If `cargo deny check` was wired into the test harness, run it too:

```bash
cargo deny check
```

Expected: clean (no new skips).

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/Cargo.toml crates/rimap-server/src/ crates/rimap-server/tests/
git commit -m "$(cat <<'EOF'
feat(server): emit process_start record at audit writer init

New audit_init helper runs read_trailing_state, opens the writer with
the resumed initial_seq, captures current_inode, and emits the
process_start chain-of-history record. Updates the audit merge
round-trip test to assert the first record on a fresh log is
process_start.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Scaffold rimap-imap dependencies and module skeleton

**Goal:** Empty crate body with all 4 new external deps wired and `cargo build` / `cargo deny check` green.

**Files:**
- Modify: `Cargo.toml` (workspace deps: add `async-imap`, `tokio-rustls`, `rustls`, `webpki-roots`)
- Modify: `crates/rimap-imap/Cargo.toml`
- Create: `crates/rimap-imap/src/{connection,tls,auth,types,error,time}.rs`
- Create: `crates/rimap-imap/src/ops/{mod,folders,search,fetch}.rs`
- Modify: `crates/rimap-imap/src/lib.rs`

- [ ] **Step 1: Add the four external deps to workspace `[workspace.dependencies]`**

Edit `Cargo.toml`. Add these alongside existing deps (a separate `# IMAP / TLS` section header is fine):

```toml
# IMAP / TLS (Sprint 3)
async-imap = { version = "0.11", default-features = false, features = ["runtime-tokio"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "tls12", "ring"] }
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "ring"] }
webpki-roots = "0.26"
```

> `default-features = false` + explicit feature sets keep the dep surface tight:
> - `async-imap` drops its default `runtime-async-std` in favor of `runtime-tokio` — this removes the unmaintained `async-std 1.x` chain (RUSTSEC-2025-0052).
> - `tokio-rustls` drops its default `aws-lc-rs` backend in favor of `ring`, keeping us on one crypto provider and dodging an extra `getrandom` major via the `aws-lc-sys` build edge.
> - `rustls` uses `ring` (no `aws-lc-rs`, no `dangerous_configuration` — task 9 enables the latter on the verifier only).
>
> **Upstream conflicts to expect:** `async-imap 0.11.2` depends on `stop-token 0.7` (unmaintained since 2022, pulls `async-channel/event-listener 1.x/2.x` while async-imap itself uses the 2.x/5.x lines) AND pins `thiserror ^1.0.9` directly. Neither is fixable with `cargo update`. `webpki-roots 0.26.10+` re-licensed from `MPL-2.0` to `CDLA-Permissive-2.0`. These require one license addition and four skip entries in `deny.toml` — see the new Step 1b below.

- [ ] **Step 1b: Update `deny.toml` for the async-imap and webpki-roots constraints**

Commit this BEFORE the scaffold commit so `cargo deny check` passes on the scaffold commit. Under `[licenses] allow = [...]`, add:

```toml
    # webpki-roots >= 0.26.10 re-licensed from MPL-2.0 to CDLA-Permissive-2.0
    # (Community Data License Agreement). It's a legitimate permissive license
    # published by the Linux Foundation. Accepted here because the alternative
    # is pinning to stale root certs.
    "CDLA-Permissive-2.0",
```

Under `[bans] skip = [...]`, append after the existing `hashbrown` entry:

```toml
    # The four entries below all trace to `async-imap 0.11.2` — the only
    # maintained pure-Rust async IMAP client. Its direct deps include
    # `stop-token 0.7` (last released 2022, unmaintained but harmless) which
    # pulls the 1.x line of the `async` runtime primitives, while async-imap
    # itself uses the 2.x line. `thiserror 1` is also a direct, non-optional
    # pin from async-imap. None can be resolved with `cargo update`; forking
    # async-imap is not warranted. Revisit when async-imap modernizes.
    { name = "async-channel", version = "1" },
    { name = "event-listener", version = "2" },
    { name = "thiserror", version = "1" },
    { name = "thiserror-impl", version = "1" },
```

Verify `cargo deny check` is clean on this commit alone (before scaffolding), then commit `deny.toml` on its own with a message like `chore(deny): allow CDLA-Permissive-2.0 and async-imap transitive duplicates`.

- [ ] **Step 2: Populate `crates/rimap-imap/Cargo.toml`**

Read the existing file first:

```bash
cat crates/rimap-imap/Cargo.toml
```

It is currently a stub. Replace the contents with:

```toml
[package]
name = "rimap-imap"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
readme.workspace = true
description = "IMAP session, TLS pinning, and read operations for rusty-imap-mcp"

[lints]
workspace = true

[dependencies]
# Internal — direct path + explicit version to satisfy cargo-deny's wildcard ban.
rimap-core = { path = "../rimap-core", version = "0.0.0" }
rimap-config = { path = "../rimap-config", version = "0.0.0" }
rimap-audit = { path = "../rimap-audit", version = "0.0.0" }

# Async runtime
tokio = { workspace = true }

# IMAP + TLS
async-imap = { workspace = true }
tokio-rustls = { workspace = true }
rustls = { workspace = true }
webpki-roots = { workspace = true }

# Error handling
thiserror = { workspace = true }

# Observability
tracing = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
tempfile = { workspace = true }
serde_json = { workspace = true }
```

> The `tokio test-util` feature unlocks `tokio::time::pause()` for the timeout unit test in task 13.

- [ ] **Step 3: Create the module files (empty stubs)**

Create each of the following files with placeholder content. Each file needs a module-level doc comment so the workspace `missing_docs = "warn"` lint doesn't trip.

`crates/rimap-imap/src/connection.rs`:
```rust
//! `Connection` lifecycle: lazy connect, TCP-half-open detection, lazy
//! reconnect on next use.
```

`crates/rimap-imap/src/tls.rs`:
```rust
//! `PinningVerifier` and `TlsConfig` builder. Two modes: pinned (skip chain)
//! and system trust (webpki-roots).
```

`crates/rimap-imap/src/auth.rs`:
```rust
//! LOGIN flow and `Auth` audit-record construction.
```

`crates/rimap-imap/src/types.rs`:
```rust
//! Public types: `Uid`, `Envelope`, `BodyStructure`, `Folder`, `SearchQuery`,
//! `FetchSpec`, `FetchedMessage`.
```

`crates/rimap-imap/src/error.rs`:
```rust
//! `rimap_imap::Error` and `From` conversions into `rimap_core::RimapError`.
```

`crates/rimap-imap/src/time.rs`:
```rust
//! `tokio::time::timeout` wrapper helpers used by every IMAP op.
```

`crates/rimap-imap/src/ops/mod.rs`:
```rust
//! IMAP read operations grouped by verb family.

pub mod fetch;
pub mod folders;
pub mod search;
```

`crates/rimap-imap/src/ops/folders.rs`:
```rust
//! `LIST`, `STATUS`, `SELECT` / `EXAMINE`.
```

`crates/rimap-imap/src/ops/search.rs`:
```rust
//! `SEARCH` (structured + raw).
```

`crates/rimap-imap/src/ops/fetch.rs`:
```rust
//! `FETCH ENVELOPE` / `BODYSTRUCTURE` / `UID` / `FLAGS` / `RFC822.SIZE` and
//! the streaming `FETCH BODY[]` path.
```

- [ ] **Step 4: Replace `crates/rimap-imap/src/lib.rs`**

```rust
//! IMAP connection, TLS fingerprint pinning, and read operations for
//! rusty-imap-mcp. See `docs/superpowers/specs/2026-04-07-sprint-3-imap-design.md`
//! for the design.

#![deny(missing_docs)]

pub mod auth;
pub mod connection;
pub mod error;
pub mod ops;
pub mod time;
pub mod tls;
pub mod types;
```

- [ ] **Step 5: Build the workspace**

```bash
cargo build --workspace
```

Expected: compiles. The new crate has zero functions but all module files exist.

If cargo complains about a duplicate version (`rustls` shipping multiple majors via the dependency tree, for example), run `cargo update -p <crate>` until cargo-deny is happy. Do NOT add deny.toml skips.

- [ ] **Step 6: Run cargo-deny**

```bash
cargo deny check
```

Expected: clean. The most likely surface is `webpki` showing up multiple times (from `rustls` and `tokio-rustls`). If a duplicate appears, try:

```bash
cargo update -p webpki
cargo deny check
```

If a genuine new duplicate cannot be resolved with `cargo update`, stop and surface the version conflict to the user — do not add a skip.

- [ ] **Step 7: Run clippy on the empty crate**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/rimap-imap/Cargo.toml crates/rimap-imap/src/
git commit -m "$(cat <<'EOF'
chore(imap): scaffold rimap-imap dependencies and module skeleton

Adds async-imap, tokio-rustls, rustls (ring backend), and webpki-roots
to the workspace. rimap-imap gets its module layout (connection, tls,
auth, types, error, time, ops/{folders,search,fetch}) as empty stubs.
cargo deny clean — no new skips beyond Sprint 0's documented entries.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: rimap-imap types and error taxonomy

**Goal:** Concrete `types.rs` and `error.rs` plus `From` impls into `RimapError`. Closes #27 in passing.

**Files:**
- Create: `crates/rimap-imap/src/types.rs` (replace stub)
- Create: `crates/rimap-imap/src/error.rs` (replace stub)
- Modify: `crates/rimap-core/src/error.rs` — add `Imap` and `Audit` variants to `RimapError`
- Modify: `crates/rimap-core/Cargo.toml` — add `rimap-audit` dep? NO. Backward dep would create a cycle. Use `Box<dyn Error>` for the audit source.
- Create: `crates/rimap-imap/tests/error_mapping.rs`

- [ ] **Step 1: Add new variants to `RimapError`**

Edit `crates/rimap-core/src/error.rs`. Replace the existing `RimapError` enum with:

```rust
/// Top-level tool error returned from dispatch. Library crates produce more
/// specific errors (`AuthzError`, `ConfigError`, `rimap_imap::Error`, …) which
/// map into this via `From` impls.
#[derive(Debug, Error)]
pub enum RimapError {
    /// Authorization, posture, rate limit, or breaker failure.
    #[error("{code}: {message}")]
    Authz {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
    },
    /// IMAP-layer failure (TLS, auth, network, protocol, timeout, size cap).
    #[error("{code}: {message}")]
    Imap {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
        /// Underlying source error from `rimap_imap::Error`, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// Audit log failure. Carries both the stable code (open-time errors
    /// map to `ErrorCode::Config`, runtime errors to `ErrorCode::Internal`)
    /// and the original `AuditError` via the source chain. The Display
    /// form includes the source's message so operators see the audit
    /// path and underlying I/O error.
    #[error("{code}: {source}")]
    Audit {
        /// Stable error code — `Config` for open-time, `Internal` for runtime.
        code: ErrorCode,
        /// The original audit error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Startup-time configuration error.
    #[error("ERR_CONFIG: {0}")]
    Config(String),
    /// Bug / invariant violation.
    #[error("ERR_INTERNAL: {0}")]
    Internal(String),
}

impl RimapError {
    /// The stable error code carried by this error.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authz { code, .. }
            | Self::Imap { code, .. }
            | Self::Audit { code, .. } => *code,
            Self::Config(_) => ErrorCode::Config,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }
}
```

> `RimapError::Audit` carries its own `code` field so the existing Open/ParentDir/Locked → `ErrorCode::Config` distinction is preserved end-to-end. The `#[error("{code}: {source}")]` interpolation drives Display (and includes the original path via the source's Display); the `#[source]` attribute exposes the boxed error to `Error::source()`. Using `Box<dyn Error>` avoids a `rimap-core → rimap-audit` cycle.

- [ ] **Step 2: Replace the existing `From<AuditError> for RimapError` impl in rimap-audit**

`crates/rimap-audit/src/error.rs` already has a `From<AuditError> for RimapError` impl (from Sprint 2) that returns `Config(String)` / `Internal(String)` without the source chain. Replace it with this source-preserving version that honors the same code distinction via the existing `AuditError::code()` accessor:

```rust
impl From<AuditError> for rimap_core::RimapError {
    fn from(err: AuditError) -> Self {
        let code = err.code();
        rimap_core::RimapError::Audit {
            code,
            source: Box::new(err),
        }
    }
}
```

`rimap-audit` already depends on `rimap-core` (don't re-add it).

- [ ] **Step 3: Update the existing round-trip test**

The Sprint 2 test `rimap_error_conversion_preserves_code` in `crates/rimap-audit/src/error.rs` only asserts `rimap.code() == ErrorCode::Config`. Strengthen it to also verify Display includes the path AND the source chain is preserved:

```rust
#[test]
fn rimap_error_conversion_preserves_code_and_source() {
    use std::error::Error as _;

    let err = AuditError::Locked {
        path: PathBuf::from("/tmp/a.jsonl"),
    };
    let rimap: rimap_core::RimapError = err.into();

    // Open-time errors still carry ERR_CONFIG.
    assert_eq!(rimap.code(), ErrorCode::Config);

    // Display form must include the code AND the original path.
    let display = rimap.to_string();
    assert!(display.contains("ERR_CONFIG"), "got: {display}");
    assert!(display.contains("/tmp/a.jsonl"), "got: {display}");

    // Source chain preserved.
    let source = rimap.source().expect("source chain must be preserved");
    assert!(
        source.to_string().contains("/tmp/a.jsonl"),
        "source should be the AuditError with path, got: {source}",
    );

    // Runtime error still maps to ERR_INTERNAL.
    let err = AuditError::Write {
        path: PathBuf::from("/tmp/a.jsonl"),
        source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
    };
    let rimap: rimap_core::RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Internal);
}
```

The test module's existing `#[cfg(test)] mod tests` block needs `#[expect(clippy::unwrap_used, reason = "tests")]` added at the module level because the new test uses `.expect()`. The three other tests in the module (`open_time_errors_map_to_config`, `runtime_errors_map_to_internal`, `locked_message_names_the_path`) are unaffected and should stay unchanged.

- [ ] **Step 4: Write rimap-imap `types.rs`**

Replace `crates/rimap-imap/src/types.rs`:

```rust
//! Public types for `rimap-imap`. These are the IMAP-shaped data the read
//! ops return — RFC-5322 / MIME parsing belongs to `rimap-content` (Sprint 4).

use std::num::NonZeroU32;

/// IMAP UID. Always non-zero per RFC 3501 §2.3.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uid(NonZeroU32);

impl Uid {
    /// Construct from a raw integer. Returns `None` for `0`.
    #[must_use]
    pub fn new(n: u32) -> Option<Self> {
        NonZeroU32::new(n).map(Self)
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// Opaque RFC 5322 `Message-ID` header value, as raw bytes (no decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(Vec<u8>);

impl MessageId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Underlying raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// IMAP `LIST` response entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Folder name (mailbox path) as the server reported it. Modified UTF-7
    /// decoding is left to the caller / Sprint 4.
    pub name: String,
    /// Folder attribute flags (`\Noinferiors`, `\Marked`, etc.).
    pub attributes: Vec<String>,
    /// Hierarchy delimiter, if the server reported one.
    pub delimiter: Option<char>,
}

/// Bitflags-style selection for `STATUS` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusItems {
    /// Include `MESSAGES` (total count).
    pub messages: bool,
    /// Include `RECENT`.
    pub recent: bool,
    /// Include `UIDNEXT`.
    pub uid_next: bool,
    /// Include `UIDVALIDITY`.
    pub uid_validity: bool,
    /// Include `UNSEEN`.
    pub unseen: bool,
}

impl StatusItems {
    /// All items selected.
    #[must_use]
    pub fn all() -> Self {
        Self {
            messages: true,
            recent: true,
            uid_next: true,
            uid_validity: true,
            unseen: true,
        }
    }
}

/// Result of a `STATUS` command. Fields are populated only when requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderStatus {
    /// `MESSAGES`.
    pub messages: Option<u32>,
    /// `RECENT`.
    pub recent: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `UIDVALIDITY`.
    pub uid_validity: Option<u32>,
    /// `UNSEEN`.
    pub unseen: Option<u32>,
}

/// Result of a `SELECT` or `EXAMINE` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFolder {
    /// Mailbox name.
    pub name: String,
    /// `EXISTS` count.
    pub exists: u32,
    /// `RECENT` count.
    pub recent: u32,
    /// `UIDVALIDITY`.
    pub uid_validity: u32,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `READ-ONLY` if `EXAMINE`, otherwise `READ-WRITE`.
    pub read_only: bool,
}

/// IMAP message flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// `\Seen`.
    Seen,
    /// `\Answered`.
    Answered,
    /// `\Flagged`.
    Flagged,
    /// `\Deleted`.
    Deleted,
    /// `\Draft`.
    Draft,
    /// `\Recent` (RFC 3501 only; deprecated in RFC 9051).
    Recent,
    /// Server-specific keyword (anything not in the canonical list above).
    Keyword(String),
}

/// IMAP `ENVELOPE` response. Header values stay raw bytes — RFC 2047 decoding
/// is Sprint 4's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `Date` header, raw.
    pub date: Option<Vec<u8>>,
    /// `Subject` header, raw.
    pub subject_raw: Option<Vec<u8>>,
    /// `From` addresses, raw.
    pub from: Vec<Address>,
    /// `Sender` addresses, raw.
    pub sender: Vec<Address>,
    /// `Reply-To` addresses, raw.
    pub reply_to: Vec<Address>,
    /// `To` addresses, raw.
    pub to: Vec<Address>,
    /// `Cc` addresses, raw.
    pub cc: Vec<Address>,
    /// `Bcc` addresses, raw.
    pub bcc: Vec<Address>,
    /// `In-Reply-To` header, raw.
    pub in_reply_to: Option<Vec<u8>>,
    /// `Message-ID` header, raw.
    pub message_id: Option<MessageId>,
}

/// IMAP envelope address. Raw bytes; no charset decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Personal name (`name`), raw.
    pub name: Option<Vec<u8>>,
    /// Source route (`adl`), raw.
    pub adl: Option<Vec<u8>>,
    /// Mailbox local part, raw.
    pub mailbox: Option<Vec<u8>>,
    /// Host part, raw.
    pub host: Option<Vec<u8>>,
}

/// IMAP `BODYSTRUCTURE` recursive type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStructure {
    /// A single-part body.
    Single {
        /// MIME type (`text`, `image`, …).
        mime_type: String,
        /// MIME subtype (`plain`, `jpeg`, …).
        mime_subtype: String,
        /// MIME content-type parameters.
        params: Vec<(String, String)>,
        /// Transfer encoding (`7bit`, `base64`, …).
        encoding: String,
        /// Octet count.
        size: u32,
    },
    /// A `multipart/*` body.
    Multipart {
        /// Multipart subtype (`mixed`, `alternative`, …).
        subtype: String,
        /// Constituent parts.
        parts: Vec<BodyStructure>,
    },
}

/// SEARCH query — either a structured builder or a raw passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchQuery {
    /// Typed query built via `StructuredQuery`.
    Structured(StructuredQuery),
    /// Raw IMAP SEARCH key string. The audit/dispatch layer (Sprint 5) decides
    /// whether to log it verbatim or redacted.
    Raw(String),
}

/// Structured SEARCH builder. Empty builder = `ALL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredQuery {
    /// Match `FROM` substring.
    pub from: Option<String>,
    /// Match `TO` substring.
    pub to: Option<String>,
    /// Match `SUBJECT` substring.
    pub subject: Option<String>,
    /// `SINCE` (inclusive lower bound by INTERNALDATE).
    pub since: Option<time::Date>,
    /// `BEFORE` (exclusive upper bound by INTERNALDATE).
    pub before: Option<time::Date>,
    /// Restrict to messages with `\Seen`.
    pub seen: Option<bool>,
    /// Restrict to messages with attachments (`HAS_ATTACHMENT` heuristic;
    /// emitted as `BODY "Content-Disposition: attachment"`).
    pub has_attachment: bool,
}

/// FETCH item selection. `ENVELOPE`, `BODYSTRUCTURE`, `UID`, `FLAGS`, `SIZE`.
/// `BODY[]` has its own dedicated method (`Connection::fetch_body`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchSpec {
    /// Include `ENVELOPE`.
    pub envelope: bool,
    /// Include `BODYSTRUCTURE`.
    pub bodystructure: bool,
    /// Include `UID`.
    pub uid: bool,
    /// Include `FLAGS`.
    pub flags: bool,
    /// Include `RFC822.SIZE`.
    pub size: bool,
}

/// One message returned by a `fetch` call. Only the fields requested in the
/// `FetchSpec` are populated; the rest are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Message UID (always present — IMAP servers always return UID for UID FETCH).
    pub uid: Uid,
    /// `ENVELOPE` if requested.
    pub envelope: Option<Envelope>,
    /// `BODYSTRUCTURE` if requested.
    pub bodystructure: Option<BodyStructure>,
    /// `FLAGS` if requested.
    pub flags: Option<Vec<Flag>>,
    /// `RFC822.SIZE` if requested.
    pub size: Option<u32>,
}
```

> Note: this types module imports `time::Date`. The `time` crate is already in `[workspace.dependencies]` (used by `rimap-audit`). Add `time = { workspace = true }` to `crates/rimap-imap/Cargo.toml` `[dependencies]` if not already there.

- [ ] **Step 5: Write rimap-imap `error.rs`**

Replace `crates/rimap-imap/src/error.rs`:

```rust
//! `rimap_imap::Error` and conversion into `rimap_core::RimapError`.

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use thiserror::Error;

/// Errors produced by `rimap-imap`. Each variant maps to a stable
/// `ErrorCode` via `From<Error> for RimapError`.
#[derive(Debug, Error)]
pub enum Error {
    /// TLS leaf-cert fingerprint did not match the configured pin.
    #[error("ERR_TLS: fingerprint mismatch (observed={observed}, expected={expected})")]
    Tls {
        /// The fingerprint the server presented.
        observed: TlsFingerprint,
        /// The fingerprint configured in `imap.tls_fingerprint_sha256`.
        expected: TlsFingerprint,
    },
    /// TLS handshake failed for a reason other than fingerprint mismatch
    /// (signature algorithm, protocol version, webpki path error in unpinned mode).
    #[error("ERR_TLS: handshake failed")]
    TlsHandshake(#[source] tokio_rustls::rustls::Error),
    /// TCP connect failed.
    #[error("connect failed")]
    Connect(#[source] std::io::Error),
    /// `tokio::time::timeout` fired around an IMAP command.
    #[error("ERR_TIMEOUT: {op} exceeded deadline")]
    Timeout {
        /// Short tag identifying the operation that timed out.
        op: &'static str,
    },
    /// Authentication-layer failure (LOGIN rejected, LOGIN disabled, BYE greeting).
    #[error("ERR_AUTH: {reason}")]
    Auth {
        /// Specific failure mode.
        reason: AuthFailure,
    },
    /// Body fetch exceeded the configured size cap; connection was dropped.
    #[error("ERR_ATTACHMENT_TOO_LARGE: body size exceeded limit of {limit} bytes")]
    SizeLimit {
        /// The configured `max_fetch_body_bytes`.
        limit: u64,
    },
    /// Underlying `async-imap` protocol error.
    #[error("ERR_IMAP_PROTOCOL: {0}")]
    Protocol(#[source] async_imap::error::Error),
    /// TCP half-open: detected dead connection during a command.
    #[error("ERR_CONNECTION_LOST: connection torn down mid-command")]
    ConnectionLost,
}

/// Specific authentication failure mode for `Error::Auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    /// LOGIN command rejected by the server.
    LoginRejected,
    /// Server advertised `LOGINDISABLED` in CAPABILITY.
    CapabilityMissing {
        /// The capability that was required but missing.
        needed: &'static str,
    },
    /// Server sent `BYE` as its greeting.
    ServerRejected,
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginRejected => f.write_str("LOGIN rejected"),
            Self::CapabilityMissing { needed } => write!(f, "missing capability `{needed}`"),
            Self::ServerRejected => f.write_str("server BYE greeting"),
        }
    }
}

impl From<Error> for RimapError {
    fn from(err: Error) -> Self {
        let code = match &err {
            Error::Tls { .. } | Error::TlsHandshake(_) => ErrorCode::Tls,
            Error::Connect(_) | Error::ConnectionLost => ErrorCode::ConnectionLost,
            Error::Timeout { .. } => ErrorCode::Timeout,
            Error::Auth { .. } => ErrorCode::Auth,
            Error::SizeLimit { .. } => ErrorCode::AttachmentTooLarge,
            Error::Protocol(_) => ErrorCode::ImapProtocol,
        };
        let message = err.to_string();
        RimapError::Imap {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
```

- [ ] **Step 6: Write `tests/error_mapping.rs`**

Create `crates/rimap-imap/tests/error_mapping.rs`:

```rust
//! Round-trip tests for `From<rimap_imap::Error> for RimapError` — assert
//! the source chain is preserved through `Error::source()`.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::error::Error as _;

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use rimap_imap::error::{AuthFailure, Error};

const FP_HEX_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FP_HEX_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

#[test]
fn tls_fingerprint_mismatch_maps_to_err_tls() {
    let observed = TlsFingerprint::from_hex(FP_HEX_A).unwrap();
    let expected = TlsFingerprint::from_hex(FP_HEX_B).unwrap();
    let err = Error::Tls { observed, expected };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Tls);
    assert!(rimap.source().is_some());
}

#[test]
fn auth_login_rejected_maps_to_err_auth() {
    let err = Error::Auth { reason: AuthFailure::LoginRejected };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Auth);
}

#[test]
fn capability_missing_maps_to_err_auth() {
    let err = Error::Auth {
        reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
    };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Auth);
    let msg = rimap.to_string();
    assert!(msg.contains("LOGIN"), "got {msg}");
}

#[test]
fn timeout_maps_to_err_timeout() {
    let err = Error::Timeout { op: "fetch" };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Timeout);
}

#[test]
fn size_limit_maps_to_err_attachment_too_large() {
    let err = Error::SizeLimit { limit: 1024 };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::AttachmentTooLarge);
    let chain = rimap.source().expect("source preserved");
    assert!(chain.to_string().contains("1024"));
}

#[test]
fn connection_lost_maps_to_err_connection_lost() {
    let err = Error::ConnectionLost;
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::ConnectionLost);
}

#[test]
fn connect_io_error_maps_to_err_connection_lost() {
    let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
    let err = Error::Connect(io);
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::ConnectionLost);
}
```

- [ ] **Step 7: Run the tests**

```bash
cargo test -p rimap-imap --test error_mapping
cargo test -p rimap-core
cargo test -p rimap-audit
```

Expected: green.

- [ ] **Step 8: Run clippy across the touched crates**

```bash
cargo clippy -p rimap-core -p rimap-audit -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-core/src/error.rs crates/rimap-audit/Cargo.toml crates/rimap-audit/src/error.rs crates/rimap-imap/Cargo.toml crates/rimap-imap/src/types.rs crates/rimap-imap/src/error.rs crates/rimap-imap/tests/error_mapping.rs
git commit -m "$(cat <<'EOF'
feat(imap): types and error taxonomy

Adds the public types module (Uid, Envelope, BodyStructure, Folder,
SearchQuery, FetchSpec, FetchedMessage) and the rimap_imap::Error enum
with From impls into RimapError. RimapError gains Imap and Audit
variants so the source chain is preserved end-to-end. From<AuditError>
for RimapError lands in passing.

Closes #27.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: TlsConfig builder with PinningVerifier

**Goal:** Two-mode `TlsConfig`. `PinningVerifier` skips chain validation when a fingerprint is configured; `webpki-roots` is used otherwise. Captures observed fingerprint in a `OnceLock` for the audit record.

**Files:**
- Modify: `crates/rimap-imap/Cargo.toml` — add `dangerous_configuration` feature on `rustls`
- Modify: `crates/rimap-imap/src/tls.rs` (replace stub)
- Create: `crates/rimap-imap/tests/tls_pinning.rs`

- [ ] **Step 1: Enable rustls `dangerous_configuration` feature**

The custom `ServerCertVerifier` requires `rustls`'s `dangerous_configuration` feature. Edit `Cargo.toml` workspace deps:

```toml
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "ring", "dangerous_configuration"] }
```

Then re-run:

```bash
cargo build --workspace
cargo deny check
```

Expected: clean. If `dangerous_configuration` is renamed in rustls 0.23 (it was in earlier versions), check `cargo doc --open -p rustls` for the current feature name. As of rustls 0.23 the feature is named `dangerous_configuration`.

- [ ] **Step 2: Write `crates/rimap-imap/src/tls.rs`**

```rust
//! `PinningVerifier` and `TlsConfig` builder. Two modes: pinned (skip chain
//! validation) and system trust (`webpki-roots`).
//!
//! ## Capturing the observed fingerprint
//!
//! Both modes wrap their verifier so the fingerprint is recorded in a
//! `OnceLock` regardless of whether the handshake succeeds. After the
//! `tokio_rustls::TlsConnector::connect` call returns, `Connection` reads
//! the slot and uses it to populate the `Auth` audit record.

use std::sync::{Arc, OnceLock};

use rimap_core::TlsFingerprint;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Pinned-mode verifier. Constructed only when `pinned.is_some()`.
#[derive(Debug)]
pub(crate) struct PinningVerifier {
    pinned: TlsFingerprint,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
    /// Default rustls verifier we delegate to for signature scheme listing
    /// (chain validation is skipped, but signature algorithm enforcement is not).
    inner_signature_verifier: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        if self.pinned == observed {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "tls fingerprint mismatch: observed={observed}, expected={pinned}",
                pinned = self.pinned,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.inner_signature_verifier.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.inner_signature_verifier.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner_signature_verifier
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wraps the system-trust verifier so we still capture the observed
/// fingerprint into the same `OnceLock` slot used by pinned mode.
#[derive(Debug)]
pub(crate) struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A `ClientConfig` plus the slot the verifier writes the observed
/// fingerprint into. Construct via [`build_tls_config`]; pass the
/// `last_observed` handle to `Connection` so it can read the value after
/// the handshake.
pub struct TlsConfigBundle {
    /// The `rustls::ClientConfig` ready to hand to `tokio_rustls::TlsConnector`.
    pub config: Arc<ClientConfig>,
    /// Slot the verifier sets exactly once during `verify_server_cert`.
    /// `None` if the handshake failed before the verifier ran.
    pub last_observed: Arc<OnceLock<TlsFingerprint>>,
}

/// Build a `TlsConfigBundle`. If `pinned.is_some()`, uses `PinningVerifier`
/// (skips chain validation). Otherwise uses webpki-roots.
#[must_use]
pub fn build_tls_config(pinned: Option<TlsFingerprint>) -> TlsConfigBundle {
    let last_observed = Arc::new(OnceLock::new());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());

    let config = if let Some(pin) = pinned {
        let verifier = Arc::new(PinningVerifier {
            pinned: pin,
            last_observed: Arc::clone(&last_observed),
            inner_signature_verifier: Arc::clone(&provider),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("default protocol versions are valid"))
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner_verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap_or_else(|_| unreachable!("webpki-roots produces a valid builder"));
        let capturing = Arc::new(CapturingVerifier {
            inner: inner_verifier,
            last_observed: Arc::clone(&last_observed),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("default protocol versions are valid"))
            .dangerous()
            .with_custom_certificate_verifier(capturing)
            .with_no_client_auth()
    };

    TlsConfigBundle {
        config: Arc::new(config),
        last_observed,
    }
}
```

> **Implementer note:** rustls 0.23 has had several API churn releases. If `with_safe_default_protocol_versions().unwrap_or_else(...)` does not compile because it returns `Self` instead of `Result<Self, _>`, drop the `unwrap_or_else` chain and call `.dangerous()` directly. Likewise `WebPkiServerVerifier::builder_with_provider` may be `builder` in some patch releases. Use `cargo doc -p rustls --open` to confirm the exact API surface for the version `cargo update` resolved.

- [ ] **Step 3: Write `tests/tls_pinning.rs`**

Create `crates/rimap-imap/tests/tls_pinning.rs`:

```rust
//! Verifier-level tests. No network. We exercise the `OnceLock` capture
//! path with synthetic cert DER bytes.

#![expect(clippy::unwrap_used, reason = "tests")]

use rimap_core::TlsFingerprint;
use rimap_imap::tls::build_tls_config;

#[test]
fn pinned_mode_builds_a_client_config() {
    let pin = TlsFingerprint::from_cert_der(b"synthetic-cert");
    let bundle = build_tls_config(Some(pin));
    // Slot starts empty; the verifier hasn't run yet.
    assert!(bundle.last_observed.get().is_none());
    // Two clones of the slot share state.
    let slot = bundle.last_observed.clone();
    assert!(slot.get().is_none());
}

#[test]
fn unpinned_mode_builds_a_client_config_with_webpki_roots() {
    let bundle = build_tls_config(None);
    assert!(bundle.last_observed.get().is_none());
    // We can't easily exercise the verifier without a real handshake; the
    // Dovecot integration test in Task 15 covers the success and failure
    // paths end-to-end.
}

#[test]
fn fingerprint_eq_uses_constant_time_path() {
    let a = TlsFingerprint::from_cert_der(b"alpha");
    let b = TlsFingerprint::from_cert_der(b"alpha");
    let c = TlsFingerprint::from_cert_der(b"beta");
    assert_eq!(a, b);
    assert_ne!(a, c);
}
```

> **Why so few tests at this layer:** the verifier's `verify_server_cert` is only invoked during a real TLS handshake. Mocking that requires either a custom rustls test harness or feeding bytes through `ClientConnection` by hand — both significantly more code than just running it against the Dovecot container in Task 15. The tests above cover the construction path; the behavioral coverage lives in the integration suite.

- [ ] **Step 4: Build and test**

```bash
cargo build -p rimap-imap
cargo test -p rimap-imap --test tls_pinning
```

Expected: green. If rustls API drift causes `tls.rs` to fail to compile, fix locally per the implementer note in Step 2 — do not change the test file.

- [ ] **Step 5: Run clippy**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/rimap-imap/src/tls.rs crates/rimap-imap/tests/tls_pinning.rs
git commit -m "$(cat <<'EOF'
feat(imap): TlsConfig builder with PinningVerifier and capturing fallback

PinningVerifier skips chain validation when imap.tls_fingerprint_sha256
is configured; CapturingVerifier wraps the webpki-roots verifier in
unpinned mode. Both write the observed fingerprint into a shared
OnceLock slot before returning, so Connection::ensure_connected can
emit it in the Auth audit record regardless of handshake outcome.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: ConnectionConfig and Connection::ensure_connected

**Goal:** The full connect/handshake/login/CAPABILITY flow with `Auth` audit emission via `spawn_blocking`. This is the largest single task in the sprint.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (replace stub)
- Modify: `crates/rimap-imap/src/auth.rs` (replace stub) — `Auth` record builders
- Modify: `crates/rimap-imap/src/lib.rs` — re-export `Connection`, `ConnectionConfig`

- [ ] **Step 1: Write `auth.rs` — record builders**

Replace `crates/rimap-imap/src/auth.rs`:

```rust
//! Builders that translate connect-flow outcomes into `rimap_audit::Auth`
//! records. Pure functions — no I/O, no audit emission. The caller
//! (`connection.rs`) hands the result to `AuditWriter::log_auth`.

use rimap_audit::record::{Auth, AuthResult};
use rimap_core::TlsFingerprint;

/// Inputs every `Auth` record needs.
pub(crate) struct AuthContext<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub pinned: Option<TlsFingerprint>,
    pub observed: Option<TlsFingerprint>,
}

impl<'a> AuthContext<'a> {
    fn fingerprint_match(&self) -> Option<bool> {
        match (self.pinned, self.observed) {
            (Some(p), Some(o)) => Some(p == o),
            _ => None,
        }
    }

    fn observed_hex(&self) -> Option<String> {
        self.observed.map(|f| f.to_hex())
    }
}

/// Build a successful `Auth` record.
pub(crate) fn auth_success(ctx: &AuthContext<'_>) -> Auth {
    Auth {
        result: AuthResult::Success,
        host: ctx.host.to_string(),
        port: ctx.port,
        username: ctx.username.to_string(),
        tls_fingerprint_sha256: ctx.observed_hex(),
        fingerprint_match: ctx.fingerprint_match(),
        error_code: None,
    }
}

/// Build a failure `Auth` record carrying the stable error code.
pub(crate) fn auth_failure(ctx: &AuthContext<'_>, error_code: &str) -> Auth {
    Auth {
        result: AuthResult::Failure,
        host: ctx.host.to_string(),
        port: ctx.port,
        username: ctx.username.to_string(),
        tls_fingerprint_sha256: ctx.observed_hex(),
        fingerprint_match: ctx.fingerprint_match(),
        error_code: Some(error_code.to_string()),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{AuthContext, auth_failure, auth_success};
    use rimap_audit::record::AuthResult;
    use rimap_core::TlsFingerprint;

    fn fp(seed: &[u8]) -> TlsFingerprint {
        TlsFingerprint::from_cert_der(seed)
    }

    #[test]
    fn success_with_matching_fingerprint() {
        let pin = fp(b"good");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(pin),
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.result, AuthResult::Success);
        assert_eq!(rec.fingerprint_match, Some(true));
        assert_eq!(rec.tls_fingerprint_sha256, Some(pin.to_hex()));
        assert!(rec.error_code.is_none());
    }

    #[test]
    fn failure_with_mismatched_fingerprint() {
        let pin = fp(b"good");
        let observed = fp(b"bad");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(observed),
        };
        let rec = auth_failure(&ctx, "ERR_TLS");
        assert_eq!(rec.result, AuthResult::Failure);
        assert_eq!(rec.fingerprint_match, Some(false));
        assert_eq!(rec.error_code.as_deref(), Some("ERR_TLS"));
    }

    #[test]
    fn unpinned_observed_yields_none_match() {
        let observed = fp(b"x");
        let ctx = AuthContext {
            host: "h",
            port: 993,
            username: "u",
            pinned: None,
            observed: Some(observed),
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.fingerprint_match, None);
        assert!(rec.tls_fingerprint_sha256.is_some());
    }
}
```

- [ ] **Step 2: Write `connection.rs` — `ConnectionConfig` and `Connection`**

Replace `crates/rimap-imap/src/connection.rs`:

```rust
//! `Connection`: lazy-connect IMAP session with TLS fingerprint pinning,
//! command timeout enforcement, and `Auth` audit emission.
//!
//! ## Locking discipline
//!
//! - The `tokio::sync::Mutex` around `Option<Session>` IS held across `.await`
//!   points (it has to be — async-imap commands are themselves `.await`).
//! - The `rimap_audit::AuditWriter` lock (a `std::sync::Mutex`) is NEVER held
//!   across an `.await`. Every audit emission goes through
//!   `tokio::task::spawn_blocking`.
//!
//! These two rules are independent and both must hold. See
//! `docs/architecture/audit-locking.md` (added in Task 17).

use std::sync::Arc;
use std::time::Duration;

use async_imap::Session;
use rimap_audit::AuditWriter;
use rimap_audit::record::Auth;
use rimap_config::credential::{CredentialStore, resolve_credential};
use rimap_core::TlsFingerprint;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::auth::{AuthContext, auth_failure, auth_success};
use crate::error::{AuthFailure, Error};
use crate::tls::{TlsConfigBundle, build_tls_config};

/// Everything `Connection` needs to open a session, pulled out of
/// `rimap_config::ValidatedConfig` by the caller. `Connection` clones this
/// value once at construction time.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// IMAP server host.
    pub host: String,
    /// IMAP server port (typically 993 for IMAPS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Optional pinned TLS fingerprint. `None` = use system trust roots.
    pub pinned_fingerprint: Option<TlsFingerprint>,
    /// TCP + TLS handshake + greeting + CAPABILITY deadline.
    pub connect_timeout: Duration,
    /// Per-IMAP-command deadline applied via `tokio::time::timeout`.
    pub command_timeout: Duration,
    /// Hard cap on `FETCH BODY[]` byte count.
    pub max_fetch_body_bytes: u64,
}

/// Active IMAP session type alias. `async-imap` parameterizes over the
/// underlying transport; we always use `TlsStream<TcpStream>`.
pub(crate) type ImapSession = Session<TlsStream<TcpStream>>;

/// Lazy-connect IMAP connection. Cheaply cloneable (`Arc` internally).
#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    cfg: ConnectionConfig,
    audit: AuditWriter,
    credentials: Arc<dyn CredentialStore>,
    /// `None` = never connected, or last command tore down the connection.
    /// `Some(_)` = live session ready for the next command.
    session: Mutex<Option<ImapSession>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("host", &self.inner.cfg.host)
            .field("port", &self.inner.cfg.port)
            .field("username", &self.inner.cfg.username)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Build a connection handle. Does NOT open a socket.
    #[must_use]
    pub fn new(
        cfg: ConnectionConfig,
        audit: AuditWriter,
        credentials: Arc<dyn CredentialStore>,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                cfg,
                audit,
                credentials,
                session: Mutex::new(None),
            }),
        }
    }

    /// Read the configured host (used by ops to log context).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.inner.cfg.host
    }

    /// Test/debug only: returns whether a live session is currently held.
    #[cfg(any(test, feature = "test-introspection"))]
    pub async fn is_connected(&self) -> bool {
        self.inner.session.lock().await.is_some()
    }

    /// Acquire the session lock; lazy-connect if needed. The returned guard
    /// holds the tokio mutex; drop it before any other method on `Connection`.
    pub(crate) async fn session(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ImapSession>>, Error> {
        let mut guard = self.inner.session.lock().await;
        if guard.is_none() {
            let session = self.connect_inner().await?;
            *guard = Some(session);
        }
        Ok(guard)
    }

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path.
    async fn connect_inner(&self) -> Result<ImapSession, Error> {
        let cfg = &self.inner.cfg;
        let bundle = build_tls_config(cfg.pinned_fingerprint);

        let outcome = self.connect_with_bundle(&bundle).await;
        let observed = bundle.last_observed.get().copied();
        let ctx = AuthContext {
            host: &cfg.host,
            port: cfg.port,
            username: &cfg.username,
            pinned: cfg.pinned_fingerprint,
            observed,
        };

        match &outcome {
            Ok(_) => self.emit_auth(auth_success(&ctx)).await?,
            Err(err) => self.emit_auth(auth_failure(&ctx, error_code_for(err))).await?,
        }
        outcome
    }

    async fn connect_with_bundle(&self, bundle: &TlsConfigBundle) -> Result<ImapSession, Error> {
        let cfg = &self.inner.cfg;
        let total_deadline = cfg.connect_timeout;
        let started = std::time::Instant::now();

        // Step 1: TCP connect.
        let tcp = timeout(total_deadline, TcpStream::connect((cfg.host.as_str(), cfg.port)))
            .await
            .map_err(|_| Error::Timeout { op: "tcp_connect" })?
            .map_err(Error::Connect)?;

        // Step 2: TLS handshake.
        let server_name = ServerName::try_from(cfg.host.clone())
            .map_err(|_| Error::Connect(std::io::Error::other("invalid server name for TLS")))?;
        let connector = TlsConnector::from(bundle.config.clone());
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        let tls_stream = timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| Error::Timeout { op: "tls_handshake" })?
            .map_err(map_tls_handshake_error)?;

        // Step 3: IMAP greeting + capability + login.
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        timeout(remaining, self.imap_login(tls_stream))
            .await
            .map_err(|_| Error::Timeout { op: "imap_login" })?
    }

    async fn imap_login(
        &self,
        tls_stream: TlsStream<TcpStream>,
    ) -> Result<ImapSession, Error> {
        let mut client = async_imap::Client::new(tls_stream);

        // Greeting.
        let _greeting = client
            .read_response()
            .await
            .ok_or(Error::Auth { reason: AuthFailure::ServerRejected })?
            .map_err(Error::Protocol)?;

        // CAPABILITY probe.
        let caps = client.capabilities().await.map_err(Error::Protocol)?;
        if caps.has_str("LOGINDISABLED") {
            return Err(Error::Auth {
                reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
            });
        }
        drop(caps);

        // LOGIN.
        let cfg = &self.inner.cfg;
        let password = resolve_credential(&*self.inner.credentials, &cfg.username, &cfg.host)
            .map_err(|e| Error::Connect(std::io::Error::other(format!("credential: {e}"))))?;

        match client.login(&cfg.username, &password).await {
            Ok(session) => Ok(session),
            Err((err, _client)) => {
                if matches!(err, async_imap::error::Error::No(_)) {
                    Err(Error::Auth { reason: AuthFailure::LoginRejected })
                } else {
                    Err(Error::Protocol(err))
                }
            }
        }
    }

    async fn emit_auth(&self, record: Auth) -> Result<(), Error> {
        let audit = self.inner.audit.clone();
        tokio::task::spawn_blocking(move || audit.log_auth(record))
            .await
            .map_err(|join_err| {
                Error::Connect(std::io::Error::other(format!(
                    "audit join error: {join_err}"
                )))
            })?
            .map_err(|audit_err| {
                Error::Connect(std::io::Error::other(format!(
                    "audit write error: {audit_err}"
                )))
            })?;
        Ok(())
    }
}

fn map_tls_handshake_error(err: std::io::Error) -> Error {
    // tokio-rustls wraps the rustls::Error inside an io::Error of kind
    // InvalidData (or similar). The "fingerprint mismatch" path produces a
    // `rustls::Error::General` whose Display contains our marker text.
    let msg = err.to_string();
    if msg.contains("tls fingerprint mismatch") {
        // Caller will read the OnceLock to learn the observed value;
        // we can't produce a typed Tls { observed, expected } here without
        // re-parsing the message. Connection::connect_inner enriches the
        // returned error after the fact via the bundle's last_observed slot
        // — but for now, surface as TlsHandshake; the audit record carries
        // the structured fields.
        Error::TlsHandshake(tokio_rustls::rustls::Error::General(msg))
    } else {
        Error::TlsHandshake(tokio_rustls::rustls::Error::General(msg))
    }
}

fn error_code_for(err: &Error) -> &'static str {
    match err {
        Error::Tls { .. } | Error::TlsHandshake(_) => "ERR_TLS",
        Error::Connect(_) | Error::ConnectionLost => "ERR_NETWORK",
        Error::Timeout { .. } => "ERR_TIMEOUT",
        Error::Auth { .. } => "ERR_AUTH",
        Error::SizeLimit { .. } => "ERR_ATTACHMENT_TOO_LARGE",
        Error::Protocol(_) => "ERR_IMAP_PROTOCOL",
    }
}
```

> **Implementer note on `Error::Tls { observed, expected }`:** The current implementation returns `TlsHandshake` for the mismatch path. Refining it to construct the typed `Tls { observed, expected }` requires reading `bundle.last_observed` AFTER the failure and re-wrapping the error. Add this enrichment in `connect_inner` between the `connect_with_bundle` call and the `emit_auth` call:
>
> ```rust
> let outcome = match self.connect_with_bundle(&bundle).await {
>     Ok(session) => Ok(session),
>     Err(Error::TlsHandshake(_)) if cfg.pinned_fingerprint.is_some() => {
>         // Try to enrich into Error::Tls if we know both fingerprints.
>         match (cfg.pinned_fingerprint, bundle.last_observed.get().copied()) {
>             (Some(expected), Some(observed)) if expected != observed => {
>                 Err(Error::Tls { observed, expected })
>             }
>             _ => Err(Error::TlsHandshake(tokio_rustls::rustls::Error::General(
>                 "tls handshake failed".into(),
>             ))),
>         }
>     }
>     Err(other) => Err(other),
> };
> ```
>
> Apply this refinement BEFORE moving to the next step.

- [ ] **Step 3: Re-export `Connection` and `ConnectionConfig` from lib.rs**

Edit `crates/rimap-imap/src/lib.rs`. After the `pub mod` declarations, add:

```rust
pub use crate::connection::{Connection, ConnectionConfig};
pub use crate::error::{AuthFailure, Error};
```

- [ ] **Step 4: Add `tokio` `net` and `time` features to rimap-imap**

Check `crates/rimap-imap/Cargo.toml`. The workspace tokio feature set is `["rt-multi-thread", "macros", "time", "sync"]`. Sprint 3 also needs `net` for `TcpStream`. Add a per-crate feature override:

```toml
tokio = { workspace = true, features = ["net"] }
```

Or, if cleaner, add `net` to the workspace tokio features in `Cargo.toml`:

```toml
tokio = { version = "1.42", features = ["rt-multi-thread", "macros", "time", "sync", "net"] }
```

- [ ] **Step 5: Build**

```bash
cargo build -p rimap-imap
```

Expected: compiles. Likely compile errors from async-imap API drift (the Client/Session type names, `read_response`, `capabilities`, `login` signatures). For each:

1. Run `cargo doc -p async-imap --open` to confirm the current 0.10 API.
2. Adjust the call site, NOT the design.

Common drift points to check:
- `Client::new` may take a generic transport that requires `AsyncRead + AsyncWrite + Unpin`.
- `client.login(user, pass)` returns `Result<Session, (Error, Client)>` — the test for `LoginRejected` matches on `async_imap::error::Error::No`. If the variant name differs, adjust.
- `caps.has_str("LOGINDISABLED")` may be `caps.has(...)` — check the `Capabilities` API.

- [ ] **Step 6: Run the unit tests in `auth.rs`**

```bash
cargo test -p rimap-imap --lib auth::tests
```

Expected: 3 tests pass.

- [ ] **Step 7: Run clippy**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/rimap-imap/Cargo.toml crates/rimap-imap/src/connection.rs crates/rimap-imap/src/auth.rs crates/rimap-imap/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(imap): Connection::ensure_connected with auth audit emission

Lazy-connect IMAP session with TCP connect, TLS handshake (via the
tls.rs builder), greeting, CAPABILITY probe, and LOGIN. Every connect
attempt emits exactly one Auth audit record via spawn_blocking so the
std-mutex audit lock never crosses an .await. Fingerprint mismatches
are enriched from TlsHandshake into the structured Tls { observed,
expected } variant by reading the verifier's OnceLock after failure.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: list / status / select read ops

**Goal:** `Connection::list_folders`, `status`, `select`. Wires `command_timeout` via the `time.rs` helper.

**Files:**
- Modify: `crates/rimap-imap/src/time.rs` (helper)
- Modify: `crates/rimap-imap/src/connection.rs` — add public methods
- Modify: `crates/rimap-imap/src/ops/folders.rs` — implementation details

- [ ] **Step 1: Write the timeout helper in `time.rs`**

Replace `crates/rimap-imap/src/time.rs`:

```rust
//! `tokio::time::timeout` wrapper that maps the elapsed error into our
//! typed `Error::Timeout { op }`.

use std::future::Future;
use std::time::Duration;

use crate::error::Error;

/// Run `fut` under `timeout`, mapping the elapsed error to `Error::Timeout`.
///
/// # Errors
/// Returns `Error::Timeout { op }` if the future does not complete within
/// `dur`. Otherwise propagates the future's own error.
pub async fn with_timeout<F, T>(
    op: &'static str,
    dur: Duration,
    fut: F,
) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    match tokio::time::timeout(dur, fut).await {
        Ok(inner) => inner,
        Err(_) => Err(Error::Timeout { op }),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use super::with_timeout;
    use crate::error::Error;

    #[tokio::test(start_paused = true)]
    async fn returns_timeout_when_future_exceeds_deadline() {
        let result: Result<(), Error> = with_timeout("test_op", Duration::from_millis(50), async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        })
        .await;
        match result {
            Err(Error::Timeout { op }) => assert_eq!(op, "test_op"),
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn passes_through_value_when_future_completes_in_time() {
        let result: Result<i32, Error> = with_timeout("ok_op", Duration::from_secs(60), async {
            Ok(42)
        })
        .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn passes_through_error_when_future_fails_in_time() {
        let result: Result<(), Error> = with_timeout("err_op", Duration::from_secs(60), async {
            Err(Error::ConnectionLost)
        })
        .await;
        assert!(matches!(result, Err(Error::ConnectionLost)));
    }
}
```

- [ ] **Step 2: Add ops methods to `Connection`**

Edit `crates/rimap-imap/src/connection.rs`. Inside `impl Connection`, add:

```rust
    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    pub async fn list_folders(&self, pattern: &str) -> Result<Vec<crate::types::Folder>, Error> {
        let dur = self.inner.cfg.command_timeout;
        crate::time::with_timeout("list", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::list(session, pattern).await
        })
        .await
    }

    /// `STATUS` for `folder` selecting the requested items.
    pub async fn status(
        &self,
        folder: &str,
        items: crate::types::StatusItems,
    ) -> Result<crate::types::FolderStatus, Error> {
        let dur = self.inner.cfg.command_timeout;
        crate::time::with_timeout("status", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::status(session, folder, items).await
        })
        .await
    }

    /// `SELECT` (or `EXAMINE` if `read_only`) the named folder.
    pub async fn select(
        &self,
        folder: &str,
        read_only: bool,
    ) -> Result<crate::types::SelectedFolder, Error> {
        let dur = self.inner.cfg.command_timeout;
        crate::time::with_timeout("select", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::select(session, folder, read_only).await
        })
        .await
    }
```

- [ ] **Step 3: Implement `ops/folders.rs`**

Replace `crates/rimap-imap/src/ops/folders.rs`:

```rust
//! `LIST`, `STATUS`, `SELECT` / `EXAMINE` against an active `async-imap` session.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{Folder, FolderStatus, SelectedFolder, StatusItems};

pub(crate) async fn list(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<Folder>, Error> {
    let mut stream = session.list(Some(""), Some(pattern)).await.map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(name) = stream.next().await {
        let name = name.map_err(map_err)?;
        out.push(Folder {
            name: name.name().to_string(),
            attributes: name
                .attributes()
                .iter()
                .map(|attr| format!("{attr:?}"))
                .collect(),
            delimiter: name.delimiter().and_then(|s| s.chars().next()),
        });
    }
    Ok(out)
}

pub(crate) async fn status(
    session: &mut ImapSession,
    folder: &str,
    items: StatusItems,
) -> Result<FolderStatus, Error> {
    let item_str = build_status_items(items);
    let mailbox = session.status(folder, &item_str).await.map_err(map_err)?;
    Ok(FolderStatus {
        messages: mailbox.exists,
        recent: mailbox.recent,
        uid_next: mailbox.uid_next,
        uid_validity: mailbox.uid_validity,
        unseen: mailbox.unseen,
    })
}

pub(crate) async fn select(
    session: &mut ImapSession,
    folder: &str,
    read_only: bool,
) -> Result<SelectedFolder, Error> {
    let mailbox = if read_only {
        session.examine(folder).await.map_err(map_err)?
    } else {
        session.select(folder).await.map_err(map_err)?
    };
    Ok(SelectedFolder {
        name: folder.to_string(),
        exists: mailbox.exists.unwrap_or(0),
        recent: mailbox.recent.unwrap_or(0),
        uid_validity: mailbox.uid_validity.unwrap_or(0),
        uid_next: mailbox.uid_next,
        read_only,
    })
}

fn build_status_items(items: StatusItems) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(5);
    if items.messages {
        parts.push("MESSAGES");
    }
    if items.recent {
        parts.push("RECENT");
    }
    if items.uid_next {
        parts.push("UIDNEXT");
    }
    if items.uid_validity {
        parts.push("UIDVALIDITY");
    }
    if items.unseen {
        parts.push("UNSEEN");
    }
    format!("({})", parts.join(" "))
}

fn map_err(err: async_imap::error::Error) -> Error {
    // Detect connection-lost-style errors and surface them as ConnectionLost
    // so the caller can drop the session and lazy-reconnect on the next op.
    let msg = err.to_string().to_lowercase();
    if msg.contains("connection") && (msg.contains("reset") || msg.contains("closed") || msg.contains("eof") || msg.contains("broken pipe")) {
        Error::ConnectionLost
    } else {
        Error::Protocol(err)
    }
}
```

> **Implementer note:** `futures_util` may need adding to `crates/rimap-imap/Cargo.toml` if it's not already a transitive dep made visible. Add `futures-util = "0.3"` to workspace deps if missing, then add `futures-util = { workspace = true }` to rimap-imap. Alternative: use `tokio_stream::StreamExt`.

> The `async-imap` `Mailbox` field types may differ slightly — `exists`, `recent`, etc. may be `Option<u32>` already. If the `unwrap_or(0)` calls don't compile, drop them and propagate `Option<u32>` directly.

- [ ] **Step 4: Build and run unit tests**

```bash
cargo build -p rimap-imap
cargo test -p rimap-imap --lib time::tests
```

Expected: green. The 3 timeout tests pass; the new ops methods compile but have no unit tests yet (covered by Dovecot integration in Task 15).

- [ ] **Step 5: Wire connection-lost into `Connection::session`**

When ops return `Error::ConnectionLost`, the public methods on `Connection` need to call `invalidate()` so the next call lazy-reconnects. Edit each of `list_folders`, `status`, `select` to wrap the inner result:

```rust
    pub async fn list_folders(&self, pattern: &str) -> Result<Vec<crate::types::Folder>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("list", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::list(session, pattern).await
        })
        .await;
        if matches!(result, Err(Error::ConnectionLost)) {
            self.invalidate().await;
        }
        result
    }
```

Apply the same pattern to `status` and `select`. (This block will repeat for `search` and `fetch_*` in tasks 12-13.)

- [ ] **Step 6: Run clippy**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean. Clippy will warn about repeated `if matches!(...)` blocks across the four methods; that's intentional duplication (DRY would require a higher-order helper that's harder to read).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/rimap-imap/Cargo.toml crates/rimap-imap/src/time.rs crates/rimap-imap/src/connection.rs crates/rimap-imap/src/ops/folders.rs
git commit -m "$(cat <<'EOF'
feat(imap): list / status / select read ops with command timeout

Adds the time::with_timeout helper (covered by tokio::time::pause unit
tests), Connection::list_folders/status/select methods, and the
folders.rs implementation against async-imap. Each public method drops
the cached session on ConnectionLost so the next call lazy-reconnects
without auto-retrying the failed command.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: search and fetch envelope/bodystructure/uid/flags/size

**Goal:** Structured + raw `SEARCH`. `FETCH ENVELOPE BODYSTRUCTURE UID FLAGS RFC822.SIZE` (no `BODY[]` yet).

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` — add `search`, `fetch`
- Modify: `crates/rimap-imap/src/ops/search.rs` — implementation
- Modify: `crates/rimap-imap/src/ops/fetch.rs` — implementation (envelope path only)

- [ ] **Step 1: Implement `ops/search.rs`**

Replace `crates/rimap-imap/src/ops/search.rs`:

```rust
//! `SEARCH` (structured + raw passthrough).

use std::fmt::Write;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{SearchQuery, StructuredQuery, Uid};

pub(crate) async fn search(
    session: &mut ImapSession,
    folder: &str,
    query: SearchQuery,
) -> Result<Vec<Uid>, Error> {
    // Caller has already SELECTed the folder via the public API; this is
    // a defensive re-select to keep the search scoped.
    session.examine(folder).await.map_err(map_err)?;

    let key = match query {
        SearchQuery::Structured(s) => structured_to_key(&s),
        SearchQuery::Raw(r) => r,
    };

    let uids = session.uid_search(&key).await.map_err(map_err)?;
    Ok(uids
        .into_iter()
        .filter_map(Uid::new)
        .collect())
}

fn structured_to_key(q: &StructuredQuery) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &q.from {
        parts.push(format!("FROM {}", quote(s)));
    }
    if let Some(s) = &q.to {
        parts.push(format!("TO {}", quote(s)));
    }
    if let Some(s) = &q.subject {
        parts.push(format!("SUBJECT {}", quote(s)));
    }
    if let Some(d) = q.since {
        parts.push(format!("SINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.before {
        parts.push(format!("BEFORE {}", format_imap_date(d)));
    }
    match q.seen {
        Some(true) => parts.push("SEEN".to_string()),
        Some(false) => parts.push("UNSEEN".to_string()),
        None => {}
    }
    if q.has_attachment {
        parts.push("BODY \"Content-Disposition: attachment\"".to_string());
    }
    if parts.is_empty() {
        return "ALL".to_string();
    }
    parts.join(" ")
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn format_imap_date(d: time::Date) -> String {
    // IMAP SEARCH dates use "DD-Mon-YYYY" with English month abbreviations.
    let month = match u8::from(d.month()) {
        1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
        5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
        9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec",
        _ => unreachable!("time::Date month is 1..=12"),
    };
    let mut out = String::with_capacity(11);
    let _ = write!(out, "{:02}-{}-{}", d.day(), month, d.year());
    out
}

fn map_err(err: async_imap::error::Error) -> Error {
    super::folders::map_err_for_test_visibility(err)
}
```

> The `map_err` function in `folders.rs` is currently `fn`-private. Change its declaration to `pub(super) fn map_err_for_test_visibility(err: async_imap::error::Error) -> Error` (rename if you prefer; the goal is one shared classifier across the ops module).

- [ ] **Step 2: Implement `ops/fetch.rs` (without BODY[])**

Replace `crates/rimap-imap/src/ops/fetch.rs`:

```rust
//! `FETCH ENVELOPE BODYSTRUCTURE UID FLAGS RFC822.SIZE`. The streaming
//! `FETCH BODY[]` path is in Task 13.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{
    Address, BodyStructure, Envelope, FetchSpec, FetchedMessage, Flag, MessageId, Uid,
};

pub(crate) async fn fetch(
    session: &mut ImapSession,
    folder: &str,
    uids: &[Uid],
    spec: FetchSpec,
) -> Result<Vec<FetchedMessage>, Error> {
    session.examine(folder).await.map_err(super::folders::map_err_for_test_visibility)?;

    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let uid_set = uids
        .iter()
        .map(|u| u.get().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let items = build_fetch_items(spec);
    let mut stream = session
        .uid_fetch(&uid_set, &items)
        .await
        .map_err(super::folders::map_err_for_test_visibility)?;

    let mut out = Vec::with_capacity(uids.len());
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err_for_test_visibility)?;
        let Some(uid_raw) = msg.uid else {
            continue;
        };
        let Some(uid) = Uid::new(uid_raw) else {
            continue;
        };
        out.push(FetchedMessage {
            uid,
            envelope: spec.envelope.then(|| convert_envelope(msg.envelope())).flatten(),
            bodystructure: spec.bodystructure.then(|| convert_bodystructure(msg.bodystructure())).flatten(),
            flags: spec.flags.then(|| {
                msg.flags()
                    .map(|f| convert_flag(&format!("{f:?}")))
                    .collect()
            }),
            size: spec.size.then(|| msg.size).flatten(),
        });
    }
    Ok(out)
}

fn build_fetch_items(spec: FetchSpec) -> String {
    let mut parts: Vec<&str> = vec!["UID"]; // always request UID
    if spec.envelope {
        parts.push("ENVELOPE");
    }
    if spec.bodystructure {
        parts.push("BODYSTRUCTURE");
    }
    if spec.flags {
        parts.push("FLAGS");
    }
    if spec.size {
        parts.push("RFC822.SIZE");
    }
    format!("({})", parts.join(" "))
}

fn convert_envelope(env: Option<&imap_proto::types::Envelope<'_>>) -> Option<Envelope> {
    let env = env?;
    Some(Envelope {
        date: env.date.as_ref().map(|b| b.to_vec()),
        subject_raw: env.subject.as_ref().map(|b| b.to_vec()),
        from: convert_addresses(env.from.as_deref()),
        sender: convert_addresses(env.sender.as_deref()),
        reply_to: convert_addresses(env.reply_to.as_deref()),
        to: convert_addresses(env.to.as_deref()),
        cc: convert_addresses(env.cc.as_deref()),
        bcc: convert_addresses(env.bcc.as_deref()),
        in_reply_to: env.in_reply_to.as_ref().map(|b| b.to_vec()),
        message_id: env.message_id.as_ref().map(|b| MessageId(b.to_vec())),
    })
}

fn convert_addresses(addrs: Option<&[imap_proto::types::Address<'_>]>) -> Vec<Address> {
    addrs
        .unwrap_or(&[])
        .iter()
        .map(|a| Address {
            name: a.name.as_ref().map(|b| b.to_vec()),
            adl: a.adl.as_ref().map(|b| b.to_vec()),
            mailbox: a.mailbox.as_ref().map(|b| b.to_vec()),
            host: a.host.as_ref().map(|b| b.to_vec()),
        })
        .collect()
}

fn convert_bodystructure(_bs: Option<&imap_proto::types::BodyStructure<'_>>) -> Option<BodyStructure> {
    // Recursive conversion is mechanical but lengthy; deferred to a follow-up
    // commit if real envelope tests don't exercise it. For Sprint 3, returning
    // None is acceptable when bodystructure parsing isn't reachable from a test.
    // TODO BEFORE COMMIT: implement recursive conversion using `imap_proto::types::BodyStructure`.
    None
}

fn convert_flag(s: &str) -> Flag {
    // async-imap exposes flags as a typed enum, but we round-trip through the
    // Debug repr here to keep the conversion focused. Replace with a typed
    // match against `async_imap::types::Flag` if it's exposed publicly.
    match s {
        "Seen" => Flag::Seen,
        "Answered" => Flag::Answered,
        "Flagged" => Flag::Flagged,
        "Deleted" => Flag::Deleted,
        "Draft" => Flag::Draft,
        "Recent" => Flag::Recent,
        other => Flag::Keyword(other.to_string()),
    }
}
```

> **TWO things flagged TODO BEFORE COMMIT in this file:**
>
> 1. **`convert_bodystructure`** must actually convert. Implement a recursive function that walks `imap_proto::types::BodyStructure::{BasicFields, ...}` and produces `BodyStructure::{Single, Multipart}`. If `imap_proto` is not in the dep tree, add it (it's a transitive dep of `async-imap` already). The function will be ~40 lines; split out as `fn convert_bs_recursive(...)`.
>
> 2. **`convert_flag`** should match against the typed `async_imap::types::Flag` enum directly rather than going through `Debug`. Confirm the actual enum name (it may be `async_imap::imap_proto::Flag` or re-exported from `async_imap::types::Flag`). Use the typed match.
>
> Both must be done before the commit at the bottom of this task. Do NOT skip these — the comment is a forcing function for the implementer, not a deferred TODO.

- [ ] **Step 3: Add `search` and `fetch` to `Connection`**

Edit `crates/rimap-imap/src/connection.rs`. Inside `impl Connection`, add:

```rust
    /// `SEARCH` against `folder`. Returns matching UIDs.
    pub async fn search(
        &self,
        folder: &str,
        query: crate::types::SearchQuery,
    ) -> Result<Vec<crate::types::Uid>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("search", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::search::search(session, folder, query).await
        })
        .await;
        if matches!(result, Err(Error::ConnectionLost)) {
            self.invalidate().await;
        }
        result
    }

    /// `FETCH` for the given UIDs with the requested items. Does NOT include
    /// `BODY[]` — see `fetch_body` for full message retrieval.
    pub async fn fetch(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        spec: crate::types::FetchSpec,
    ) -> Result<Vec<crate::types::FetchedMessage>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("fetch", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::fetch::fetch(session, folder, uids, spec).await
        })
        .await;
        if matches!(result, Err(Error::ConnectionLost)) {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 4: Build**

```bash
cargo build -p rimap-imap
```

Expected: compiles. Likely API drift in `imap_proto` types — `BasicFields`, `Address`, `Envelope` field names may differ. Check `cargo doc -p imap-proto --open` if available, or grep async-imap's source for the actual type signatures.

- [ ] **Step 5: Run clippy and tests**

```bash
cargo test -p rimap-imap
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/connection.rs crates/rimap-imap/src/ops/search.rs crates/rimap-imap/src/ops/fetch.rs crates/rimap-imap/src/ops/folders.rs
git commit -m "$(cat <<'EOF'
feat(imap): search and fetch envelope/bodystructure/uid/flags/size

SearchQuery::Structured serializes to an IMAP key string with proper
quoting and date formatting; SearchQuery::Raw passes through verbatim.
fetch returns FetchedMessage values populated according to FetchSpec,
with recursive BODYSTRUCTURE conversion. BODY[] streaming lives in
Task 13.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: fetch_body with size cap and connection drop on overflow

**Goal:** `Connection::fetch_body` streams `BODY[]` bytes, aborts if it would exceed `max_fetch_body_bytes`, and tears down the connection on overflow.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` — add `fetch_body`
- Modify: `crates/rimap-imap/src/ops/fetch.rs` — add streaming body fetch

- [ ] **Step 1: Add the streaming body fetch to `ops/fetch.rs`**

Append to `crates/rimap-imap/src/ops/fetch.rs`:

```rust
/// Fetch the full `BODY[]` of a single UID. Streams the bytes; if the
/// running total would exceed `limit`, aborts and returns `Error::SizeLimit`.
/// On size-limit overflow the caller drops the session — the IMAP response
/// state is half-consumed and the connection cannot be reused.
pub(crate) async fn fetch_body(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    limit: u64,
) -> Result<Vec<u8>, Error> {
    session.examine(folder).await.map_err(super::folders::map_err_for_test_visibility)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "BODY.PEEK[]")
        .await
        .map_err(super::folders::map_err_for_test_visibility)?;

    let mut acc: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    let mut found = false;

    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err_for_test_visibility)?;
        if let Some(body) = msg.body() {
            found = true;
            let chunk_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
            let projected = total.saturating_add(chunk_len);
            if projected > limit {
                return Err(Error::SizeLimit { limit });
            }
            acc.extend_from_slice(body);
            total = projected;
        }
    }

    if !found {
        return Err(Error::Protocol(async_imap::error::Error::Bad(
            "FETCH BODY[] returned no body".into(),
        )));
    }
    Ok(acc)
}
```

> **Note on streaming granularity:** `async-imap` delivers each `Fetch` response as a parsed message with `body()` returning the full bytes. This means the size check happens per-message, not per-network-chunk — for a 100 MB body the client would buffer all 100 MB before the check fires. To enforce the limit before exceeding it, we'd need a lower-level streaming API (`uid_fetch_stream` or similar) that doesn't exist in async-imap 0.10. For Sprint 3 the per-message check is acceptable: the IMAP server will not deliver bytes faster than `command_timeout` allows, and the configured `max_fetch_body_bytes` is a hard cap on what we accept post-receive. Document this limitation in the rustdoc above the function (one sentence).

Add a doc note to the function above the body:

```rust
    // NOTE: async-imap delivers each Fetch as a parsed unit, so the body bytes
    // are already in memory before this check fires. The limit acts as an
    // accept/reject gate, not a backpressure mechanism. A future async-imap
    // version with chunked body streaming would let us enforce the limit
    // mid-network-read.
```

- [ ] **Step 2: Add `fetch_body` to `Connection`**

Inside `impl Connection`:

```rust
    /// Fetch the full `BODY[]` of `uid` from `folder`. Returns raw bytes
    /// (no MIME parsing — Sprint 4's `rimap-content` owns that). Drops the
    /// connection on size-limit overflow.
    pub async fn fetch_body(
        &self,
        folder: &str,
        uid: crate::types::Uid,
    ) -> Result<Vec<u8>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_fetch_body_bytes;
        let result = crate::time::with_timeout("fetch_body", dur, async {
            let mut guard = self.session().await?;
            let session = guard.as_mut().unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::fetch::fetch_body(session, folder, uid, limit).await
        })
        .await;
        match &result {
            Err(Error::ConnectionLost) | Err(Error::SizeLimit { .. }) => {
                self.invalidate().await;
            }
            _ => {}
        }
        result
    }
```

- [ ] **Step 3: Build and test**

```bash
cargo test -p rimap-imap
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: green. The size-limit-mid-stream behavior gets covered by Dovecot test case 10 in Task 15.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/connection.rs crates/rimap-imap/src/ops/fetch.rs
git commit -m "$(cat <<'EOF'
feat(imap): fetch_body with size cap and connection drop on overflow

Streams BODY[] bytes per FETCH response and rejects with
Error::SizeLimit if the running total would exceed the configured
max_fetch_body_bytes. On overflow the connection is invalidated so
the next call lazy-reconnects rather than reusing a half-consumed
response stream.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Dovecot integration harness (no test bodies yet)

**Goal:** Compose file, Dovecot config, fixtures, and the Rust `DovecotHarness` Drop guard. No test cases yet.

**Files:**
- Create: `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`
- Create: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`
- Create: `crates/rimap-imap/tests/integration/dovecot/users`
- Create: `crates/rimap-imap/tests/integration/dovecot/entrypoint.sh`
- Create: `crates/rimap-imap/tests/integration/dovecot/fixtures/{plain,multipart,attachment}.eml`
- Create: `crates/rimap-imap/tests/integration/support/mod.rs`
- Create: `crates/rimap-imap/tests/integration/support/docker.rs`
- Create: `crates/rimap-imap/tests/integration/support/fixtures.rs`
- Create: `crates/rimap-imap/tests/integration/dovecot.rs` (smoke test only)

- [ ] **Step 1: Create the Dovecot Docker Compose file**

Create `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`:

```yaml
services:
  dovecot:
    image: dovecot/dovecot:2.3.21
    container_name: ${COMPOSE_PROJECT_NAME:-rimap-it}-dovecot
    ports:
      - "0:993"
    volumes:
      - ./dovecot.conf:/etc/dovecot/dovecot.conf:ro
      - ./users:/etc/dovecot/users:ro
      - ./fixtures:/fixtures:ro
      - ./entrypoint.sh:/entrypoint.sh:ro
      - shared:/shared
    entrypoint: ["/bin/sh", "/entrypoint.sh"]
    healthcheck:
      test: ["CMD", "test", "-f", "/shared/ready"]
      interval: 1s
      timeout: 1s
      retries: 30

volumes:
  shared:
```

> Port `0:993` lets Docker pick a free host port; the harness reads the assigned port via `docker compose port`.

- [ ] **Step 2: Create the Dovecot config**

Create `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`:

```
protocols = imap

ssl = required
ssl_cert = </etc/dovecot/cert.pem
ssl_key = </etc/dovecot/key.pem
ssl_min_protocol = TLSv1.2

disable_plaintext_auth = no

mail_location = maildir:~/Maildir

passdb {
  driver = passwd-file
  args = scheme=PLAIN /etc/dovecot/users
}

userdb {
  driver = static
  args = uid=1000 gid=1000 home=/var/mail/%u
}

namespace inbox {
  inbox = yes
  separator = /
}

service imap-login {
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

log_path = /dev/stderr
info_log_path = /dev/stderr
debug_log_path = /dev/stderr
```

- [ ] **Step 3: Create the users file**

Create `crates/rimap-imap/tests/integration/dovecot/users`:

```
rimap-test:{PLAIN}testpass
```

- [ ] **Step 4: Create the entrypoint script**

Create `crates/rimap-imap/tests/integration/dovecot/entrypoint.sh`:

```sh
#!/bin/sh
set -eu

# Generate a self-signed cert at container start so each test run gets a
# fresh fingerprint.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/dovecot/key.pem \
    -out /etc/dovecot/cert.pem \
    -days 1 \
    -subj "/CN=rimap-test-dovecot" >/dev/null 2>&1

# Compute and publish the SHA-256 fingerprint of the leaf cert (DER form,
# lowercase hex, no separators) so the host harness can read it.
openssl x509 -in /etc/dovecot/cert.pem -outform DER \
    | openssl dgst -sha256 -hex \
    | awk '{print $2}' \
    > /shared/fingerprint.hex

# Seed mailboxes for the test user.
mkdir -p /var/mail/rimap-test/Maildir/cur \
         /var/mail/rimap-test/Maildir/new \
         /var/mail/rimap-test/Maildir/tmp \
         "/var/mail/rimap-test/Maildir/.Archive/cur" \
         "/var/mail/rimap-test/Maildir/.Archive/new" \
         "/var/mail/rimap-test/Maildir/.Archive/tmp" \
         "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/cur" \
         "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/new" \
         "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/tmp"

# Drop fixture .eml files into INBOX/new — Dovecot will move them to cur on
# next read.
i=0
for fixture in /fixtures/*.eml; do
    i=$((i + 1))
    cp "$fixture" "/var/mail/rimap-test/Maildir/new/${i}.fixture"
done

chown -R 1000:1000 /var/mail/rimap-test
chmod -R u+rwX /var/mail/rimap-test

# Mark ready so the host harness's healthcheck passes.
touch /shared/ready

# Hand off to dovecot.
exec dovecot -F
```

- [ ] **Step 5: Create the fixture .eml files**

Create `crates/rimap-imap/tests/integration/dovecot/fixtures/plain.eml`:

```
From: Test Sender <sender@example.test>
To: rimap-test <rimap-test@example.test>
Subject: Sprint 3 plain text fixture
Message-ID: <plain-001@example.test>
Date: Tue, 7 Apr 2026 10:00:00 +0000
Content-Type: text/plain; charset=us-ascii

This is a plain text fixture for the rimap-imap integration tests.
It contains exactly one paragraph and no attachments.
```

Create `crates/rimap-imap/tests/integration/dovecot/fixtures/multipart.eml`:

```
From: Multi Sender <multi@example.test>
To: rimap-test <rimap-test@example.test>
Subject: Sprint 3 multipart fixture
Message-ID: <multi-001@example.test>
Date: Tue, 7 Apr 2026 10:00:01 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary42"

--boundary42
Content-Type: text/plain; charset=us-ascii

Plain text body of the multipart fixture.

--boundary42
Content-Type: text/html; charset=us-ascii

<p>HTML body of the multipart fixture.</p>

--boundary42--
```

Create `crates/rimap-imap/tests/integration/dovecot/fixtures/attachment.eml`:

```
From: Attach Sender <attach@example.test>
To: rimap-test <rimap-test@example.test>
Subject: Sprint 3 attachment fixture
X-Test: marker
Message-ID: <attach-001@example.test>
Date: Tue, 7 Apr 2026 10:00:02 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundaryAA"

--boundaryAA
Content-Type: text/plain; charset=us-ascii

Body of the attachment fixture.

--boundaryAA
Content-Type: application/octet-stream; name="payload.bin"
Content-Disposition: attachment; filename="payload.bin"
Content-Transfer-Encoding: base64

SGVsbG8gd29ybGQK

--boundaryAA--
```

- [ ] **Step 6: Create the support module**

Create `crates/rimap-imap/tests/integration/support/mod.rs`:

```rust
//! Test support: Dovecot Docker harness, fixture loaders.

pub mod docker;
pub mod fixtures;
```

Create `crates/rimap-imap/tests/integration/support/fixtures.rs`:

```rust
//! Path helpers for the seeded fixtures.

use std::path::PathBuf;

#[must_use]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("integration")
        .join("dovecot")
        .join("fixtures")
}
```

- [ ] **Step 7: Create the Dovecot harness in `support/docker.rs`**

Create `crates/rimap-imap/tests/integration/support/docker.rs`:

```rust
//! `DovecotHarness`: hand-rolled `docker compose up`/`down` lifecycle with a
//! Drop guard. Each test run gets a unique compose project name so parallel
//! tests don't collide.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    DockerCommandFailed(String),
    Timeout,
    FingerprintReadFailed(String),
    PortReadFailed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DockerUnavailable => f.write_str("docker is not available"),
            Self::DockerCommandFailed(s) => write!(f, "docker command failed: {s}"),
            Self::Timeout => f.write_str("timed out waiting for dovecot ready"),
            Self::FingerprintReadFailed(s) => write!(f, "fingerprint read failed: {s}"),
            Self::PortReadFailed(s) => write!(f, "port read failed: {s}"),
        }
    }
}

impl std::error::Error for HarnessError {}

pub struct DovecotHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    port: u16,
}

impl DovecotHarness {
    /// Start a fresh Dovecot container. Returns `Err(DockerUnavailable)`
    /// if Docker is missing AND `RIMAP_REQUIRE_DOCKER` is unset; returns
    /// the underlying error if `RIMAP_REQUIRE_DOCKER=1`.
    pub fn try_start() -> Result<Self, HarnessError> {
        if !docker_available() {
            if std::env::var("RIMAP_REQUIRE_DOCKER").is_ok() {
                return Err(HarnessError::DockerCommandFailed(
                    "docker missing but RIMAP_REQUIRE_DOCKER=1".into(),
                ));
            }
            return Err(HarnessError::DockerUnavailable);
        }

        let project = format!("rimap-it-{}", uuid_like());
        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("integration")
            .join("dovecot");

        let status = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&project)
            .arg("up")
            .arg("-d")
            .current_dir(&compose_dir)
            .status()
            .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))?;
        if !status.success() {
            return Err(HarnessError::DockerCommandFailed(format!(
                "compose up exit {status}"
            )));
        }

        let harness = Self {
            project: project.clone(),
            compose_dir: compose_dir.clone(),
            fingerprint: TlsFingerprint::from_cert_der(b"placeholder"),
            port: 0,
        };

        let started = Instant::now();
        let timeout = Duration::from_secs(30);
        loop {
            if started.elapsed() > timeout {
                return Err(HarnessError::Timeout);
            }
            if let (Ok(fp), Ok(p)) = (read_fingerprint(&project), read_port(&project, &compose_dir))
            {
                return Ok(Self {
                    project,
                    compose_dir,
                    fingerprint: fp,
                    port: p,
                });
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    #[must_use]
    pub fn host(&self) -> &str {
        "127.0.0.1"
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn pinned_fingerprint(&self) -> TlsFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn username(&self) -> &str {
        "rimap-test"
    }

    #[must_use]
    pub fn password(&self) -> &str {
        "testpass"
    }

    /// Run an arbitrary command inside the running dovecot container.
    pub fn exec(&self, args: &[&str]) -> Result<std::process::Output, HarnessError> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose").arg("-p").arg(&self.project);
        cmd.arg("exec").arg("-T").arg("dovecot");
        for a in args {
            cmd.arg(a);
        }
        cmd.current_dir(&self.compose_dir);
        cmd.output()
            .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))
    }
}

impl Drop for DovecotHarness {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("down")
            .arg("-v")
            .arg("--remove-orphans")
            .current_dir(&self.compose_dir)
            .status();
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, HarnessError> {
    let out = Command::new("docker")
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("exec")
        .arg("-T")
        .arg("dovecot")
        .arg("cat")
        .arg("/shared/fingerprint.hex")
        .output()
        .map_err(|e| HarnessError::FingerprintReadFailed(e.to_string()))?;
    if !out.status.success() {
        return Err(HarnessError::FingerprintReadFailed("not yet ready".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    TlsFingerprint::from_hex(&s)
        .map_err(|e| HarnessError::FingerprintReadFailed(e.to_string()))
}

fn read_port(project: &str, compose_dir: &std::path::Path) -> Result<u16, HarnessError> {
    let out = Command::new("docker")
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("port")
        .arg("dovecot")
        .arg("993")
        .current_dir(compose_dir)
        .output()
        .map_err(|e| HarnessError::PortReadFailed(e.to_string()))?;
    if !out.status.success() {
        return Err(HarnessError::PortReadFailed("not yet bound".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let port_str = s.trim().rsplit(':').next().unwrap_or("");
    port_str
        .parse::<u16>()
        .map_err(|e| HarnessError::PortReadFailed(e.to_string()))
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}
```

> The `uuid_like()` helper avoids pulling in the `uuid` crate just for a per-test project name. Nanosecond-since-epoch is sufficient for parallel test isolation.

- [ ] **Step 8: Create the smoke test stub**

Create `crates/rimap-imap/tests/integration/dovecot.rs`:

```rust
//! Dovecot integration smoke test. Real test cases land in Task 15.

#![expect(clippy::unwrap_used, reason = "tests")]

mod support;

use support::docker::{DovecotHarness, HarnessError};

#[test]
fn dovecot_harness_starts_and_publishes_fingerprint() {
    let harness = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => {
            eprintln!("skipping: docker not available");
            return;
        }
        Err(e) => panic!("harness failed: {e}"),
    };
    assert!(harness.port() > 0);
    let fp_hex = harness.pinned_fingerprint().to_hex();
    assert_eq!(fp_hex.len(), 64);
}
```

- [ ] **Step 9: Build (no test execution yet)**

```bash
cargo build -p rimap-imap --tests
```

Expected: compiles. The test won't run yet — Task 15 adds the actual coverage.

If running it locally with Docker installed, you can `cargo test -p rimap-imap --test dovecot` and it should pass. In CI without `RIMAP_REQUIRE_DOCKER=1` it skips silently.

- [ ] **Step 10: Run clippy**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 11: Commit**

```bash
git add crates/rimap-imap/tests/integration/
git commit -m "$(cat <<'EOF'
test(imap): dovecot integration harness with self-signed cert lifecycle

docker-compose.yml + dovecot.conf + entrypoint.sh that generates a
fresh self-signed cert per run and publishes its leaf-DER SHA-256
fingerprint into a shared volume. DovecotHarness reads the fingerprint
+ host port back through `docker compose exec`/`port`, exposes them to
tests, and tears the project down on Drop. Each test run gets a unique
compose project name to allow parallel execution.

A smoke test verifies the harness starts and publishes a 64-char
fingerprint; the full coverage suite lands in Task 15.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Dovecot integration test cases (1-11)

**Goal:** All 11 Dovecot test cases from spec §7. Each is a separate `#[test]` in `tests/integration/dovecot.rs`. Each starts the harness independently (acceptable startup tax for Sprint 3).

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`
- Create: a small helper that builds a `Connection` from a `DovecotHarness`

- [ ] **Step 1: Add a Connection builder helper to `support/docker.rs`**

Append to `crates/rimap-imap/tests/integration/support/docker.rs`:

```rust
use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::CredentialStore;
use rimap_imap::{Connection, ConnectionConfig};
use std::sync::Arc;
use tempfile::TempDir;

/// In-memory credential store for tests. Returns the configured password
/// for any account name.
pub struct StaticCreds(pub String);

impl CredentialStore for StaticCreds {
    fn get_password(&self, _account: &str) -> Result<Option<String>, rimap_config::ConfigError> {
        Ok(Some(self.0.clone()))
    }
    fn set_password(&self, _account: &str, _password: &str) -> Result<(), rimap_config::ConfigError> {
        unreachable!("tests do not write credentials")
    }
}

/// Bundle: harness + temp audit dir + writer + connection.
pub struct ConnectedHarness {
    pub harness: DovecotHarness,
    pub audit_dir: TempDir,
    pub audit: AuditWriter,
    pub connection: Connection,
}

impl ConnectedHarness {
    pub fn new(pin_with: PinChoice) -> Result<Self, HarnessError> {
        let harness = DovecotHarness::try_start()?;
        let audit_dir = TempDir::new().expect("tempdir");
        let audit_path = audit_dir.path().join("audit.jsonl");
        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            initial_seq: Seq::FIRST,
        })
        .expect("audit open");

        let pinned = match pin_with {
            PinChoice::Correct => Some(harness.pinned_fingerprint()),
            PinChoice::Wrong => Some(TlsFingerprint::from_cert_der(b"deliberately-wrong")),
            PinChoice::None => None,
        };

        let cfg = ConnectionConfig {
            host: harness.host().to_string(),
            port: harness.port(),
            username: harness.username().to_string(),
            pinned_fingerprint: pinned,
            connect_timeout: std::time::Duration::from_secs(10),
            command_timeout: std::time::Duration::from_secs(10),
            max_fetch_body_bytes: 5_242_880,
        };
        let creds: Arc<dyn CredentialStore> = Arc::new(StaticCreds(harness.password().to_string()));
        let connection = Connection::new(cfg, audit.clone(), creds);
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
}

#[derive(Debug, Clone, Copy)]
pub enum PinChoice {
    Correct,
    Wrong,
    None,
}
```

> If the `CredentialStore` trait signature differs from the assumed `get_password(&str) -> Result<Option<String>>`, adjust to match the actual trait read in Task 8 of the original investigation. Run `grep -n "trait CredentialStore" crates/rimap-config/src/credential.rs` to confirm.

- [ ] **Step 2: Replace the smoke test in `dovecot.rs` with the 11-case suite**

Replace `crates/rimap-imap/tests/integration/dovecot.rs`:

```rust
//! Dovecot-in-Docker integration suite for rimap-imap. CI runs Docker;
//! local devs without Docker get the skip path automatically.

#![expect(clippy::unwrap_used, reason = "tests")]

mod support;

use std::time::Duration;

use rimap_imap::error::{AuthFailure, Error};
use rimap_imap::{Connection, ConnectionConfig};
use support::docker::{ConnectedHarness, DovecotHarness, HarnessError, PinChoice};

fn boot(pin: PinChoice) -> Option<ConnectedHarness> {
    match ConnectedHarness::new(pin) {
        Ok(h) => Some(h),
        Err(HarnessError::DockerUnavailable) => {
            eprintln!("skipping: docker not available");
            None
        }
        Err(e) => panic!("harness failed: {e}"),
    }
}

fn read_audit_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[tokio::test]
async fn case_01_connect_with_correct_pin_succeeds() {
    let Some(h) = boot(PinChoice::Correct) else { return; };
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));
    assert!(h.connection.is_connected().await);

    let lines = read_audit_lines(&h.audit_path());
    let auths: Vec<_> = lines.iter().filter(|v| v["kind"] == "auth").collect();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0]["result"], "success");
    assert_eq!(auths[0]["fingerprint_match"], true);
}

#[tokio::test]
async fn case_02_connect_with_wrong_pin_emits_audit_and_returns_tls_error() {
    let Some(h) = boot(PinChoice::Wrong) else { return; };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(Error::Tls { observed, expected }) => {
            assert_eq!(expected, rimap_core::TlsFingerprint::from_cert_der(b"deliberately-wrong"));
            assert_eq!(observed, h.harness.pinned_fingerprint());
        }
        Err(Error::TlsHandshake(_)) => {
            // Acceptable fallback if the enrichment path didn't fire — the
            // audit record is still the source of truth for the fingerprint.
        }
        other => panic!("expected TLS error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let mismatch = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_TLS")
        .expect("expected an ERR_TLS auth record");
    assert_eq!(mismatch["fingerprint_match"], false);
    assert!(mismatch["tls_fingerprint_sha256"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn case_03_connect_with_no_pin_uses_system_trust_and_fails_self_signed() {
    let Some(h) = boot(PinChoice::None) else { return; };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(Error::TlsHandshake(_)) => {}
        other => panic!("expected TlsHandshake error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let auth = lines
        .iter()
        .find(|v| v["kind"] == "auth")
        .expect("auth record");
    assert_eq!(auth["result"], "failure");
    assert_eq!(auth["error_code"], "ERR_TLS");
}

#[tokio::test]
async fn case_04_login_rejected_emits_audit() {
    use rimap_audit::{AuditOptions, AuditWriter, Seq};
    use rimap_config::credential::CredentialStore;
    use std::sync::Arc;

    struct WrongPass;
    impl CredentialStore for WrongPass {
        fn get_password(&self, _: &str) -> Result<Option<String>, rimap_config::ConfigError> {
            Ok(Some("wrong-password".to_string()))
        }
        fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
            unreachable!()
        }
    }

    let Some(h) = boot(PinChoice::Correct) else { return; };
    // Rebuild the connection with a wrong-password credential store but
    // reuse the harness + audit writer.
    let cfg = ConnectionConfig {
        host: h.harness.host().to_string(),
        port: h.harness.port(),
        username: h.harness.username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(WrongPass);
    let conn = Connection::new(cfg, h.audit.clone(), creds);

    let result = conn.list_folders("*").await;
    match result {
        Err(Error::Auth { reason: AuthFailure::LoginRejected }) => {}
        other => panic!("expected LoginRejected, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let rejected = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_AUTH")
        .expect("ERR_AUTH record");
    assert_eq!(rejected["result"], "failure");
}

#[tokio::test]
async fn case_05_list_returns_seeded_folders() {
    let Some(h) = boot(PinChoice::Correct) else { return; };
    let folders = h.connection.list_folders("*").await.unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")));
    assert!(names.iter().any(|n| n.contains("Archive")));
    assert!(names.iter().any(|n| n.contains("Subfolder")));
}

#[tokio::test]
async fn case_06_search_structured_subject_match() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else { return; };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty(), "expected at least one UID for the seeded subject");
}

#[tokio::test]
async fn case_07_search_raw_passthrough() {
    use rimap_imap::types::SearchQuery;

    let Some(h) = boot(PinChoice::Correct) else { return; };
    let q = SearchQuery::Raw("HEADER \"X-Test\" \"marker\"".to_string());
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty(), "expected at least one UID for X-Test: marker");
}

#[tokio::test]
async fn case_08_fetch_envelope_and_bodystructure() {
    use rimap_imap::types::{FetchSpec, SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else { return; };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty());
    let spec = FetchSpec {
        envelope: true,
        bodystructure: true,
        uid: true,
        flags: false,
        size: false,
    };
    let msgs = h.connection.fetch("INBOX", &uids, spec).await.unwrap();
    assert_eq!(msgs.len(), uids.len());
    let envelope = msgs[0].envelope.as_ref().expect("envelope");
    assert!(envelope.subject_raw.is_some());
    assert!(msgs[0].bodystructure.is_some());
}

#[tokio::test]
async fn case_09_fetch_body_under_limit() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else { return; };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty());
    let body = h.connection.fetch_body("INBOX", uids[0]).await.unwrap();
    assert!(!body.is_empty());
    assert!(body.len() < 5_000, "fixture is small");
}

#[tokio::test]
async fn case_10_fetch_body_over_limit_drops_connection() {
    use rimap_audit::{AuditOptions, AuditWriter, Seq};
    use rimap_config::credential::CredentialStore;
    use rimap_imap::types::{SearchQuery, StructuredQuery};
    use std::sync::Arc;

    let Some(h) = boot(PinChoice::Correct) else { return; };
    // Rebuild a connection with a 10-byte limit.
    let cfg = ConnectionConfig {
        host: h.harness.host().to_string(),
        port: h.harness.port(),
        username: h.harness.username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 10,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(support::docker::StaticCreds(h.harness.password().to_string()));
    let conn = Connection::new(cfg, h.audit.clone(), creds);

    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = conn.search("INBOX", q).await.unwrap();
    let result = conn.fetch_body("INBOX", uids[0]).await;
    match result {
        Err(Error::SizeLimit { limit }) => assert_eq!(limit, 10),
        other => panic!("expected SizeLimit, got {other:?}"),
    }
    assert!(!conn.is_connected().await);
}

#[tokio::test]
async fn case_11_tcp_half_open_recovery() {
    let Some(h) = boot(PinChoice::Correct) else { return; };
    // Establish.
    let _ = h.connection.list_folders("*").await.unwrap();
    assert!(h.connection.is_connected().await);

    // Kill imap process inside the container.
    let _ = h.harness.exec(&["pkill", "-9", "imap"]);

    // Next op should fail with ConnectionLost (or Protocol that maps to it).
    let result = h.connection.list_folders("*").await;
    assert!(
        matches!(result, Err(Error::ConnectionLost) | Err(Error::Protocol(_))),
        "expected ConnectionLost or Protocol error, got {result:?}"
    );
    assert!(!h.connection.is_connected().await);

    // Following op should reconnect cleanly.
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(!folders.is_empty());
}
```

> **Implementer note:** The exact behavior of `pkill imap` inside Dovecot's container depends on whether the parent supervises children. If the next call hangs instead of erroring, replace `pkill imap` with `docker compose -p ${PROJECT} stop dovecot && docker compose -p ${PROJECT} start dovecot`. Add a helper on `DovecotHarness` for this if needed.

- [ ] **Step 3: Build and (if Docker) run**

```bash
cargo build -p rimap-imap --tests
```

If you have Docker:

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test dovecot
```

Expected: 11 tests pass.

If you don't have Docker:

```bash
cargo test -p rimap-imap --test dovecot
```

Expected: 11 tests skip (each prints "skipping: docker not available").

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs crates/rimap-imap/tests/integration/support/docker.rs
git commit -m "$(cat <<'EOF'
test(imap): dovecot integration suite covering all 11 cases

The full Sprint 3 exit-criteria suite: pin success, pin mismatch with
audit, system-trust failure on self-signed, login reject, list, search
(structured + raw), fetch envelope/bodystructure, fetch body under
limit, fetch body over limit with connection drop, and TCP half-open
recovery without auto-retry. Each test boots its own DovecotHarness;
in CI under RIMAP_REQUIRE_DOCKER=1 they all run, locally without
Docker they all skip cleanly.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Proton Bridge harness README and gated tests

**Goal:** Documentation for running against a real Proton Bridge instance, plus two gated tests that never run in CI.

**Files:**
- Create: `crates/rimap-imap/tests/integration/proton/README.md`
- Create: `crates/rimap-imap/tests/integration/proton.rs`

- [ ] **Step 1: Write the Proton Bridge README**

Create `crates/rimap-imap/tests/integration/proton/README.md`:

```markdown
# Proton Bridge integration tests (local only)

These tests connect to a running Proton Bridge instance and exercise the
real IMAP login flow against a real mailbox. They never run in CI — they
require credentials in environment variables and a Bridge instance the
test machine has logged into.

## Prerequisites

1. Install [Proton Mail Bridge](https://proton.me/mail/bridge) and log in.
2. Open Bridge → Settings → IMAP/SMTP and note the IMAP host (default
   `127.0.0.1`) and port (default `1143`).
3. Extract Bridge's TLS fingerprint with the openssl one-liner below — Bridge
   uses a per-installation self-signed cert that the system trust store
   does not know about, so the test must pin it.

## Extracting the fingerprint

```sh
echo | openssl s_client -connect 127.0.0.1:1143 -starttls imap 2>/dev/null \
    | openssl x509 -outform DER \
    | openssl dgst -sha256 -hex \
    | awk '{print $2}'
```

The output is a 64-character lowercase hex string. Set it as
`PROTON_BRIDGE_FINGERPRINT` (see below).

## Required environment variables

| Variable | Description |
|---|---|
| `PROTON_BRIDGE_TEST` | Set to any non-empty value to enable the tests. |
| `PROTON_BRIDGE_HOST` | Bridge IMAP host. Default `127.0.0.1`. |
| `PROTON_BRIDGE_PORT` | Bridge IMAP port. Default `1143`. |
| `PROTON_BRIDGE_USER` | Bridge IMAP username (your Proton email). |
| `PROTON_BRIDGE_PASS` | Bridge IMAP password (the per-app password Bridge generates, NOT your Proton account password). |
| `PROTON_BRIDGE_FINGERPRINT` | The 64-char hex fingerprint extracted above. |

## Running

```sh
PROTON_BRIDGE_TEST=1 \
  PROTON_BRIDGE_USER=alice@proton.me \
  PROTON_BRIDGE_PASS=xxxx-xxxx-xxxx-xxxx \
  PROTON_BRIDGE_FINGERPRINT=abc... \
  cargo test -p rimap-imap --test proton
```

Without `PROTON_BRIDGE_TEST=1` the tests print a skip message and pass.

## Security notes

- Putting Bridge passwords in environment variables means they end up in
  shell history, process listings, and (on shared dev machines) other
  users' view of `/proc/<pid>/environ`. Run this on a personal workstation
  only.
- The test connects to a real mailbox and READS messages. It does not
  modify, delete, or send anything. Sprint 3 has no write operations.
- Bridge's TLS fingerprint changes if you reinstall Bridge or rotate its
  cert; you must re-extract and re-set the env var when this happens.
```

- [ ] **Step 2: Write the Proton Bridge tests**

Create `crates/rimap-imap/tests/integration/proton.rs`:

```rust
//! Proton Bridge integration tests. Local only — never runs in CI.

#![expect(clippy::unwrap_used, reason = "tests")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::CredentialStore;
use rimap_core::TlsFingerprint;
use rimap_imap::types::FetchSpec;
use rimap_imap::{Connection, ConnectionConfig};

struct EnvCreds(String);
impl CredentialStore for EnvCreds {
    fn get_password(&self, _: &str) -> Result<Option<String>, rimap_config::ConfigError> {
        Ok(Some(self.0.clone()))
    }
    fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
        unreachable!()
    }
}

struct ProtonConfig {
    host: String,
    port: u16,
    user: String,
    pass: String,
    fingerprint: TlsFingerprint,
}

fn require_proton() -> Option<ProtonConfig> {
    if std::env::var("PROTON_BRIDGE_TEST").is_err() {
        eprintln!("skipping: set PROTON_BRIDGE_TEST=1 to run");
        return None;
    }
    let host = std::env::var("PROTON_BRIDGE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("PROTON_BRIDGE_PORT")
        .unwrap_or_else(|_| "1143".to_string())
        .parse()
        .expect("PROTON_BRIDGE_PORT must be a u16");
    let user = std::env::var("PROTON_BRIDGE_USER").expect("PROTON_BRIDGE_USER required");
    let pass = std::env::var("PROTON_BRIDGE_PASS").expect("PROTON_BRIDGE_PASS required");
    let fingerprint_hex =
        std::env::var("PROTON_BRIDGE_FINGERPRINT").expect("PROTON_BRIDGE_FINGERPRINT required");
    let fingerprint = TlsFingerprint::from_hex(&fingerprint_hex).expect("valid hex fingerprint");
    Some(ProtonConfig {
        host,
        port,
        user,
        pass,
        fingerprint,
    })
}

fn build_connection(cfg: &ProtonConfig) -> Connection {
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditWriter::open(&AuditOptions {
        path: dir.path().join("audit.jsonl"),
        rotate_bytes: 0,
        initial_seq: Seq::FIRST,
    })
    .unwrap();
    let conn_cfg = ConnectionConfig {
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.user.clone(),
        pinned_fingerprint: Some(cfg.fingerprint),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(60),
        max_fetch_body_bytes: 26_214_400,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(EnvCreds(cfg.pass.clone()));
    Connection::new(conn_cfg, audit, creds)
}

#[tokio::test]
async fn proton_bridge_connect_and_list() {
    let Some(cfg) = require_proton() else { return; };
    let conn = build_connection(&cfg);
    let folders = conn.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));
}

#[tokio::test]
async fn proton_bridge_connect_and_fetch_one_envelope() {
    let Some(cfg) = require_proton() else { return; };
    let conn = build_connection(&cfg);
    let _ = conn.select("INBOX", true).await.unwrap();
    let uids = conn.search("INBOX", rimap_imap::types::SearchQuery::Raw("ALL".into())).await.unwrap();
    assert!(!uids.is_empty(), "expected at least one message in INBOX");
    let spec = FetchSpec {
        envelope: true,
        bodystructure: false,
        uid: true,
        flags: true,
        size: true,
    };
    let msgs = conn.fetch("INBOX", &uids[..1], spec).await.unwrap();
    assert_eq!(msgs.len(), 1);
}
```

- [ ] **Step 3: Build**

```bash
cargo build -p rimap-imap --tests
cargo test -p rimap-imap --test proton
```

Expected: builds. Without `PROTON_BRIDGE_TEST=1` both tests print "skipping" and pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/proton/ crates/rimap-imap/tests/integration/proton.rs
git commit -m "$(cat <<'EOF'
docs(imap): proton bridge integration harness and gated tests

README documents how to extract Bridge's per-installation fingerprint,
which env vars to set, and the security implications of putting Bridge
credentials in env. Two tests (connect+list and connect+fetch) gated
behind PROTON_BRIDGE_TEST=1; they skip with a clear message in CI and
never reach the network there.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: Document the spawn_blocking audit emission rule

**Goal:** A short workspace-level note explaining the std-mutex-no-await vs tokio-mutex-yes-await split between the two locks.

**Files:**
- Create: `docs/architecture/audit-locking.md`
- Modify: `crates/rimap-imap/src/connection.rs` — add a doc-comment cross-reference

- [ ] **Step 1: Write the architecture note**

Create `docs/architecture/audit-locking.md`:

```markdown
# Audit locking discipline

rusty-imap-mcp uses two distinct mutexes around shared state, with
opposite rules about whether they may be held across an `.await`. Both
rules apply concurrently — getting either wrong is a deadlock or a
data-loss bug.

## The audit writer lock (`std::sync::Mutex`)

`rimap_audit::AuditWriter` wraps its buffered file writer in a
`std::sync::Mutex` (via `Arc<Mutex<Inner>>`). Every call to
`write_record`, `log_auth`, `log_process_start`, or `allocate_seq`
locks this mutex, performs synchronous I/O, and unlocks before
returning.

**Rule: this lock must NEVER be held across an `.await` point.**

Why:

- The lock is `std::sync::Mutex`, not `tokio::sync::Mutex`. Holding a
  std mutex across an `.await` blocks the runtime worker if the future
  is poll-yielded while the lock is held.
- The clippy lint `await_holding_lock = "deny"` enforces this at the
  workspace level for `std::sync::MutexGuard`.
- Sprint 2's design committed to synchronous, fsync-on-critical-record
  audit emission. Making the audit writer async would require either
  spawning blocking tasks per write (the path Sprint 3 takes for
  emission from async code) or rewriting it as fully async (rejected:
  audit logs are append-only and small; tokio's async I/O adds latency
  without throughput benefit).

### How async code calls into the audit writer

From any async function that needs to emit an audit record, use
`tokio::task::spawn_blocking`:

```rust
let audit = self.audit.clone();   // AuditWriter is cheaply cloneable
tokio::task::spawn_blocking(move || audit.log_auth(record))
    .await??;
```

`rimap_imap::Connection::ensure_connected` is the canonical example.
Every `Auth` audit record passes through this pattern.

## The connection session lock (`tokio::sync::Mutex`)

`rimap_imap::Connection` wraps its `Option<async_imap::Session>` in a
`tokio::sync::Mutex`. Every public method on `Connection` acquires the
lock, runs an `.await`-heavy IMAP command sequence, and releases.

**Rule: this lock IS held across `.await` points. It HAS to be —
async-imap commands are themselves `.await`.**

Why this is fine:

- `tokio::sync::Mutex::lock()` is itself `.await`-able and yields
  cooperatively rather than blocking the runtime worker.
- The lock serializes IMAP commands per-connection, which is what we
  want: a single IMAP session can only have one in-flight tagged
  command at a time per RFC 3501.
- We never hold the connection lock and the audit lock simultaneously.
  When a connect attempt finishes (success or failure), we drop the
  session lock guard before calling `spawn_blocking` to log the audit
  record. The two locks are taken in opposite orders by different code
  paths, so even acquiring both would not deadlock — but in practice
  nothing in Sprint 3 holds both at once.

## Quick reference

| Lock | Type | Held across `.await`? | Why |
|---|---|---|---|
| Audit writer (`Inner`) | `std::sync::Mutex` | **NO** | Synchronous I/O; clippy enforces |
| Connection session | `tokio::sync::Mutex` | **YES** | async-imap commands are async |

Future contributors who add new audit emission paths from async code:
follow the `spawn_blocking` pattern in
`crates/rimap-imap/src/connection.rs::Connection::emit_auth`.
```

- [ ] **Step 2: Cross-reference from connection.rs**

The doc comment at the top of `crates/rimap-imap/src/connection.rs` already mentions the rule. Verify it includes a pointer to the new doc:

```bash
grep -n "audit-locking.md" crates/rimap-imap/src/connection.rs
```

If absent, add a line to the existing module-level doc comment:

```rust
//! See `docs/architecture/audit-locking.md` for the workspace-level rule.
```

- [ ] **Step 3: Verify the doc renders cleanly**

```bash
cargo doc -p rimap-imap --no-deps
```

Expected: clean. (No warnings about broken intra-doc links — the markdown file is plain documentation, not a doctest.)

- [ ] **Step 4: Final workspace check**

Run the full local equivalent of CI before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
```

Expected: all green. If `cargo deny` flags a duplicate version that wasn't there at scaffold time, run `cargo update` and re-check. Do NOT add deny.toml skips.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/audit-locking.md crates/rimap-imap/src/connection.rs
git commit -m "$(cat <<'EOF'
docs(audit): architecture note on audit lock vs session lock discipline

Workspace-level explanation of why AuditWriter uses std::sync::Mutex
and Connection uses tokio::sync::Mutex, why one must never be held
across .await and the other has to be, and the spawn_blocking pattern
async code follows when emitting audit records.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Pre-PR sweep

After Task 17, before opening the PR:

- [ ] **Run the security review agents.** Each is opus and reads the diff:
  - `rust-safety-reviewer` — `PinningVerifier`, `Connection` mutex discipline, `tokio::time::timeout` semantics.
  - `email-imap-security-reviewer` — IMAP protocol handling, command injection in folder names, `SEARCH::Raw` boundary.
  - `supply-chain-reviewer` — `async-imap`, `tokio-rustls`, `webpki-roots`, `subtle`.
  - `local-security-reviewer` — Dovecot harness container isolation and file permissions.
  - `mcp-security-reviewer` — sanity sweep that no IMAP state leaks into stdout.
- [ ] **Local Proton Bridge run.** Set the env vars from Task 16's README and run `cargo test -p rimap-imap --test proton`. Both tests must pass against your real Bridge instance. Record the result in the PR description.
- [ ] **Push and open the PR.** PR title: `feat(sprint-3): IMAP connection, TLS pinning, read operations`. PR body links the spec, the plan, and the closed issues (#21, #24, #27).
- [ ] **Watch the 7 required CI checks land green:** rustfmt, clippy, test (stable), test (MSRV 1.88.0), cargo-deny, zizmor self-check, SonarQube.
- [ ] **Do NOT merge from the agent.** Hand off to the human after CI is green.
