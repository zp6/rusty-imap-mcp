# Credential Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three credential-path issues as a single coherent sweep — redact usernames from `ConfigError` Display strings (#76), namespace keyring entries by account id with a migration path (#77), and add a strict-credential fallback mode that disables env-var fallback and audit-logs the credential source (#78).

**Architecture:** All three issues live in `crates/rimap-config/src/credential.rs` and its close neighbours (`error.rs`, `model.rs`, `validate.rs`, `login.rs`). They ripple into `crates/rimap-imap/src/connection.rs` (credential plumbing), `crates/rimap-server/src/main.rs` (SMTP resolution + CLI wiring), `crates/rimap-server/src/cli/mod.rs` (new `migrate-keyring` subcommand), and `crates/rimap-audit/src/record/mod.rs` (new `credential_source` field on `Auth`). The sweep lands in one branch, with #76 first (smallest), then #77 (breaking keyring-key change with migration), then #78 (strict mode + audit enrichment).

**Tech Stack:** Rust (stable), `keyring`, `secrecy`, `thiserror`, `serde`, `toml`, `clap` (for the `migrate-keyring` subcommand), `sha2` (already present — used for `hash_account_tag`).

---

## File Structure

### New files

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `crates/rimap-server/src/cli/migrate_keyring.rs` | `rusty-imap-mcp migrate-keyring` subcommand logic (reads old `<username>@<host>` keys, prompts, rewrites under new `<account-id>/<username>@<host>` key). |

### Modified files

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-config/src/credential.rs` | New `account_key` signature (`AccountId`-aware); `legacy_account_key` helper for back-compat reads; `resolve_credential` returns `(SecretString, CredentialSource)`; honors `FallbackMode`; new `hash_account_tag` helper used by `ConfigError` Display. |
| Modify | `crates/rimap-config/src/error.rs` | `NoCredential` and `Keychain` Display strings replace the `{account}` (username@host) interpolation with the short hash tag. `{host}` becomes a separate field for operator context. |
| Modify | `crates/rimap-config/src/model.rs` | Add `CredentialsConfig { fallback: FallbackMode }` struct and `FallbackMode` enum; add `credentials: CredentialsConfig` to `DefaultsConfig` and `RawAccountConfig`. |
| Modify | `crates/rimap-config/src/validate.rs` | Resolve per-account `FallbackMode` from account override ∪ defaults; add `fallback_mode: FallbackMode` to `ValidatedAccountConfig`. |
| Modify | `crates/rimap-config/src/login.rs` | `run_login` signature takes `&AccountId`; uses new `account_key`. |
| Modify | `crates/rimap-config/src/lib.rs` | Re-export new types (`FallbackMode`, `CredentialSource`, `hash_account_tag`). |
| Modify | `crates/rimap-imap/src/types.rs` or `connection.rs` | Add `account_id: AccountId` + `fallback_mode: FallbackMode` fields to `ConnectionConfig`. |
| Modify | `crates/rimap-imap/src/connection.rs` | Pass `account_id` + `fallback_mode` into `resolve_credential`; propagate `CredentialSource` into `emit_auth`. |
| Create | `crates/rimap-core/src/credential.rs` | New `CredentialSource` enum (shared by config + audit; avoids `rimap-config → rimap-audit` dep). |
| Modify | `crates/rimap-core/src/lib.rs` | Register `credential` module and re-export `CredentialSource`. |
| Modify | `crates/rimap-audit/src/record/mod.rs` | Add `credential_source: Option<rimap_core::CredentialSource>` to `Auth`. |
| Modify | `crates/rimap-server/src/main.rs` | `build_account_connection` plumbs `AccountId` + `fallback_mode`; `build_smtp_client` passes the same into `resolve_credential`; `run` dispatches the new `MigrateKeyring` subcommand. |
| Modify | `crates/rimap-server/src/cli/mod.rs` | Add `Login { account, host, username }` (new required arg), `MigrateKeyring { account }` subcommand. |
| Modify | `docs/multi-account.md` | Replace the two "Recommendation:" paragraphs (§"Keyring Collision", §"Env-var Fallback") with references to the new enforceable config knob; document `migrate-keyring`. |
| Modify | `CHANGELOG.md` | `[Unreleased]` → Breaking: keyring key format changed; migration path. |

---

## Task 1: Short-hash helper + redact `ConfigError::NoCredential` / `Keychain` Display (#76)

**Issue:** #76 — username leaks via error-chain Display strings.

**Files:**
- Modify: `crates/rimap-config/src/credential.rs` (add `hash_account_tag`)
- Modify: `crates/rimap-config/src/error.rs` (redact Display strings; add `host` field)

### Approach

Add `hash_account_tag(username, host) -> String` that returns the first 16 hex chars of SHA-256(`"{username}@{host}"`). Change `ConfigError::NoCredential` to `{ host: String, account_tag: String, reason: String }` and `ConfigError::Keychain` to `{ host: String, account_tag: String, source: Box<dyn Error> }`. Display strings read `no credential for host `{host}` (account_tag `{account_tag}`): {reason}` — no username, no full `username@host` tuple.

- [ ] **Step 1: Write failing test for `hash_account_tag` determinism + length**

Add to `crates/rimap-config/src/credential.rs` in the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn hash_account_tag_is_16_hex_and_deterministic() {
    let a = super::hash_account_tag("alice", "mail.example.com");
    let b = super::hash_account_tag("alice", "mail.example.com");
    assert_eq!(a, b);
    assert_eq!(a.len(), 16);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_account_tag_differs_on_different_inputs() {
    let a = super::hash_account_tag("alice", "mail.example.com");
    let b = super::hash_account_tag("bob", "mail.example.com");
    let c = super::hash_account_tag("alice", "other.example.com");
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-config --lib credential::tests::hash_account_tag`
Expected: FAIL — `hash_account_tag` not yet defined.

- [ ] **Step 3: Add the `sha2` workspace dependency to `rimap-config`**

`sha2` is already a workspace dep (`Cargo.toml:74`) and is used by `rimap-core`, `rimap-audit`, and `rimap-server`. Add it to `rimap-config/Cargo.toml` under `[dependencies]`:

```toml
sha2 = { workspace = true }
```

- [ ] **Step 4: Add `hash_account_tag` to `credential.rs`**

Add near the top of `crates/rimap-config/src/credential.rs` (before `account_key`):

```rust
use sha2::{Digest, Sha256};

/// Return a short (16 hex chars) SHA-256 hash of `"{username}@{host}"` suitable
/// for correlating error/audit log lines without disclosing the username.
///
/// 16 hex chars = 64 bits of prefix — collision probability is negligible at
/// the scale of "accounts a single deployment's error chain correlates".
/// The hash is not a keyring key — `account_key` remains distinct and uses the
/// full unhashed identifiers.
#[must_use]
pub fn hash_account_tag(username: &str, host: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(b"@");
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use core::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p rimap-config --lib credential::tests::hash_account_tag`
Expected: PASS.

- [ ] **Step 6: Write failing test for redacted Display strings**

Add to `crates/rimap-config/src/error.rs` a new `#[cfg(test)] mod tests` block (or append if one exists — there isn't one currently):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_credential_display_omits_username() {
        let err = ConfigError::NoCredential {
            host: "mail.example.com".to_string(),
            account_tag: "deadbeefcafef00d".to_string(),
            reason: "nothing in keyring".to_string(),
        };
        let display = format!("{err}");
        let full = format!("{err:#}");
        assert!(!display.contains("alice"), "display leaked username: {display}");
        assert!(!full.contains("alice"), "full chain leaked username: {full}");
        assert!(display.contains("mail.example.com"));
        assert!(display.contains("deadbeefcafef00d"));
    }

    #[test]
    fn keychain_display_omits_username() {
        let err = ConfigError::Keychain {
            host: "mail.example.com".to_string(),
            account_tag: "deadbeefcafef00d".to_string(),
            source: "underlying kernel error for alice@something".into(),
        };
        let display = format!("{err}");
        assert!(!display.contains("alice"), "display leaked username: {display}");
        assert!(display.contains("mail.example.com"));
        assert!(display.contains("deadbeefcafef00d"));
    }
}
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `cargo test -p rimap-config --lib error::tests`
Expected: FAIL — variants still have `account` field, not `host`/`account_tag`.

- [ ] **Step 8: Redact both variants in `error.rs`**

Replace the `NoCredential` variant block at `crates/rimap-config/src/error.rs:90-97`:

```rust
    /// No credential could be found in keychain or environment.
    ///
    /// Display never includes the username. `host` is the IMAP/SMTP host
    /// (public DNS in practice). `account_tag` is `hash_account_tag(username,
    /// host)` — operators can correlate logs without seeing the username.
    #[error("no credential for host `{host}` (account_tag {account_tag}): {reason}")]
    NoCredential {
        /// IMAP/SMTP host (public DNS, safe to log).
        host: String,
        /// Short hash of `username@host` for log correlation.
        account_tag: String,
        /// What we tried and what the user should do next.
        reason: String,
    },
```

Replace the `Keychain` variant block at `crates/rimap-config/src/error.rs:98-106`:

```rust
    /// Keychain access error (not "not found" — that becomes `NoCredential`).
    ///
    /// Display never includes the username. See `NoCredential` for the rules
    /// on `host` and `account_tag`.
    #[error("keychain error for host `{host}` (account_tag {account_tag}): {source}")]
    Keychain {
        /// IMAP/SMTP host (public DNS, safe to log).
        host: String,
        /// Short hash of `username@host` for log correlation.
        account_tag: String,
        /// Underlying keyring error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
```

- [ ] **Step 9: Update the three `ConfigError::NoCredential { ... }` / `Keychain { ... }` constructors in `credential.rs` and `login.rs`**

In `crates/rimap-config/src/credential.rs`, replace the two construction sites (currently at lines 68-74, 86-88, 93-95, 102-104, 108-110).

At `crates/rimap-config/src/credential.rs:68-75`:

```rust
    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` and \
             `{PASSWORD_ENV_VAR}` is unset or empty; run `rusty-imap-mcp login` \
             or set the environment variable"
        ),
    })
```

At `crates/rimap-config/src/credential.rs:85-97` and `:100-112` (inside `KeyringStore::get_password` and `KeyringStore::set_password`), replace both `ConfigError::Keychain { account: ..., source: ... }` constructions. These functions currently receive `account: &str` (which is `username@host`). Extract the host + hash: the helper needs to accept the raw `account` string and split it at `@`:

Add near the top of `credential.rs`:

```rust
/// Split a `username@host` account key back into `(host, account_tag)` for
/// building error records. If the input has no `@` (malformed), treat the
/// whole string as host and use an empty username for hashing.
fn split_account_for_error(account: &str) -> (String, String) {
    let (username, host) = account.split_once('@').unwrap_or(("", account));
    (host.to_string(), hash_account_tag(username, host))
}
```

Then in `KeyringStore::get_password`, replace both `ConfigError::Keychain { ... }` arms:

```rust
        let entry =
            keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
                let (host, account_tag) = split_account_for_error(account);
                ConfigError::Keychain {
                    host,
                    account_tag,
                    source: Box::new(e),
                }
            })?;
        match entry.get_password() {
            Ok(p) => Ok(Some(SecretString::from(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                let (host, account_tag) = split_account_for_error(account);
                Err(ConfigError::Keychain {
                    host,
                    account_tag,
                    source: Box::new(e),
                })
            }
        }
```

Apply the same pattern to `KeyringStore::set_password`.

In `crates/rimap-config/src/login.rs`, replace the two `ConfigError::NoCredential { ... }` constructions (lines 28-31 and 33-36):

```rust
    let password = prompt(&prompt_text).map_err(|e| ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!("interactive prompt failed: {e}"),
    })?;
    if password.is_empty() {
        return Err(ConfigError::NoCredential {
            host: host.to_string(),
            account_tag: hash_account_tag(username, host),
            reason: "empty password not accepted".to_string(),
        });
    }
```

Update the `use` in login.rs:8 to import `hash_account_tag`:

```rust
use crate::credential::{CredentialStore, account_key, hash_account_tag};
```

- [ ] **Step 10: Update the mock-store test at `credential.rs:154-160`**

The existing test constructs `ConfigError::Keychain { account: ..., source: ... }` — update to the new shape:

```rust
    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
            if self.fail_on_get {
                let (host, account_tag) = super::split_account_for_error(account);
                return Err(ConfigError::Keychain {
                    host,
                    account_tag,
                    source: "simulated failure".into(),
                });
            }
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(SecretString::from))
        }
        ...
```

Also update the existing `missing_everywhere_returns_no_credential` test at lines 206-219 to match the new variant shape. The existing assertions on `account == "alice@host"` become assertions on `host` / `account_tag`:

```rust
    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(&store, "alice", "host").unwrap_err();
            match err {
                ConfigError::NoCredential { host, account_tag, reason } => {
                    assert_eq!(host, "host");
                    assert_eq!(account_tag.len(), 16);
                    assert!(reason.contains("rusty-imap-mcp login"));
                    assert!(reason.contains("RUSTY_IMAP_MCP_PASSWORD"));
                }
                other => panic!("wrong variant: {other:?}"),
            }
        });
    }
```

- [ ] **Step 11: Run the full `rimap-config` test suite**

Run: `cargo test -p rimap-config`
Expected: PASS — both `error::tests` and `credential::tests` cover the new shape.

- [ ] **Step 12: Run clippy to catch any field-rename fallout**

Run: `cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 13: Commit**

```bash
git add crates/rimap-config/Cargo.toml crates/rimap-config/src/credential.rs crates/rimap-config/src/error.rs crates/rimap-config/src/login.rs
git commit -m "config: redact username from ConfigError Display (#76)

NoCredential and Keychain now carry { host, account_tag, ... } instead
of { account: \"username@host\", ... }. Display shows the host (public
DNS) and a 16-hex-char SHA-256 tag derived from username@host — enough
for log correlation, insufficient for username enumeration."
```

---

## Task 2: Add `AccountId` to `ConnectionConfig` and `run_login` signature (#77 prep)

**Issue:** #77 — keyring key collisions in multi-account.

This step plumbs `AccountId` to every `account_key` / `resolve_credential` / `run_login` call site without yet changing the key format. Splitting it out keeps the #77 diff focused on the key change itself.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs` (ConnectionConfig + `resolve_credential` call)
- Modify: `crates/rimap-imap/src/types.rs` (if `ConnectionConfig` lives there; else stays in `connection.rs`)
- Modify: `crates/rimap-server/src/main.rs` (`build_account_connection`, `build_smtp_client`, login subcommand)
- Modify: `crates/rimap-server/src/cli/mod.rs` (`Login { account, host, username }` new arg)
- Modify: `crates/rimap-config/src/login.rs` (`run_login` signature)
- Modify: `crates/rimap-config/src/credential.rs` (`resolve_credential` and `account_key` signatures — still produce the old key format this task, new format in task 3)

### Approach

Change the public signatures to accept `&AccountId`, but have `account_key` continue returning the legacy `"{username}@{host}"` form for this task. Task 3 swaps in the new format.

- [ ] **Step 1: Write failing test for `account_key(&AccountId, username, host)` signature shape**

In `crates/rimap-config/src/credential.rs`, replace the existing `account_key_is_username_at_host` test with:

```rust
    #[test]
    fn account_key_signature_accepts_account_id() {
        use rimap_core::account::AccountId;
        let id = AccountId::default_account();
        // Old format still returned in this task; task 3 changes to
        // "<id>/<user>@<host>".
        let key = account_key(&id, "alice", "mail.example.test");
        assert_eq!(key, "alice@mail.example.test");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-config --lib credential::tests::account_key_signature_accepts_account_id`
Expected: FAIL — `account_key` takes `(&str, &str)`, not `(&AccountId, &str, &str)`.

- [ ] **Step 3: Update `account_key` signature**

At `crates/rimap-config/src/credential.rs:36-40`:

```rust
use rimap_core::account::AccountId;

/// Build the keyring account key for `(account_id, username, host)`.
///
/// Returns the **legacy** `<username>@<host>` form for compatibility with
/// stored credentials. Task 3 introduces the new `<account-id>/<username>@<host>`
/// form and a back-compat read path.
#[must_use]
pub fn account_key(_account_id: &AccountId, username: &str, host: &str) -> String {
    format!("{username}@{host}")
}
```

Cargo.toml for `rimap-config` already depends on `rimap-core`, so no new dep.

- [ ] **Step 4: Update `resolve_credential` signature**

At `crates/rimap-config/src/credential.rs:52-76`:

```rust
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
) -> Result<SecretString, ConfigError> {
    let account = account_key(account_id, username, host);
    if let Some(p) = store.get_password(&account)?
        && !p.expose_secret().is_empty()
    {
        return Ok(p);
    }
    if let Ok(env) = std::env::var(PASSWORD_ENV_VAR)
        && !env.is_empty()
    {
        return Ok(SecretString::from(env));
    }
    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` and \
             `{PASSWORD_ENV_VAR}` is unset or empty; run `rusty-imap-mcp login` \
             or set the environment variable"
        ),
    })
}
```

Update all five existing `resolve_credential(&store, "alice", "host")` test call sites in `credential.rs` to pass a default AccountId:

```rust
    use rimap_core::account::AccountId;
    let default_id = AccountId::default_account();
    let got = resolve_credential(&store, &default_id, "alice", "host").unwrap();
```

- [ ] **Step 5: Update `run_login` signature**

At `crates/rimap-config/src/login.rs:20-40`:

```rust
pub fn run_login<S: CredentialStore>(
    store: &S,
    account_id: &rimap_core::account::AccountId,
    username: &str,
    host: &str,
    prompt: impl FnOnce(&str) -> std::io::Result<String>,
) -> Result<(), ConfigError> {
    let account = account_key(account_id, username, host);
    let prompt_text = format!("Password for {account}: ");
    let password = prompt(&prompt_text).map_err(|e| ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!("interactive prompt failed: {e}"),
    })?;
    if password.is_empty() {
        return Err(ConfigError::NoCredential {
            host: host.to_string(),
            account_tag: hash_account_tag(username, host),
            reason: "empty password not accepted".to_string(),
        });
    }
    store.set_password(&account, &password)?;
    Ok(())
}
```

Update the three `run_login` test call sites (`login.rs:88-114`) to include a default AccountId argument.

- [ ] **Step 6: Add `account_id: AccountId` to `ConnectionConfig`**

Find `ConnectionConfig`'s definition. It's currently used at `main.rs:243-254`. Locate the struct (likely in `crates/rimap-imap/src/types.rs` or `crates/rimap-imap/src/connection.rs`):

```bash
grep -n "pub struct ConnectionConfig" crates/rimap-imap/src/
```

Add the field:

```rust
pub struct ConnectionConfig {
    /// Optional human-visible account label for audit records (None = default
    /// account elision; see Sprint 3 design §3).
    pub account: Option<String>,
    /// Account id used for keyring lookups. Always set — the default account
    /// uses `AccountId::default_account()`.
    pub account_id: rimap_core::account::AccountId,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub pinned_fingerprint: Option<rimap_core::tls::TlsFingerprint>,
    pub connect_timeout: std::time::Duration,
    pub command_timeout: std::time::Duration,
    pub max_fetch_body_bytes: u64,
    pub max_append_bytes: u64,
}
```

- [ ] **Step 7: Wire `account_id` into the IMAP `resolve_credential` call**

At `crates/rimap-imap/src/connection.rs:325`:

```rust
        let password = resolve_credential(
            &*self.inner.credentials,
            &cfg.account_id,
            &cfg.username,
            &cfg.host,
        )
        .map_err(|e| ImapError::Auth {
            reason: AuthFailure::CredentialUnavailable(e.to_string()),
        })?;
```

- [ ] **Step 8: Wire `account_id` into `build_account_connection` and `build_smtp_client`**

At `crates/rimap-server/src/main.rs:234-254`:

```rust
fn build_account_connection(
    id: &rimap_core::account::AccountId,
    acfg: &ValidatedAccountConfig,
) -> ConnectionConfig {
    let account = if id.as_str() == rimap_core::account::DEFAULT_ACCOUNT_NAME {
        None
    } else {
        Some(id.as_str().to_string())
    };
    ConnectionConfig {
        account,
        account_id: id.clone(),
        host: acfg.imap.host.clone(),
        port: acfg.imap.port,
        username: acfg.imap.username.clone(),
        pinned_fingerprint: acfg.tls_fingerprint,
        connect_timeout: Duration::from_secs(u64::from(acfg.imap.connect_timeout_seconds)),
        command_timeout: Duration::from_secs(u64::from(acfg.imap.command_timeout_seconds)),
        max_fetch_body_bytes: acfg.limits.max_fetch_body_bytes,
        max_append_bytes: acfg.limits.max_append_bytes,
    }
}
```

At `crates/rimap-server/src/main.rs:203`:

```rust
    let smtp_password = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
    )
    .with_context(|| {
        format!("resolving SMTP credential for account {}", acfg.id.as_str())
    })?;
```

- [ ] **Step 9: Add `account` arg to `Login` CLI subcommand**

At `crates/rimap-server/src/cli/mod.rs`, update the `Login` variant:

```rust
    /// Interactively store IMAP credentials in the OS keychain.
    Login {
        /// Account name from config. Defaults to `default`, matching the
        /// synthetic account used for legacy single-account configs.
        #[arg(long, default_value = "default")]
        account: String,
        /// IMAP host (e.g. `127.0.0.1` for Proton Bridge).
        #[arg(long)]
        host: String,
        /// IMAP username (e.g. `alice@example.com`).
        #[arg(long)]
        username: String,
    },
```

At `crates/rimap-server/src/main.rs:44-51`:

```rust
    if let Some(Command::Login { account, host, username }) = &cli.command {
        let store = KeyringStore;
        let account_id = rimap_core::account::AccountId::new(account)
            .with_context(|| format!("invalid account name `{account}`"))?;
        run_login(&store, &account_id, username, host, tty_prompt)
            .with_context(|| format!("storing credential for {username}@{host}"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "credential stored for {username}@{host}")?;
        return Ok(());
    }
```

Update any existing CLI parsing tests (`cli/mod.rs:89+`) to include `--account`.

- [ ] **Step 10: Run full workspace tests + clippy**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS on both. Plumbing-only change; behavior is unchanged.

- [ ] **Step 11: Commit**

```bash
git add crates/rimap-config/src/credential.rs crates/rimap-config/src/login.rs \
        crates/rimap-imap/src/connection.rs crates/rimap-imap/src/types.rs \
        crates/rimap-server/src/main.rs crates/rimap-server/src/cli/mod.rs
git commit -m "config: thread AccountId through credential resolution (#77 prep)

account_key, resolve_credential, and run_login now accept &AccountId.
Keyring key format still the legacy <username>@<host> — task 3 changes
the key and adds the back-compat fallback."
```

---

## Task 3: Switch keyring key to `<account-id>/<username>@<host>` with back-compat read (#77)

**Issue:** #77 — keyring key collisions in multi-account.

**Files:**
- Modify: `crates/rimap-config/src/credential.rs`

### Approach

`account_key` returns the new `<account-id>/<username>@<host>` form. A new `legacy_account_key` returns the old `<username>@<host>` form. `resolve_credential` consults the new key first; on miss, falls back to the legacy key and emits `tracing::warn!` recommending migration.

- [ ] **Step 1: Write failing test for the new key format**

Replace the `account_key_signature_accepts_account_id` test in `credential.rs`:

```rust
    #[test]
    fn account_key_uses_namespaced_format() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let key = account_key(&id, "alice", "mail.example.test");
        assert_eq!(key, "work/alice@mail.example.test");
    }

    #[test]
    fn legacy_account_key_returns_bare_form() {
        let key = legacy_account_key("alice", "mail.example.test");
        assert_eq!(key, "alice@mail.example.test");
    }

    #[test]
    fn resolve_credential_reads_new_key_format_first() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[
            ("work/alice@host", "from_new_key"),
            ("alice@host", "from_legacy_key"),
        ]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let got = resolve_credential(&store, &id, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_new_key");
        });
    }

    #[test]
    fn resolve_credential_falls_back_to_legacy_key() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "from_legacy_key")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let got = resolve_credential(&store, &id, "alice", "host").unwrap();
            assert_eq!(got.expose_secret(), "from_legacy_key");
        });
    }
```

- [ ] **Step 2: Run tests — expect failure**

Run: `cargo test -p rimap-config --lib credential::tests`
Expected: the four new tests fail.

- [ ] **Step 3: Change `account_key` and add `legacy_account_key`**

```rust
/// Build the keyring account key for `(account_id, username, host)`.
///
/// New format: `<account-id>/<username>@<host>`. Added in #77 to prevent
/// collisions when two accounts share a `<username>@<host>` tuple. Use
/// [`legacy_account_key`] only for the read-fallback path during migration.
#[must_use]
pub fn account_key(account_id: &AccountId, username: &str, host: &str) -> String {
    format!("{}/{username}@{host}", account_id.as_str())
}

/// Legacy keyring key format (`<username>@<host>`) — retained for the
/// back-compat read path in [`resolve_credential`]. New code MUST call
/// [`account_key`].
#[must_use]
pub fn legacy_account_key(username: &str, host: &str) -> String {
    format!("{username}@{host}")
}
```

- [ ] **Step 4: Add fallback read to `resolve_credential`**

Replace the body of `resolve_credential`:

```rust
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
) -> Result<SecretString, ConfigError> {
    let new_key = account_key(account_id, username, host);
    if let Some(p) = store.get_password(&new_key)?
        && !p.expose_secret().is_empty()
    {
        return Ok(p);
    }

    // Back-compat: before #77 the keyring key was <username>@<host>, with no
    // account-id prefix. If the new key lookup missed, try the legacy key and
    // warn the operator to run `rusty-imap-mcp migrate-keyring`.
    let legacy_key = legacy_account_key(username, host);
    if let Some(p) = store.get_password(&legacy_key)?
        && !p.expose_secret().is_empty()
    {
        tracing::warn!(
            account_id = %account_id.as_str(),
            host = %host,
            "credential resolved via legacy keyring key format; \
             run `rusty-imap-mcp migrate-keyring --account {}` to migrate",
            account_id.as_str(),
        );
        return Ok(p);
    }

    if let Ok(env) = std::env::var(PASSWORD_ENV_VAR)
        && !env.is_empty()
    {
        return Ok(SecretString::from(env));
    }

    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` (under key \
             `{new_key}` or legacy `{legacy_key}`) and `{PASSWORD_ENV_VAR}` \
             is unset or empty; run `rusty-imap-mcp login --account \
             {}` or set the environment variable",
            account_id.as_str(),
        ),
    })
}
```

- [ ] **Step 5: Run the four new tests — expect pass**

Run: `cargo test -p rimap-config --lib credential::tests`
Expected: PASS, including the existing 6 tests that still exercise the new behaviour via the default AccountId.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-config/src/credential.rs
git commit -m "config: namespace keyring keys by account id (#77)

account_key now returns <account-id>/<username>@<host>. legacy_account_key
preserves the old form for the read-fallback path — resolve_credential
tries the new key, then the legacy key (with a tracing warning recommending
migration), then the env var. Existing single-account deployments keep
working; new multi-account deployments no longer collide."
```

---

## Task 4: `migrate-keyring` CLI subcommand (#77)

**Issue:** #77 — migration path for the breaking keyring-key change.

**Files:**
- Create: `crates/rimap-server/src/cli/migrate_keyring.rs`
- Modify: `crates/rimap-server/src/cli/mod.rs` (new subcommand variant)
- Modify: `crates/rimap-server/src/main.rs` (dispatch)

### Approach

`rusty-imap-mcp migrate-keyring --account <id> --host <h> --username <u>` reads the legacy key `<username>@<host>`, writes it under the new key `<id>/<username>@<host>`, and deletes the legacy entry. The operator runs it once per account after upgrading.

A "migrate all accounts from a config file" flow is out of scope (keeps the CLI surface small; operators with many accounts can script the per-account call).

- [ ] **Step 1: Write failing test for `migrate_one`**

Create `crates/rimap-server/src/cli/migrate_keyring.rs`:

```rust
//! `rusty-imap-mcp migrate-keyring` subcommand.
//!
//! Migrates a single credential from the legacy key `<username>@<host>` to
//! the new `<account-id>/<username>@<host>` key format (see #77).

use rimap_config::credential::{
    CredentialStore, account_key, hash_account_tag, legacy_account_key,
};
use rimap_config::error::ConfigError;
use rimap_core::account::AccountId;

/// Migrate one credential. Returns `Ok(true)` if migration happened,
/// `Ok(false)` if the legacy key was absent (nothing to migrate).
///
/// # Errors
/// `ConfigError::NoCredential` or `ConfigError::Keychain` on I/O errors.
pub fn migrate_one<S: CredentialStore>(
    store: &S,
    account_id: &AccountId,
    username: &str,
    host: &str,
) -> Result<bool, ConfigError> {
    let legacy = legacy_account_key(username, host);
    let Some(password) = store.get_password(&legacy)? else {
        return Ok(false);
    };
    let new_key = account_key(account_id, username, host);
    use secrecy::ExposeSecret;
    store.set_password(&new_key, password.expose_secret())?;
    // Overwrite the legacy entry with an empty value so subsequent
    // `resolve_credential` calls no longer find it. CredentialStore has no
    // delete method; an empty string is treated as "no credential" by the
    // `!p.expose_secret().is_empty()` guard in resolve_credential.
    store.set_password(&legacy, "")?;
    tracing::info!(
        account_id = %account_id.as_str(),
        host = %host,
        account_tag = %hash_account_tag(username, host),
        "migrated keyring entry from legacy key",
    );
    Ok(true)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use rimap_config::credential::{CredentialStore, account_key, legacy_account_key};
    use rimap_config::error::ConfigError;
    use rimap_core::account::AccountId;
    use secrecy::{ExposeSecret, SecretString};

    use super::migrate_one;

    #[derive(Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
    }

    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(SecretString::from))
        }
        fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_string());
            Ok(())
        }
    }

    #[test]
    fn migrate_copies_legacy_to_new_and_empties_legacy() {
        let store = MockStore::default();
        let id = AccountId::new("work").unwrap();
        store
            .set_password(&legacy_account_key("alice", "host"), "hunter2")
            .unwrap();

        let migrated = migrate_one(&store, &id, "alice", "host").unwrap();
        assert!(migrated);

        let new = store
            .get_password(&account_key(&id, "alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(new.expose_secret(), "hunter2");

        let legacy = store
            .get_password(&legacy_account_key("alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(legacy.expose_secret(), "", "legacy entry should be empty");
    }

    #[test]
    fn migrate_returns_false_when_no_legacy_entry() {
        let store = MockStore::default();
        let id = AccountId::new("work").unwrap();
        let migrated = migrate_one(&store, &id, "alice", "host").unwrap();
        assert!(!migrated);
    }
}
```

- [ ] **Step 2: Run test — expect compilation failure on the module not being declared**

Run: `cargo test -p rimap-server --lib cli::migrate_keyring::tests`
Expected: FAIL — module not registered yet.

- [ ] **Step 3: Register the module and subcommand in `cli/mod.rs`**

At the top of `crates/rimap-server/src/cli/mod.rs`:

```rust
pub(crate) mod audit_merge;
pub(crate) mod dry_run;
pub(crate) mod migrate_keyring;
```

Add a `MigrateKeyring` variant to `Command`:

```rust
    /// Migrate a credential from the legacy keyring key format
    /// (`<username>@<host>`) to the new namespaced format
    /// (`<account-id>/<username>@<host>`). Run once per account after
    /// upgrading across #77.
    MigrateKeyring {
        /// Account name from config.
        #[arg(long)]
        account: String,
        /// IMAP host.
        #[arg(long)]
        host: String,
        /// IMAP username.
        #[arg(long)]
        username: String,
    },
```

- [ ] **Step 4: Dispatch the new subcommand in `main.rs::run`**

Add below the existing `Login` dispatch (around `main.rs:51`):

```rust
    if let Some(Command::MigrateKeyring { account, host, username }) = &cli.command {
        let store = KeyringStore;
        let account_id = rimap_core::account::AccountId::new(account)
            .with_context(|| format!("invalid account name `{account}`"))?;
        let migrated = cli::migrate_keyring::migrate_one(&store, &account_id, username, host)
            .with_context(|| {
                format!("migrating credential for account `{account}`, host `{host}`")
            })?;
        let mut stdout = std::io::stdout().lock();
        if migrated {
            writeln!(stdout, "migrated credential for account `{account}`")?;
        } else {
            writeln!(
                stdout,
                "no legacy credential found for account `{account}` (host `{host}`); nothing to migrate"
            )?;
        }
        return Ok(());
    }
```

- [ ] **Step 5: Run the tests + clippy**

Run: `cargo test -p rimap-server --lib cli::migrate_keyring`
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/cli/migrate_keyring.rs crates/rimap-server/src/cli/mod.rs crates/rimap-server/src/main.rs
git commit -m "cli: add migrate-keyring subcommand (#77)

rusty-imap-mcp migrate-keyring --account <id> --host <h> --username <u>
reads the legacy keyring key <username>@<host> and rewrites it under the
new <account-id>/<username>@<host> key, emptying the legacy entry so
resolve_credential stops falling back to it."
```

---

## Task 5: `FallbackMode` + `CredentialsConfig` model types (#78)

**Issue:** #78 — strict credential mode.

**Files:**
- Modify: `crates/rimap-config/src/model.rs`
- Modify: `crates/rimap-config/src/lib.rs` (re-export `FallbackMode`)

### Approach

Add `FallbackMode { KeyringOnly, KeyringThenEnv }` enum and a `CredentialsConfig` struct wrapping it. Wire it into `DefaultsConfig` (so single-account configs work via the legacy-mapping path) and `RawAccountConfig` (per-account override).

- [ ] **Step 1: Write failing test for enum deserialization**

Add to `crates/rimap-config/src/model.rs` in the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn fallback_mode_defaults_to_keyring_then_env() {
        assert_eq!(FallbackMode::default(), FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn fallback_mode_round_trips_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W {
            v: FallbackMode,
        }
        for v in [FallbackMode::KeyringOnly, FallbackMode::KeyringThenEnv] {
            let s = toml::to_string(&W { v }).unwrap();
            let back: W = toml::from_str(&s).unwrap();
            assert_eq!(back.v, v);
        }
    }

    #[test]
    fn credentials_config_deserializes_with_fallback_key() {
        let toml_str = r#"
fallback = "keyring-only"
"#;
        let cfg: CredentialsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.fallback, FallbackMode::KeyringOnly);
    }
```

- [ ] **Step 2: Run test — expect compilation failure**

Run: `cargo test -p rimap-config --lib model::tests::fallback_mode`
Expected: FAIL — types undefined.

- [ ] **Step 3: Add `FallbackMode` and `CredentialsConfig` to `model.rs`**

Append in the appropriate section (near `SmtpEncryption`):

```rust
/// How credential resolution falls back when the keyring has no entry.
///
/// - `KeyringThenEnv` (default) — try the keyring, then
///   `RUSTY_IMAP_MCP_PASSWORD`, then fail. Suitable for CI/test and
///   single-account deployments.
/// - `KeyringOnly` — keyring only; a miss returns `NoCredential` without
///   consulting the env var. Recommended for multi-account deployments
///   where a shared env-var fallback would silently send one account's
///   password to another account's server (see #78).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackMode {
    /// Keyring, then env var, then fail.
    #[default]
    KeyringThenEnv,
    /// Keyring only; no env-var fallback.
    KeyringOnly,
}

/// `[defaults.credentials]` / `[[accounts.credentials]]` block.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    /// Fallback policy.
    #[serde(default)]
    pub fallback: FallbackMode,
}
```

Add `credentials: CredentialsConfig` to `DefaultsConfig`:

```rust
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Default credential policy inherited by accounts that omit it.
    #[serde(default)]
    pub credentials: CredentialsConfig,
}
```

Add `credentials: Option<CredentialsConfig>` to `RawAccountConfig`:

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAccountConfig {
    pub name: String,
    pub imap: ImapConfig,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default)]
    pub security: Option<SecurityConfig>,
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    /// Per-account credential policy; `None` inherits from `[defaults.credentials]`.
    #[serde(default)]
    pub credentials: Option<CredentialsConfig>,
}
```

In `crates/rimap-config/src/lib.rs`, add to the re-exports:

```rust
pub use crate::model::{CredentialsConfig, FallbackMode};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-config --lib model::tests`
Expected: PASS including the three new tests.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-config/src/model.rs crates/rimap-config/src/lib.rs
git commit -m "config: add FallbackMode + CredentialsConfig model (#78)

FallbackMode { KeyringThenEnv, KeyringOnly } controls credential
resolution. Reached via [defaults.credentials] for all accounts and
per-account via [[accounts.credentials]]. Default is KeyringThenEnv
(back-compat). No behavior change yet — task 6 wires it in."
```

---

## Task 6: Resolve `fallback_mode` into `ValidatedAccountConfig` (#78)

**Files:**
- Modify: `crates/rimap-config/src/validate.rs`

### Approach

`ValidatedAccountConfig.fallback_mode: FallbackMode`. Per-account override wins; else `defaults.credentials.fallback`. For the legacy single-account path (`validate_legacy_as_multi`), we use the default `FallbackMode::KeyringThenEnv` (no config surface to override).

- [ ] **Step 1: Write failing test**

Add to `crates/rimap-config/src/validate.rs` tests:

```rust
    #[test]
    fn multi_fallback_defaults_to_keyring_then_env() {
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![raw_account("work")]);
        let v = validate_multi(cfg).unwrap();
        let acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn multi_account_inherits_defaults_fallback() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_multi_config(dir.path(), vec![raw_account("work")]);
        cfg.defaults.credentials.fallback = FallbackMode::KeyringOnly;
        let v = validate_multi(cfg).unwrap();
        let acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringOnly);
    }

    #[test]
    fn multi_account_override_beats_defaults_fallback() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.credentials = Some(CredentialsConfig {
            fallback: FallbackMode::KeyringOnly,
        });
        let mut cfg = base_multi_config(dir.path(), vec![acct]);
        cfg.defaults.credentials.fallback = FallbackMode::KeyringThenEnv;
        let v = validate_multi(cfg).unwrap();
        let validated = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(validated.fallback_mode, FallbackMode::KeyringOnly);
    }

    #[test]
    fn legacy_fallback_defaults_to_keyring_then_env() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate_legacy_as_multi(cfg).unwrap();
        let id = AccountId::default_account();
        assert_eq!(v.accounts[&id].fallback_mode, FallbackMode::KeyringThenEnv);
    }
```

Import `FallbackMode` / `CredentialsConfig` at the top of the tests module.

- [ ] **Step 2: Run tests — expect failure**

Run: `cargo test -p rimap-config --lib validate::tests::multi_fallback`
Expected: FAIL — `ValidatedAccountConfig.fallback_mode` doesn't exist.

- [ ] **Step 3: Add `fallback_mode` to `ValidatedAccountConfig`**

At `crates/rimap-config/src/validate.rs:27-42`:

```rust
#[derive(Debug, Clone)]
pub struct ValidatedAccountConfig {
    pub id: AccountId,
    pub imap: ImapConfig,
    pub smtp: Option<SmtpConfig>,
    pub security: SecurityConfig,
    pub limits: LimitsConfig,
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Credential fallback policy (see #78).
    pub fallback_mode: crate::model::FallbackMode,
}
```

Update `validate_account`:

```rust
fn validate_account(
    id: AccountId,
    imap: ImapConfig,
    smtp: Option<SmtpConfig>,
    security: SecurityConfig,
    limits: LimitsConfig,
    fallback_mode: crate::model::FallbackMode,
) -> Result<ValidatedAccountConfig, ConfigError> {
    ...
    Ok(ValidatedAccountConfig {
        id,
        imap,
        smtp,
        security,
        limits,
        tool_overrides,
        tls_fingerprint,
        fallback_mode,
    })
}
```

Update `validate_multi` (`:59-88`):

```rust
    for raw in config.accounts {
        let id = AccountId::new(&raw.name)?;
        if accounts.contains_key(&id) {
            return Err(ConfigError::DuplicateAccountName { name: raw.name });
        }

        let security = raw
            .security
            .unwrap_or_else(|| config.defaults.security.clone());
        let limits = raw.limits.unwrap_or_else(|| config.defaults.limits.clone());
        let fallback_mode = raw
            .credentials
            .map(|c| c.fallback)
            .unwrap_or(config.defaults.credentials.fallback);

        let validated =
            validate_account(id.clone(), raw.imap, raw.smtp, security, limits, fallback_mode)?;
        accounts.insert(id, validated);
    }
```

Update `validate_legacy_as_multi` (`:97-117`):

```rust
pub fn validate_legacy_as_multi(config: Config) -> Result<ValidatedMultiConfig, ConfigError> {
    let id = AccountId::default_account();
    let account = validate_account(
        id.clone(),
        config.imap,
        config.smtp,
        config.security,
        config.limits,
        crate::model::FallbackMode::default(),
    )?;
    ...
}
```

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p rimap-config --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-config/src/validate.rs
git commit -m "config: resolve fallback_mode into ValidatedAccountConfig (#78)

ValidatedAccountConfig carries fallback_mode, resolved as:
per-account credentials.fallback > defaults.credentials.fallback >
KeyringThenEnv default. Legacy single-account path uses the default."
```

---

## Task 7: Gate env-var fallback on `FallbackMode` + emit `CredentialSource` (#78)

**Files:**
- Modify: `crates/rimap-config/src/credential.rs` (new return type + `FallbackMode` arg)
- Modify: `crates/rimap-audit/src/record/mod.rs` (new `CredentialSource` type; new `Auth.credential_source` field)
- Modify: `crates/rimap-imap/src/connection.rs` (pass `fallback_mode`; propagate `credential_source` into `Auth`)
- Modify: `crates/rimap-server/src/main.rs` (SMTP call site)

### Approach

`resolve_credential` becomes:

```rust
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
    fallback_mode: FallbackMode,
) -> Result<(SecretString, CredentialSource), ConfigError>
```

`CredentialSource` lives in `rimap-core` (new `credential.rs` module) so both `rimap-config` (returns it from `resolve_credential`) and `rimap-audit` (stores it in `Auth`) depend on it without creating a cycle. Variants: `Keyring`, `LegacyKeyring`, `EnvVar`. `Auth` gains `credential_source: Option<CredentialSource>` (Option to keep JSON back-compat readable by existing `audit merge` tooling — missing field decodes to None).

- [ ] **Step 1: Add `CredentialSource` to `rimap-core`**

`CredentialSource` is shared between `rimap-config` (returns it) and `rimap-audit` (records it). Placing it in `rimap-audit` would invert the natural dep direction (config generally doesn't depend on audit). Placing it in `rimap-core` — which already hosts `AccountId`, `ErrorCode`, `Posture`, `ToolName`, `TlsFingerprint` — matches the existing layering.

Create `crates/rimap-core/src/credential.rs`:

```rust
//! Credential provenance types. Referenced by `rimap-config` (returned from
//! `resolve_credential`) and by `rimap-audit::record::Auth` (recorded per
//! auth attempt). Kept here so neither crate has to depend on the other.

use serde::{Deserialize, Serialize};

/// Where a successfully resolved credential came from. Recorded in `Auth`
/// records so post-incident analysis can detect silent fallbacks (e.g. an
/// operator's keyring entry went missing and the process started using the
/// global env-var fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Resolved from the new namespaced keyring key.
    Keyring,
    /// Resolved from the legacy unnamespaced keyring key — indicates the
    /// operator still needs to run `migrate-keyring`.
    LegacyKeyring,
    /// Resolved from `RUSTY_IMAP_MCP_PASSWORD`.
    EnvVar,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::CredentialSource;

    #[test]
    fn credential_source_serializes_as_snake_case() {
        let j = serde_json::to_string(&CredentialSource::LegacyKeyring).unwrap();
        assert_eq!(j, "\"legacy_keyring\"");
        let back: CredentialSource = serde_json::from_str(&j).unwrap();
        assert_eq!(back, CredentialSource::LegacyKeyring);
    }
}
```

Register the module in `crates/rimap-core/src/lib.rs`:

```rust
pub mod credential;
pub use credential::CredentialSource;
```

Verify `serde_json` is available in `rimap-core`'s dev-dependencies for the test. Check `crates/rimap-core/Cargo.toml`; if `serde_json` is missing under `[dev-dependencies]`, add `serde_json = { workspace = true }`.

Now add `credential_source: Option<CredentialSource>` to `Auth` in `crates/rimap-audit/src/record/mod.rs` (the `Auth` struct near line 183):

```rust
pub struct Auth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub result: AuthResult,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub tls_fingerprint_sha256: Option<String>,
    pub fingerprint_match: Option<bool>,
    pub error_code: Option<ErrorCode>,
    /// Credential source on success; `None` on failure (credential was never
    /// resolved) or on `auth` records from code paths that predate #78.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_source: Option<rimap_core::CredentialSource>,
}
```

Run: `cargo test -p rimap-core --lib credential::tests`
Expected: PASS.

- [ ] **Step 2: Write failing test for the new `resolve_credential` shape**

In `crates/rimap-config/src/credential.rs`:

```rust
    #[test]
    fn strict_mode_skips_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let err = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                crate::model::FallbackMode::KeyringOnly,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::NoCredential { .. }));
        });
    }

    #[test]
    fn permissive_mode_still_uses_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (password, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                crate::model::FallbackMode::KeyringThenEnv,
            )
            .unwrap();
            assert_eq!(password.expose_secret(), "from_env");
            assert_eq!(source, rimap_core::CredentialSource::EnvVar);
        });
    }

    #[test]
    fn keyring_hit_reports_keyring_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("work/alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                crate::model::FallbackMode::KeyringOnly,
            )
            .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::Keyring);
        });
    }

    #[test]
    fn legacy_keyring_hit_reports_legacy_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                crate::model::FallbackMode::KeyringOnly,
            )
            .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::LegacyKeyring);
        });
    }
```

`rimap-config` already depends on `rimap-core` — no new dependency needed for `rimap_core::CredentialSource`.

- [ ] **Step 3: Run tests — expect failure**

Run: `cargo test -p rimap-config --lib credential::tests`
Expected: FAIL — signature mismatch.

- [ ] **Step 4: Update `resolve_credential` signature and body**

```rust
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
    fallback_mode: crate::model::FallbackMode,
) -> Result<(SecretString, rimap_core::CredentialSource), ConfigError> {
    use rimap_core::CredentialSource;

    let new_key = account_key(account_id, username, host);
    if let Some(p) = store.get_password(&new_key)?
        && !p.expose_secret().is_empty()
    {
        return Ok((p, CredentialSource::Keyring));
    }

    let legacy_key = legacy_account_key(username, host);
    if let Some(p) = store.get_password(&legacy_key)?
        && !p.expose_secret().is_empty()
    {
        tracing::warn!(
            account_id = %account_id.as_str(),
            host = %host,
            "credential resolved via legacy keyring key format; \
             run `rusty-imap-mcp migrate-keyring --account {}` to migrate",
            account_id.as_str(),
        );
        return Ok((p, CredentialSource::LegacyKeyring));
    }

    if fallback_mode == crate::model::FallbackMode::KeyringThenEnv
        && let Ok(env) = std::env::var(PASSWORD_ENV_VAR)
        && !env.is_empty()
    {
        return Ok((SecretString::from(env), CredentialSource::EnvVar));
    }

    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: build_no_credential_reason(account_id, fallback_mode, &new_key, &legacy_key),
    })
}

fn build_no_credential_reason(
    account_id: &AccountId,
    fallback_mode: crate::model::FallbackMode,
    new_key: &str,
    legacy_key: &str,
) -> String {
    match fallback_mode {
        crate::model::FallbackMode::KeyringOnly => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`; fallback mode is \
             keyring-only (env var not consulted). Run `rusty-imap-mcp \
             login --account {}`",
            account_id.as_str(),
        ),
        crate::model::FallbackMode::KeyringThenEnv => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`, and `{PASSWORD_ENV_VAR}` \
             is unset or empty. Run `rusty-imap-mcp login --account {}` \
             or set the environment variable",
            account_id.as_str(),
        ),
    }
}
```

- [ ] **Step 5: Plumb `credential_source` through `AuthContext` and the `Auth` builders**

`Auth` records are built at `crates/rimap-imap/src/auth.rs` — two builders (`auth_success`, `auth_failure`) both consume `AuthContext`. Add `credential_source` to `AuthContext` and propagate it through both builders so failure paths also carry the source when resolution already succeeded.

At `crates/rimap-imap/src/auth.rs:8-23`:

```rust
pub(crate) struct AuthContext<'a> {
    pub account: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub pinned: Option<TlsFingerprint>,
    pub observed: Option<TlsFingerprint>,
    /// Source of the resolved credential. `None` before `resolve_credential`
    /// runs (e.g. a TLS failure) or when resolution itself failed.
    pub credential_source: Option<rimap_core::CredentialSource>,
}
```

At `auth.rs:39-49` (`auth_success`) and `:53-63` (`auth_failure`), add:

```rust
    Auth {
        ...
        error_code: None,  // or Some(error_code) in the failure builder
        credential_source: ctx.credential_source,
    }
```

Update the four existing unit tests in `auth.rs` — each constructs `AuthContext { ... }` literals and now needs `credential_source: None` added.

Now update the connect flow in `crates/rimap-imap/src/connection.rs`. `ConnectionConfig` needs two new fields (add once, used by both task 2's plumbing and this task's behavior):

```rust
pub struct ConnectionConfig {
    pub account: Option<String>,
    pub account_id: rimap_core::account::AccountId,
    pub fallback_mode: rimap_config::model::FallbackMode,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub pinned_fingerprint: Option<rimap_core::tls::TlsFingerprint>,
    pub connect_timeout: std::time::Duration,
    pub command_timeout: std::time::Duration,
    pub max_fetch_body_bytes: u64,
    pub max_append_bytes: u64,
}
```

At `crates/rimap-imap/src/connection.rs:325`:

```rust
        let cfg = &self.inner.cfg;
        let (password, credential_source) = resolve_credential(
            &*self.inner.credentials,
            &cfg.account_id,
            &cfg.username,
            &cfg.host,
            cfg.fallback_mode,
        )
        .map_err(|e| ImapError::Auth {
            reason: AuthFailure::CredentialUnavailable(e.to_string()),
        })?;
```

The `AuthContext` for this connect attempt is currently constructed somewhere in the connect path (find it: `grep -n "AuthContext {" crates/rimap-imap/src/connection.rs`). Update that construction to pass `credential_source: Some(credential_source)`. For `AuthContext`s built on paths that run before `resolve_credential` (TLS handshake failure, greeting failure, CAPABILITY failure — lines 286, 295, 315), pass `credential_source: None`.

In `crates/rimap-server/src/main.rs::build_account_connection`, pass the new field:

```rust
ConnectionConfig {
    account,
    account_id: id.clone(),
    fallback_mode: acfg.fallback_mode,
    host: acfg.imap.host.clone(),
    ...
}
```

In `crates/rimap-server/src/main.rs::build_smtp_client`, update the SMTP `resolve_credential` call:

```rust
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        acfg.fallback_mode,
    )
    .with_context(|| {
        format!("resolving SMTP credential for account {}", acfg.id.as_str())
    })?;
```

(SMTP has no audit record today — discarding `_src` is correct. If a future SMTP auth record lands, it will use the same pattern.)

- [ ] **Step 6: Update all in-crate `resolve_credential` test calls**

Each existing `resolve_credential(&store, "alice", "host")` test call in `credential.rs` and any downstream crate needs:

```rust
use crate::model::FallbackMode;
let (p, _src) = resolve_credential(
    &store,
    &AccountId::default_account(),
    "alice",
    "host",
    FallbackMode::KeyringThenEnv,
).unwrap();
```

- [ ] **Step 7: Run full workspace tests + clippy**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-core/src/credential.rs crates/rimap-core/src/lib.rs \
        crates/rimap-audit/src/record/mod.rs \
        crates/rimap-config/src/credential.rs crates/rimap-config/Cargo.toml \
        crates/rimap-imap/src/auth.rs crates/rimap-imap/src/connection.rs \
        crates/rimap-imap/src/types.rs crates/rimap-server/src/main.rs
git commit -m "config: honor FallbackMode; log credential source on auth (#78)

CredentialSource lives in rimap-core (shared by rimap-config and
rimap-audit without a cycle). resolve_credential now returns
(SecretString, CredentialSource) and takes FallbackMode. KeyringOnly
skips the env var entirely.

rimap-audit::record::Auth gains credential_source (Option for
back-compat). AuthContext carries it through; both auth_success and
auth_failure propagate it so failure paths after resolution still
record the source."
```

---

## Task 8: Docs + CHANGELOG update (#77, #78)

**Files:**
- Modify: `docs/multi-account.md`
- Modify: `CHANGELOG.md`

### Approach

Replace the two "Recommendation:" paragraphs in `docs/multi-account.md` with pointers to the enforceable config knob. Add a CHANGELOG entry.

- [ ] **Step 1: Update `docs/multi-account.md`**

Replace `docs/multi-account.md:171-194` (from "Keyring Collision (Multi-Account)" heading through the "Tracking issues ..." line) with:

```markdown
### Keyring Collision (Multi-Account)

Keyring entries are namespaced by account id: `<account-id>/<username>@<host>`.
Two accounts that share a `<username>@<host>` tuple no longer collide. After
upgrading across #77, run `rusty-imap-mcp migrate-keyring --account <id>
--host <h> --username <u>` once per account to rewrite the legacy key.
Until migration completes, `resolve_credential` transparently falls back to
the legacy key and emits a `tracing::warn!` pointing at the migrate command.

### Env-var Fallback (Multi-Account)

`RUSTY_IMAP_MCP_PASSWORD` is a single global fallback. In multi-account
configs, if the keyring lookup fails for account A every subsequent account
falls back to the same env-var value, which can send account B's password to
account A's server.

To disable the fallback globally:

```toml
[defaults.credentials]
fallback = "keyring-only"
```

Or per-account:

```toml
[[accounts]]
name = "work"

[accounts.credentials]
fallback = "keyring-only"
```

With `fallback = "keyring-only"`, a missing keyring entry produces
`ERR_CONFIG` without consulting `RUSTY_IMAP_MCP_PASSWORD`.

The default is `"keyring-then-env"` (back-compat). Audit records include a
`credential_source` field (`keyring` / `legacy_keyring` / `env_var`) so
post-incident analysis can detect silent downgrades.
```

- [ ] **Step 2: Update CHANGELOG.md**

Insert a new `[Unreleased]` section at the top, above `[1.0.0] - 2026-04-13`:

```markdown
## [Unreleased]

### Changed

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
```

- [ ] **Step 3: Run `typos` over the edited docs**

Run: `typos docs/multi-account.md CHANGELOG.md`
Expected: no findings.

- [ ] **Step 4: Commit**

```bash
git add docs/multi-account.md CHANGELOG.md
git commit -m "docs: document strict credential mode + keyring migration (#77, #78)

Replaces the 'Recommendation:' paragraphs with references to the
enforceable [defaults.credentials] fallback knob and the new
migrate-keyring subcommand. CHANGELOG gets an [Unreleased] section
covering the breaking keyring key change, the new --account arg on
login, redacted ConfigError Display, and the credential_source audit
field."
```

---

## Task 9: Final workspace check + issue close-out

- [ ] **Step 1: Run the full verification pipeline**

Run in sequence:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check advisories bans licenses sources
typos
```

All five must pass. No warnings.

- [ ] **Step 2: Open the PR**

Branch: `feat/credential-hardening` (as suggested by the roadmap spec).
Target: `main`.

PR body should reference `Closes #76`, `Closes #77`, `Closes #78` so merging closes all three.

- [ ] **Step 3: After merge, update the roadmap spec**

Edit `docs/superpowers/specs/2026-04-19-open-issues-roadmap-design.md` §3 Sub-group 4 to mark the three issues as closed (or delete the sub-group block if the roadmap wants a running inventory of what's left). Commit as a small follow-up on `main` or fold into a future sub-group's branch.
