# Sprint 3b: Multi-Account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add multi-account support: multiple IMAP/SMTP accounts in a single process, discoverable via MCP resources, selectable per-session or per-call. Existing single-account configs continue to work unchanged.

**Architecture:** An `AccountRegistry` holds a `BTreeMap<AccountId, AccountState>` where each `AccountState` bundles a per-account `Connection`, `DispatchGuard`, `FolderGuard`, and optional `SmtpClient`. The server resolves an account on every tool call (explicit param > session default > auto-select > error), then delegates to the existing handler with the resolved account's state. MCP resources expose accounts for agent discovery. A shared `AuditWriter` tags every record with the account name.

**Tech Stack:** Rust, rmcp (ServerHandler + resources), serde/toml, schemars

**Depends on:** Sprint 3a (label tools — so the ToolName enum has 22 variants).

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-core/src/error.rs` | Add `NoAccount`, `UnknownAccount` error codes |
| Modify | `crates/rimap-core/src/tool.rs` | Add `UseAccount`, `ListAccounts` variants |
| Modify | `crates/rimap-core/src/posture_matrix.rs` | No change — infrastructure tools bypass matrix |
| Create | `crates/rimap-core/src/account.rs` | `AccountId` newtype |
| Modify | `crates/rimap-core/src/lib.rs` | Re-export `account` module |
| Modify | `crates/rimap-config/src/model.rs` | `MultiAccountConfig`, `AccountConfig`, `DefaultsConfig` structs |
| Modify | `crates/rimap-config/src/validate.rs` | `ValidatedAccountConfig`, per-account validation, legacy detection |
| Modify | `crates/rimap-config/src/loader.rs` | Two-pass loading: try multi-account, fall back to legacy |
| Modify | `crates/rimap-config/src/error.rs` | New config error variants |
| Create | `crates/rimap-server/src/registry.rs` | `AccountState`, `AccountRegistry`, resolution logic |
| Modify | `crates/rimap-server/src/server.rs` | Restructure to use registry, add resource handlers |
| Modify | `crates/rimap-server/src/dispatch.rs` | Account-aware guard dispatch |
| Create | `crates/rimap-server/src/tools/accounts.rs` | `use_account`, `list_accounts` handlers |
| Modify | `crates/rimap-server/src/tools/mod.rs` | Register `accounts` module |
| Modify | `crates/rimap-server/src/main.rs` | Multi-account bootstrap |
| Modify | `crates/rimap-audit/src/record.rs` | Add `account` field to records |

---

## Task 1: Add `AccountId` newtype and new error codes

**Files:**
- Create: `crates/rimap-core/src/account.rs`
- Modify: `crates/rimap-core/src/lib.rs`
- Modify: `crates/rimap-core/src/error.rs`

- [ ] **Step 1: Create `AccountId` newtype**

Create `crates/rimap-core/src/account.rs`:

```rust
//! Account identity type.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Validated account identifier.
///
/// ASCII alphanumeric + hyphens, 1–64 characters. The special name
/// `"default"` is used for legacy single-account configs.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct AccountId(String);

/// Maximum length of an account name.
const MAX_ACCOUNT_NAME_LEN: usize = 64;

/// The synthetic name for legacy single-account configs.
pub const DEFAULT_ACCOUNT_NAME: &str = "default";

impl AccountId {
    /// Create an `AccountId` from a validated string.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty, too long, or contains
    /// characters outside `[a-zA-Z0-9-]`.
    pub fn new(name: &str) -> Result<Self, InvalidAccountName> {
        if name.is_empty() {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: "account name must not be empty".to_string(),
            });
        }
        if name.len() > MAX_ACCOUNT_NAME_LEN {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: format!(
                    "account name exceeds {} character limit",
                    MAX_ACCOUNT_NAME_LEN,
                ),
            });
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: "account name must be ASCII alphanumeric or hyphens"
                    .to_string(),
            });
        }
        Ok(Self(name.to_string()))
    }

    /// Create the default account ID for legacy configs.
    pub fn default_account() -> Self {
        Self(DEFAULT_ACCOUNT_NAME.to_string())
    }

    /// Return the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when an account name fails validation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid account name `{name}`: {reason}")]
pub struct InvalidAccountName {
    /// The rejected name.
    pub name: String,
    /// Why it was rejected.
    pub reason: String,
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(AccountId::new("work").is_ok());
        assert!(AccountId::new("personal-2").is_ok());
        assert!(AccountId::new("default").is_ok());
        assert!(AccountId::new("a").is_ok());
    }

    #[test]
    fn empty_rejected() {
        assert!(AccountId::new("").is_err());
    }

    #[test]
    fn too_long_rejected() {
        let long = "a".repeat(65);
        assert!(AccountId::new(&long).is_err());
    }

    #[test]
    fn max_length_accepted() {
        let exact = "a".repeat(64);
        assert!(AccountId::new(&exact).is_ok());
    }

    #[test]
    fn spaces_rejected() {
        assert!(AccountId::new("my account").is_err());
    }

    #[test]
    fn underscores_rejected() {
        assert!(AccountId::new("my_account").is_err());
    }

    #[test]
    fn special_chars_rejected() {
        assert!(AccountId::new("work@home").is_err());
        assert!(AccountId::new("work/home").is_err());
    }

    #[test]
    fn display_matches_inner() {
        let id = AccountId::new("work").unwrap();
        assert_eq!(id.to_string(), "work");
    }
}
```

- [ ] **Step 2: Re-export from `rimap-core/src/lib.rs`**

Add to `crates/rimap-core/src/lib.rs`:

```rust
pub mod account;
```

- [ ] **Step 3: Add error codes for account resolution**

In `crates/rimap-core/src/error.rs`, add two variants to `ErrorCode`:

```rust
    NoAccount,
    UnknownAccount,
```

And their on-wire strings in the `as_str()` / `Display` impl:

```rust
    Self::NoAccount => "ERR_NO_ACCOUNT",
    Self::UnknownAccount => "ERR_UNKNOWN_ACCOUNT",
```

Add two variants to `RimapError`:

```rust
    /// No account selected in a multi-account configuration.
    NoAccount {
        available: Vec<String>,
    },
    /// The requested account does not exist.
    UnknownAccount {
        name: String,
        available: Vec<String>,
    },
```

Implement `code()` for the new variants:

```rust
    Self::NoAccount { .. } => ErrorCode::NoAccount,
    Self::UnknownAccount { .. } => ErrorCode::UnknownAccount,
```

Implement `Display` for the new variants:

```rust
    Self::NoAccount { available } => write!(
        f,
        "multiple accounts configured; call `use_account` or pass \
         `account` parameter. Available: {}",
        available.join(", "),
    ),
    Self::UnknownAccount { name, available } => write!(
        f,
        "account '{}' not found. Available: {}",
        name,
        available.join(", "),
    ),
```

- [ ] **Step 4: Run `cargo test -p rimap-core`**

Run: `cargo test -p rimap-core`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/account.rs crates/rimap-core/src/lib.rs crates/rimap-core/src/error.rs
git commit -m "feat(core): add AccountId newtype and NoAccount/UnknownAccount errors"
```

---

## Task 2: Add `UseAccount` and `ListAccounts` tool variants

**Files:**
- Modify: `crates/rimap-core/src/tool.rs`

- [ ] **Step 1: Add tool variants**

Add two variants to `ToolName` after `DeleteFolder`:

```rust
    DeleteFolder,
    UseAccount,
    ListAccounts,
```

Add `as_str()` arms:

```rust
    Self::UseAccount => "use_account",
    Self::ListAccounts => "list_accounts",
```

These tools are NOT added to `POSTURE_MATRIX` — they bypass posture checks entirely. They ARE in the `ToolName` enum so they can be parsed from MCP tool names and dispatched.

- [ ] **Step 2: Update `FromStr` — verify it works**

`FromStr` uses `EnumIter` + `as_str()` matching, so the new variants are automatically parseable. No code change needed — just verify:

Run: `cargo test -p rimap-core`
Expected: passes. The `all()` method now returns 24 variants.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-core/src/tool.rs
git commit -m "feat(core): add UseAccount and ListAccounts tool variants"
```

---

## Task 3: Restructure config for multi-account

**Files:**
- Modify: `crates/rimap-config/src/model.rs`
- Modify: `crates/rimap-config/src/error.rs`
- Modify: `crates/rimap-config/src/loader.rs`
- Modify: `crates/rimap-config/src/validate.rs`

This is the largest task. The config system needs to support both legacy flat configs and the new `[[accounts]]` format.

- [ ] **Step 1: Add new config error variants**

In `crates/rimap-config/src/error.rs`, add:

```rust
    DuplicateAccountName { name: String },
    MixedConfigFormat,
    InvalidAccountName(#[from] rimap_core::account::InvalidAccountName),
    NoAccounts,
```

- [ ] **Step 2: Define multi-account config structs**

In `crates/rimap-config/src/model.rs`, add the new types. Keep all existing types unchanged — they become the "legacy" format:

```rust
/// Multi-account configuration format.
///
/// Deserialized from TOML files with `[[accounts]]` sections.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAccountConfig {
    #[serde(default)]
    pub defaults: DefaultsConfig,
    pub accounts: Vec<RawAccountConfig>,
    pub audit: AuditConfig,
    #[serde(default)]
    pub attachments: AttachmentsConfig,
}

/// Defaults section — inherited by accounts that don't override.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// A single account entry from `[[accounts]]`.
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
}
```

- [ ] **Step 3: Create `ValidatedAccountConfig`**

In `crates/rimap-config/src/validate.rs`, add:

```rust
use std::collections::BTreeMap;

use rimap_core::account::AccountId;
use rimap_core::posture::Posture;
use rimap_core::tool::ToolName;

use crate::model::{
    AuditConfig, AttachmentsConfig, ImapConfig, LimitsConfig,
    SecurityConfig, SmtpConfig, Verdict,
};
use rimap_core::tls::TlsFingerprint;

/// Validated per-account configuration.
#[derive(Debug)]
pub struct ValidatedAccountConfig {
    pub id: AccountId,
    pub imap: ImapConfig,
    pub smtp: Option<SmtpConfig>,
    pub security: SecurityConfig,
    pub limits: LimitsConfig,
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
    pub tls_fingerprint: Option<TlsFingerprint>,
}

/// Validated multi-account configuration.
#[derive(Debug)]
pub struct ValidatedMultiConfig {
    pub accounts: BTreeMap<AccountId, ValidatedAccountConfig>,
    pub audit: AuditConfig,
    pub attachments: AttachmentsConfig,
}
```

- [ ] **Step 4: Implement multi-account validation**

Add a `validate_multi` function that:

1. Validates account names (no duplicates, valid `AccountId`)
2. For each account, merges defaults with per-account overrides
3. Runs the same per-account validations as the existing `validate()`: fingerprint parsing, limit validation, folder safety, SMTP required, SMTP encryption, tool override resolution
4. Validates global settings: audit path, download dir

```rust
pub fn validate_multi(
    config: MultiAccountConfig,
) -> Result<ValidatedMultiConfig, ConfigError> {
    if config.accounts.is_empty() {
        return Err(ConfigError::NoAccounts);
    }

    let mut validated_accounts = BTreeMap::new();

    for raw in &config.accounts {
        let id = AccountId::new(&raw.name)?;
        if validated_accounts.contains_key(&id) {
            return Err(ConfigError::DuplicateAccountName {
                name: raw.name.clone(),
            });
        }

        // Merge defaults with per-account overrides
        let security = raw.security.clone()
            .unwrap_or_else(|| config.defaults.security.clone());
        let limits = raw.limits.clone()
            .unwrap_or_else(|| config.defaults.limits.clone());

        // Run per-account validations (same as existing validate())
        let tls_fingerprint = parse_fingerprint(
            &raw.imap.tls_fingerprint_sha256,
        )?;
        validate_limits(&limits)?;
        validate_folder_safety(&security)?;
        let tool_overrides = resolve_tool_overrides(&security)?;
        validate_smtp_required(
            &security, &tool_overrides, &raw.smtp,
        )?;
        if let Some(ref smtp) = raw.smtp {
            validate_smtp_encryption(smtp)?;
        }

        validated_accounts.insert(id.clone(), ValidatedAccountConfig {
            id,
            imap: raw.imap.clone(),
            smtp: raw.smtp.clone(),
            security,
            limits,
            tool_overrides,
            tls_fingerprint,
        });
    }

    // Validate global settings
    validate_audit(&config.audit)?;
    validate_paths_global(&config.audit, &config.attachments)?;

    Ok(ValidatedMultiConfig {
        accounts: validated_accounts,
        audit: config.audit,
        attachments: config.attachments,
    })
}
```

The exact function signatures for helpers like `parse_fingerprint`, `validate_limits`, etc. should match the existing private functions already in `validate.rs`. Some may need their signatures adjusted to accept borrowed sub-configs rather than the monolithic `Config`.

- [ ] **Step 5: Implement legacy config conversion**

Add a function to convert a legacy `Config` into `ValidatedMultiConfig`:

```rust
/// Convert a legacy flat config into a multi-account config with one
/// `"default"` account.
pub fn validate_legacy_as_multi(
    config: Config,
) -> Result<ValidatedMultiConfig, ConfigError> {
    let validated = validate(config)?;
    let id = AccountId::default_account();
    let account = ValidatedAccountConfig {
        id: id.clone(),
        imap: validated.config.imap.clone(),
        smtp: validated.config.smtp.clone(),
        security: validated.config.security.clone(),
        limits: validated.config.limits.clone(),
        tool_overrides: validated.tool_overrides,
        tls_fingerprint: validated.tls_fingerprint,
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, account);
    Ok(ValidatedMultiConfig {
        accounts,
        audit: validated.config.audit,
        attachments: validated.config.attachments,
    })
}
```

- [ ] **Step 6: Implement two-pass loading in `loader.rs`**

In `crates/rimap-config/src/loader.rs`, add a function that tries multi-account parsing first, then falls back to legacy:

```rust
pub fn load_and_validate(
    path: &Path,
) -> Result<ValidatedMultiConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::Read { path: path.to_path_buf(), source: e }
    })?;

    // Detect format: if the text contains `[[accounts]]`, try multi-account.
    // If it contains `[imap]` at the top level, try legacy.
    // If both are present, error.
    let has_accounts = text.contains("[[accounts]]");
    let has_flat_imap = text.contains("[imap]")
        && !text.contains("[accounts.imap]");

    if has_accounts && has_flat_imap {
        return Err(ConfigError::MixedConfigFormat);
    }

    if has_accounts {
        let config: MultiAccountConfig =
            toml::from_str(&text).map_err(|e| {
                ConfigError::Parse { path: path.to_path_buf(), source: e }
            })?;
        validate::validate_multi(config)
    } else {
        let config: Config =
            toml::from_str(&text).map_err(|e| {
                ConfigError::Parse { path: path.to_path_buf(), source: e }
            })?;
        validate::validate_legacy_as_multi(config)
    }
}
```

Note: the heuristic detection (`contains("[[accounts]]")`) is intentionally simple. `serde(deny_unknown_fields)` on both `Config` and `MultiAccountConfig` provides the real enforcement — if a field doesn't belong, TOML parsing fails with a clear error.

- [ ] **Step 7: Write tests for multi-account config parsing**

Add tests in `crates/rimap-config/src/validate.rs` (or a new test file):

```rust
#[cfg(test)]
mod multi_account_tests {
    use super::*;

    #[test]
    fn multi_account_parses() {
        let toml = r#"
[audit]
path = "/tmp/audit.jsonl"

[[accounts]]
name = "work"
[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "user@example.com"

[[accounts]]
name = "personal"
[accounts.imap]
host = "imap.example.com"
port = 993
username = "me@example.com"
"#;
        let config: MultiAccountConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.accounts.len(), 2);
        assert_eq!(config.accounts[0].name, "work");
        assert_eq!(config.accounts[1].name, "personal");
    }

    #[test]
    fn duplicate_name_rejected() {
        // Two accounts named "work" → DuplicateAccountName
    }

    #[test]
    fn legacy_config_wraps_as_default() {
        // Flat [imap] config → single "default" account
    }

    #[test]
    fn mixed_format_rejected() {
        // Both [imap] and [[accounts]] → MixedConfigFormat
    }

    #[test]
    fn defaults_inherited() {
        // [defaults.security] posture = "full"
        // Account with no [accounts.security] → inherits "full"
    }

    #[test]
    fn account_overrides_defaults() {
        // [defaults.security] posture = "full"
        // [accounts.security] posture = "readonly" → account is "readonly"
    }

    #[test]
    fn no_accounts_rejected() {
        // [audit] only, no [imap] or [[accounts]] → NoAccounts
    }

    #[test]
    fn invalid_account_name_rejected() {
        // name = "my account" → InvalidAccountName
    }
}
```

- [ ] **Step 8: Run `cargo test -p rimap-config`**

Run: `cargo test -p rimap-config`
Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-config/
git commit -m "feat(config): add multi-account config schema with legacy backward compat"
```

---

## Task 4: Build `AccountRegistry` and `AccountState`

**Files:**
- Create: `crates/rimap-server/src/registry.rs`

- [ ] **Step 1: Define `AccountState` and `AccountRegistry`**

Create `crates/rimap-server/src/registry.rs`:

```rust
//! Account registry: per-account runtime state and session-scoped
//! account selection.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rimap_authz::DispatchGuard;
use rimap_authz::FolderGuard;
use rimap_authz::breaker::SystemClock;
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_imap::Connection;
use rimap_smtp::SmtpClient;

/// Per-account runtime state.
pub struct AccountState {
    /// Account identifier.
    pub id: AccountId,
    /// Lazy-connect IMAP connection handle.
    pub imap: Connection,
    /// SMTP client, if configured for this account.
    pub smtp: Option<SmtpClient>,
    /// Posture + circuit breaker + rate limiter.
    pub guard: DispatchGuard<SystemClock>,
    /// Folder safety guard.
    pub folder_guard: FolderGuard,
}

/// Holds all accounts and the session-scoped default selection.
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    active: Mutex<Option<AccountId>>,
}

impl AccountRegistry {
    /// Create a registry from validated account states.
    pub fn new(
        accounts: BTreeMap<AccountId, AccountState>,
    ) -> Self {
        Self {
            accounts,
            active: Mutex::new(None),
        }
    }

    /// Resolve the account for a tool call.
    ///
    /// Priority: explicit name > session default > auto-select (single
    /// account) > error.
    pub fn resolve(
        &self,
        explicit: Option<&str>,
    ) -> Result<&AccountState, RimapError> {
        let available: Vec<String> = self
            .accounts
            .keys()
            .map(|id| id.as_str().to_string())
            .collect();

        if let Some(name) = explicit {
            return self.get_by_name(name, &available);
        }

        let guard = self.active.lock().map_err(|e| {
            RimapError::Internal(format!("account mutex poisoned: {e}"))
        })?;
        if let Some(ref id) = *guard {
            return self
                .accounts
                .get(id)
                .ok_or_else(|| RimapError::Internal(
                    "active account no longer in registry".to_string(),
                ));
        }
        drop(guard);

        if self.accounts.len() == 1 {
            return Ok(self.accounts.values().next().ok_or_else(|| {
                RimapError::Internal("empty registry".to_string())
            })?);
        }

        Err(RimapError::NoAccount { available })
    }

    /// Set the session-scoped default account.
    pub fn set_active(
        &self,
        name: &str,
    ) -> Result<Option<String>, RimapError> {
        let available: Vec<String> = self
            .accounts
            .keys()
            .map(|id| id.as_str().to_string())
            .collect();

        // Validate the name exists
        let _ = self.get_by_name(name, &available)?;

        let id = AccountId::new(name).map_err(|e| {
            RimapError::Internal(e.to_string())
        })?;
        let mut guard = self.active.lock().map_err(|e| {
            RimapError::Internal(format!("account mutex poisoned: {e}"))
        })?;
        let previous = guard.as_ref().map(|id| id.as_str().to_string());
        *guard = Some(id);
        Ok(previous)
    }

    /// List all account names.
    pub fn account_names(&self) -> Vec<&AccountId> {
        self.accounts.keys().collect()
    }

    /// Get all account states for iteration.
    pub fn accounts(&self) -> &BTreeMap<AccountId, AccountState> {
        &self.accounts
    }

    fn get_by_name<'a>(
        &'a self,
        name: &str,
        available: &[String],
    ) -> Result<&'a AccountState, RimapError> {
        // Linear scan is fine — account count is small.
        for (id, state) in &self.accounts {
            if id.as_str() == name {
                return Ok(state);
            }
        }
        Err(RimapError::UnknownAccount {
            name: name.to_string(),
            available: available.to_vec(),
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Tests require constructing AccountState which needs Connection etc.
    // Use integration-style tests or mock the registry for unit tests.
    // Detailed test cases:
    // - Single account auto-selects without explicit name
    // - Multi-account with no selection returns NoAccount
    // - Explicit name resolves correct account
    // - set_active + resolve returns the active account
    // - set_active returns previous account name
    // - Unknown name returns UnknownAccount with available list
}
```

- [ ] **Step 2: Run `cargo check -p rimap-server`**

Run: `cargo check -p rimap-server`
Expected: compiles. Tests are placeholder — will be filled in when wiring is complete.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/registry.rs
git commit -m "feat(server): add AccountRegistry with session-scoped account resolution"
```

---

## Task 5: Restructure `ImapMcpServer` to use registry

**Files:**
- Modify: `crates/rimap-server/src/server.rs`
- Modify: `crates/rimap-server/src/dispatch.rs`

This is the core refactor. `ImapMcpServer` drops its singular `config`, `imap`, `guard`, `folder_guard` fields and gains a `registry`.

- [ ] **Step 1: Update `ImapMcpServer` struct**

```rust
pub struct ImapMcpServer {
    /// Account registry with all configured accounts.
    pub(crate) registry: crate::registry::AccountRegistry,
    /// Shared append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Directory for attachment downloads.
    pub(crate) download_dir: PathBuf,
}
```

- [ ] **Step 2: Update `call_tool` to resolve account and strip `account` key**

In `call_tool`, after parsing the tool name, extract the optional `"account"` key from the arguments:

```rust
async fn call_tool(
    &self,
    request: CallToolRequestParams,
    _context: RequestContext<RoleServer>,
) -> Result<CallToolResult, ErrorData> {
    let tool_name = ToolName::from_str(&request.name)
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    if tool_definition(tool_name).is_none() {
        return Err(ErrorData::new(
            McpCode::RESOURCE_NOT_FOUND,
            format!("tool `{}` is not available", request.name),
            None,
        ));
    }

    let mut args = request.arguments.unwrap_or_default();

    // Infrastructure tools bypass account resolution and guards
    match tool_name {
        ToolName::UseAccount | ToolName::ListAccounts => {
            return self
                .dispatch_infrastructure(tool_name, &args)
                .await;
        }
        _ => {}
    }

    // Extract and strip the optional "account" key
    let account_name = args
        .remove("account")
        .and_then(|v| v.as_str().map(String::from));

    // Resolve account
    let account = self
        .registry
        .resolve(account_name.as_deref())
        .map_err(|e| crate::mcp_error::to_mcp_error(&e))?;

    // Run pre-call guards on the resolved account's guard
    if let Err(e) = crate::dispatch::pre_call_guards(
        &account.guard, tool_name,
    ) {
        return Err(crate::mcp_error::to_mcp_error(&e));
    }

    let result = Box::pin(
        self.dispatch_tool(account, tool_name, &args),
    ).await;

    match result {
        Ok(resp) => {
            let value = serde_json::to_value(&resp)
                .map_err(|e| {
                    ErrorData::internal_error(e.to_string(), None)
                })?;
            Ok(CallToolResult::structured(value))
        }
        Err(e) => Err(crate::mcp_error::to_mcp_error(&e)),
    }
}
```

- [ ] **Step 3: Update `dispatch_tool` to take `&AccountState`**

Change the method signature:

```rust
impl ImapMcpServer {
    pub(crate) async fn dispatch_tool(
        &self,
        account: &crate::registry::AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<crate::response::ToolResponse, rimap_core::RimapError> {
        // ... match arms unchanged but pass account instead of self ...
    }
}
```

- [ ] **Step 4: Update every tool handler to take `&AccountState` instead of `&ImapMcpServer`**

This is a mechanical change across all tool handler files. Every handler's signature changes from:

```rust
pub async fn handle(server: &ImapMcpServer, input: T) -> Result<ToolResponse, RimapError>
```

to:

```rust
pub async fn handle(account: &AccountState, input: T) -> Result<ToolResponse, RimapError>
```

And references change: `server.imap` → `account.imap`, `server.folder_guard` → `account.folder_guard`, `server.config` → accessed via `account` fields as needed.

Files to update:
- `tools/list_folders.rs` — `server.imap` → `account.imap`
- `tools/search.rs` — `server.imap`, `server.config.limits.*` → `account.imap`
- `tools/fetch_message.rs` — `server.imap`, `server.config.*` → `account.imap`
- `tools/list_attachments.rs` — `server.imap` → `account.imap`
- `tools/download_attachment.rs` — `server.imap`, `server.download_dir` → `account.imap` (download_dir stays on server, pass separately or via context)
- `tools/flags.rs` — `server.imap` → `account.imap`
- `tools/labels.rs` — `server.imap` → `account.imap`
- `tools/move_message.rs` — `server.imap` → `account.imap`
- `tools/create_draft.rs` — `server.imap`, `server.config.*` → `account.imap`
- `tools/send_email.rs` — `server.imap`, `server.config.smtp.*` → `account.imap`, `account.smtp`
- `tools/delete_message.rs` — `server.imap` → `account.imap`
- `tools/expunge.rs` — `server.imap`, `server.folder_guard` → `account.imap`, `account.folder_guard`
- `tools/folder_mgmt.rs` — `server.imap`, `server.folder_guard` → `account.imap`, `account.folder_guard`

For handlers that need `download_dir` or `audit`, use a context struct or pass them as separate parameters from the dispatch layer.

- [ ] **Step 5: Update dispatch arms in `dispatch_tool`**

Each match arm changes from `self` to `account`:

```rust
    ToolName::ListFolders => {
        Box::pin(crate::tools::list_folders::handle(account)).await
    }
    ToolName::Search | ToolName::SearchAdvanced => {
        let input = parse_args(args)?;
        Box::pin(crate::tools::search::handle(account, input)).await
    }
    // ... etc for all tools ...
```

For `download_attachment`, pass download_dir from self:

```rust
    ToolName::DownloadAttachment => {
        let input = parse_args(args)?;
        Box::pin(crate::tools::download_attachment::handle(
            account, input, &self.download_dir,
        )).await
    }
```

- [ ] **Step 6: Run `cargo check -p rimap-server`**

Run: `cargo check -p rimap-server`
Expected: compiles. Tests may fail — they construct `ImapMcpServer` with the old fields.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/
git commit -m "refactor(server): restructure dispatch to use AccountState"
```

---

## Task 6: Add `use_account` and `list_accounts` tool handlers

**Files:**
- Create: `crates/rimap-server/src/tools/accounts.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`
- Modify: `crates/rimap-server/src/server.rs`

- [ ] **Step 1: Create account tool handlers**

Create `crates/rimap-server/src/tools/accounts.rs`:

```rust
//! Infrastructure tool handlers for account management.
//!
//! `use_account` and `list_accounts` bypass posture checks and rate
//! limiting — they are infrastructure tools, not IMAP operations.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::registry::AccountRegistry;
use crate::response::ToolResponse;

/// Input for `use_account`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UseAccountInput {
    /// Account name to select as the session default.
    pub account: String,
}

/// Handle `use_account` — set the session-scoped default account.
pub fn handle_use_account(
    registry: &AccountRegistry,
    input: UseAccountInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let previous = registry.set_active(&input.account)?;
    Ok(ToolResponse {
        meta: serde_json::json!({
            "account": input.account,
            "previous": previous,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Handle `list_accounts` — return all configured account summaries.
pub fn handle_list_accounts(
    registry: &AccountRegistry,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let accounts: Vec<serde_json::Value> = registry
        .accounts()
        .values()
        .map(|state| {
            serde_json::json!({
                "name": state.id.as_str(),
                "imap_host": state.imap.host(),
                "smtp_configured": state.smtp.is_some(),
            })
        })
        .collect();
    Ok(ToolResponse {
        meta: serde_json::json!({
            "accounts": accounts,
            "count": accounts.len(),
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
```

- [ ] **Step 2: Register the module**

In `crates/rimap-server/src/tools/mod.rs`:

```rust
pub mod accounts;
```

- [ ] **Step 3: Wire into server dispatch**

In `server.rs`, add the `dispatch_infrastructure` method and tool definitions:

```rust
impl ImapMcpServer {
    async fn dispatch_infrastructure(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = match tool {
            ToolName::UseAccount => {
                let input: crate::tools::accounts::UseAccountInput =
                    parse_args(args).map_err(|e| {
                        crate::mcp_error::to_mcp_error(&e)
                    })?;
                crate::tools::accounts::handle_use_account(
                    &self.registry, input,
                )
            }
            ToolName::ListAccounts => {
                crate::tools::accounts::handle_list_accounts(
                    &self.registry,
                )
            }
            _ => {
                return Err(ErrorData::internal_error(
                    format!("not an infrastructure tool: {}", tool.as_str()),
                    None,
                ));
            }
        };
        match result {
            Ok(resp) => {
                let value = serde_json::to_value(&resp).map_err(|e| {
                    ErrorData::internal_error(e.to_string(), None)
                })?;
                Ok(CallToolResult::structured(value))
            }
            Err(e) => Err(crate::mcp_error::to_mcp_error(&e)),
        }
    }
}
```

Add tool definitions. These are always advertised (not posture-gated):

```rust
fn tool_spec_infra(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::accounts::UseAccountInput;

    let tuple = match name {
        ToolName::UseAccount => (
            "use_account",
            "Set the active account for subsequent tool calls",
            schema_map::<UseAccountInput>(),
        ),
        ToolName::ListAccounts => (
            "list_accounts",
            "List all configured email accounts",
            serde_json::Map::new(),
        ),
        _ => return None,
    };
    Some(tuple)
}
```

Update `tool_definition` to include `tool_spec_infra`:

```rust
fn tool_definition(name: ToolName) -> Option<Tool> {
    let (tool_name, description, schema) = tool_spec_v1(name)
        .or_else(|| tool_spec_v2(name))
        .or_else(|| tool_spec_v3(name))
        .or_else(|| tool_spec_infra(name))?;
    Some(Tool::new(tool_name, description, Arc::new(schema)))
}
```

Update `list_tools` to include infrastructure tools alongside posture-filtered tools:

```rust
async fn list_tools(&self, ...) -> Result<ListToolsResult, ErrorData> {
    // Get the advertised tools from the first account's matrix
    // (for single-account compat) or union across all accounts.
    // Infrastructure tools are always included.
    let mut tools: Vec<Tool> = Vec::new();

    // Infrastructure tools — always advertised
    for name in [ToolName::UseAccount, ToolName::ListAccounts] {
        if let Some(def) = tool_definition(name) {
            tools.push(def);
        }
    }

    // Union of tools advertised by any account's posture
    let mut seen = std::collections::HashSet::new();
    for state in self.registry.accounts().values() {
        for &tn in &state.guard.matrix().advertised() {
            if seen.insert(tn) {
                if let Some(def) = tool_definition(tn) {
                    tools.push(def);
                }
            }
        }
    }

    Ok(ListToolsResult::with_all_items(tools))
}
```

- [ ] **Step 4: Run `cargo check -p rimap-server`**

Run: `cargo check -p rimap-server`
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/accounts.rs crates/rimap-server/src/tools/mod.rs crates/rimap-server/src/server.rs
git commit -m "feat(server): add use_account and list_accounts tools"
```

---

## Task 7: Add MCP resource handlers for account discovery

**Files:**
- Modify: `crates/rimap-server/src/server.rs`

- [ ] **Step 1: Implement `list_resources`**

Override `list_resources` in the `ServerHandler` impl:

```rust
async fn list_resources(
    &self,
    _request: Option<PaginatedRequestParams>,
    _context: RequestContext<RoleServer>,
) -> Result<ListResourcesResult, ErrorData> {
    let resources: Vec<Resource> = self
        .registry
        .accounts()
        .values()
        .map(|state| {
            Resource::new(
                format!("rimap://accounts/{}", state.id.as_str()),
                state.id.as_str(),
            )
            .with_description(format!(
                "IMAP account: {} on {}",
                // username from imap config — need accessor
                state.imap.host(),
                state.imap.host(),
            ))
            .with_mime_type("application/json")
        })
        .collect();
    Ok(ListResourcesResult::with_all_items(resources))
}
```

Note: the exact rmcp `Resource` constructor and builder methods need to be checked against the rmcp API. The types `Resource`, `ListResourcesResult`, `ReadResourceResult` should be imported from `rmcp::model`.

- [ ] **Step 2: Implement `read_resource`**

```rust
async fn read_resource(
    &self,
    request: ReadResourceRequestParams,
    _context: RequestContext<RoleServer>,
) -> Result<ReadResourceResult, ErrorData> {
    let uri = &request.uri;
    let prefix = "rimap://accounts/";
    let name = uri.strip_prefix(prefix).ok_or_else(|| {
        ErrorData::new(
            McpCode::RESOURCE_NOT_FOUND,
            format!("unknown resource URI: {uri}"),
            None,
        )
    })?;

    let account = self.registry.resolve(Some(name)).map_err(|e| {
        crate::mcp_error::to_mcp_error(&e)
    })?;

    let available_tools: Vec<&str> = account
        .guard
        .matrix()
        .advertised()
        .iter()
        .filter_map(|tn| tool_definition(*tn).map(|_| tn.as_str()))
        .collect();

    let metadata = serde_json::json!({
        "name": account.id.as_str(),
        "imap_host": account.imap.host(),
        "posture": account.guard.matrix().posture().as_str(),
        "smtp_configured": account.smtp.is_some(),
        "available_tools": available_tools,
    });

    let content = ResourceContents::text(
        uri,
        serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?,
        Some("application/json".to_string()),
    );
    Ok(ReadResourceResult::with_contents(vec![content]))
}
```

The exact rmcp types (`ReadResourceRequestParams`, `ResourceContents`, etc.) need to be verified against the rmcp API during implementation.

- [ ] **Step 3: Run `cargo check -p rimap-server`**

Run: `cargo check -p rimap-server`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/server.rs
git commit -m "feat(server): add MCP resource handlers for account discovery"
```

---

## Task 8: Add `account` field to audit records

**Files:**
- Modify: `crates/rimap-audit/src/record.rs`

- [ ] **Step 1: Add `account` field to relevant record types**

Add `#[serde(skip_serializing_if = "Option::is_none")]` so the field is absent for legacy configs:

In `Auth`:
```rust
pub struct Auth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    // ... existing fields ...
}
```

In `ToolStart`:
```rust
pub struct ToolStart {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    // ... existing fields ...
}
```

In `ToolEnd`:
```rust
pub struct ToolEnd {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    // ... existing fields ...
}
```

In `ProcessStart`, replace the singular `posture` field with a conditional structure:
```rust
pub struct ProcessStart {
    // Legacy single-account: flat posture string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    // Multi-account: array of account summaries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<AccountSummary>>,
    // ... remaining existing fields ...
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummary {
    pub name: String,
    pub posture: String,
    pub imap_host: String,
}
```

- [ ] **Step 2: Add `--account` filter to `Filter`**

In `crates/rimap-audit/src/reader.rs`, add to `Filter`:

```rust
pub struct Filter {
    // ... existing fields ...
    pub account: Option<String>,
}
```

Update the filter application logic to check the `account` field on records that have one.

- [ ] **Step 3: Update `ProcessStartInputs` for multi-account**

In `crates/rimap-audit/src/writer.rs`:

```rust
pub struct ProcessStartInputs {
    pub version: String,
    pub git_commit: String,
    /// Single posture for legacy, None for multi-account.
    pub posture: Option<String>,
    /// Account summaries for multi-account, None for legacy.
    pub accounts: Option<Vec<crate::record::AccountSummary>>,
    pub config_path: std::path::PathBuf,
    pub config_hash_sha256: String,
    pub trailing: crate::self_check::TrailingState,
    pub current_inode: u64,
}
```

- [ ] **Step 4: Run `cargo test -p rimap-audit`**

Run: `cargo test -p rimap-audit`
Expected: tests pass. Some tests constructing `ProcessStart` or other records will need the new `account` field set to `None`.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/
git commit -m "feat(audit): add account field to records and --account merge filter"
```

---

## Task 9: Update `main.rs` bootstrap for multi-account

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Replace single-account bootstrap with multi-account**

The bootstrap sequence changes from constructing one `Connection` + one `DispatchGuard` to iterating over `ValidatedMultiConfig.accounts` and building an `AccountState` for each:

```rust
// Replace load_from_path + validate with load_and_validate
let multi_config = rimap_config::loader::load_and_validate(&config_path)?;

// Build audit writer (same as before, using multi_config.audit)
let audit = audit_init::init_audit_writer_multi(&multi_config, &config_path)?;

// Build per-account states
let mut account_states = BTreeMap::new();
for (id, acfg) in &multi_config.accounts {
    let guard = build_dispatch_guard_from_account(acfg)?;
    let conn_cfg = build_connection_config_from_account(acfg);
    let imap = Connection::new(conn_cfg, audit.clone(), credentials.clone());
    let smtp = build_smtp_client(acfg)?;
    let folder_guard = FolderGuard::new(
        &acfg.security.protected_folders,
        &acfg.security.expunge_folders,
    );
    account_states.insert(id.clone(), AccountState {
        id: id.clone(),
        imap,
        smtp,
        guard,
        folder_guard,
    });
}

let registry = AccountRegistry::new(account_states);
let download_dir = resolve_download_dir_multi(&multi_config)?;
let server = ImapMcpServer { registry, audit, download_dir };
```

The helper functions (`build_dispatch_guard_from_account`, `build_connection_config_from_account`, `build_smtp_client`) extract the same logic that currently exists in `build_dispatch_guard` and `build_connection_config`, but take `&ValidatedAccountConfig` instead of `&ValidatedConfig`.

- [ ] **Step 2: Update dry-run mode for multi-account**

The `--dry-run` output should show the effective matrix per account:

```
Account: work
  Posture: full
  Tools: list_folders, search, ...

Account: personal
  Posture: readonly
  Tools: list_folders, search, fetch_message, ...
```

- [ ] **Step 3: Update `ProcessStart` audit record**

Emit the multi-account `ProcessStart` with `accounts` array instead of flat `posture`:

```rust
let accounts = multi_config.accounts.values().map(|acfg| {
    AccountSummary {
        name: acfg.id.as_str().to_string(),
        posture: acfg.security.posture.as_str().to_string(),
        imap_host: acfg.imap.host.clone(),
    }
}).collect();

audit.log_process_start(ProcessStartInputs {
    posture: None,
    accounts: Some(accounts),
    // ... other fields ...
})?;
```

- [ ] **Step 4: Run `cargo check --workspace`**

Run: `cargo check --workspace`
Expected: compiles.

- [ ] **Step 5: Run `just ci`**

Run: `just ci`
Expected: all checks pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "feat(server): multi-account bootstrap with per-account Connection and DispatchGuard"
```

---

## Task 10: Update tests for multi-account

**Files:**
- Modify: `crates/rimap-server/src/e2e_test.rs`
- Modify: `crates/rimap-server/src/server.rs` (tests)

- [ ] **Step 1: Update server unit tests**

The `tool_definition_covers_all_mcp_tools` test needs updating. With 24 total variants (22 posture-matrix + 2 infrastructure), minus 2 sub-capabilities = 22 MCP tools:

```rust
#[test]
fn tool_definition_covers_all_mcp_tools() {
    let defs: Vec<_> = ToolName::all()
        .into_iter()
        .filter_map(tool_definition)
        .collect();
    // 24 tool variants minus 2 sub-capabilities = 22
    assert_eq!(defs.len(), 22);
}
```

Update `sub_capabilities_return_none` — unchanged, `SearchAdvanced` and `FetchMessageHtml` still return `None`.

- [ ] **Step 2: Update e2e tests**

The e2e test helper `call_tool` constructs an `ImapMcpServer` directly. Update it to use the new struct shape with `AccountRegistry`:

```rust
fn test_server(/* ... */) -> ImapMcpServer {
    let id = AccountId::default_account();
    let state = AccountState {
        id: id.clone(),
        imap: /* ... */,
        smtp: None,
        guard: /* ... */,
        folder_guard: /* ... */,
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, state);
    let registry = AccountRegistry::new(accounts);
    ImapMcpServer {
        registry,
        audit: /* ... */,
        download_dir: /* ... */,
    }
}
```

- [ ] **Step 3: Add registry-specific unit tests**

Test account resolution logic:
- Single account auto-selects
- Multi-account with no selection → `NoAccount`
- `set_active` + resolve → correct account
- Unknown account name → `UnknownAccount`
- Explicit param overrides session default

- [ ] **Step 4: Run `just ci`**

Run: `just ci`
Expected: all checks pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/
git commit -m "test(server): update tests for multi-account registry"
```
