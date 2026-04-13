# Sprint 2a: v2 Foundation — Core Types, Config, Authz

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the type system, configuration, and authorization layers to support the six v2 tools and the `destructive` posture, without touching protocol or server code.

**Architecture:** Bottom-up changes across three crates (`rimap-core` → `rimap-config` → `rimap-authz`). Each task produces passing tests before the next begins. The IMAP and server crates are not modified — Sprint 2b/2c handle those.

**Tech Stack:** Rust, serde, strum, governor, thiserror, proptest

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-core/src/tool.rs` | Add 6 `ToolName` variants, remove `V2_TOOL_NAMES` |
| Modify | `crates/rimap-core/src/posture.rs` | Add `Posture::Destructive` |
| Modify | `crates/rimap-core/src/error.rs` | Add `ProtectedFolder` and `ExpungeDenied` error codes |
| Modify | `crates/rimap-config/src/model.rs` | Add `SmtpConfig`, `protected_folders`, `expunge_folders`, `sends_per_minute` |
| Modify | `crates/rimap-config/src/lib.rs` | Re-export `SmtpConfig` |
| Modify | `crates/rimap-config/src/error.rs` | Add `SmtpRequired`, `ConflictingFolders` variants |
| Modify | `crates/rimap-config/src/validate.rs` | Add v2 validation rules |
| Modify | `crates/rimap-authz/src/matrix.rs` | Expand to 19 tools × 4 postures |
| Modify | `crates/rimap-authz/src/rate_limit.rs` | Add `sends` bucket |
| Modify | `crates/rimap-authz/src/error.rs` | Add `ProtectedFolder`, `ExpungeDenied` variants |
| Modify | `crates/rimap-authz/src/guard.rs` | Thread folder guard into dispatch |

---

## Task 1: Add 6 new `ToolName` variants

**Files:**
- Modify: `crates/rimap-core/src/tool.rs`

- [ ] **Step 1: Update tests first — change expected variant count**

In `crates/rimap-core/src/tool.rs`, replace the test `all_has_exactly_thirteen_variants`:

```rust
#[test]
fn all_has_exactly_nineteen_variants() {
    assert_eq!(ToolName::all().len(), 19);
    assert_eq!(ToolName::iter().count(), 19);
}
```

- [ ] **Step 2: Add the `v2_tool_names_return_v2_error` replacement test**

Replace the existing `v2_tool_names_return_v2_error` test with a test that verifies the new tool names parse successfully:

```rust
#[test]
fn v2_tool_names_parse_as_real_variants() {
    for (name, expected) in [
        ("send_email", ToolName::SendEmail),
        ("delete_message", ToolName::DeleteMessage),
        ("expunge", ToolName::Expunge),
        ("create_folder", ToolName::CreateFolder),
        ("rename_folder", ToolName::RenameFolder),
        ("delete_folder", ToolName::DeleteFolder),
    ] {
        let parsed = ToolName::from_str(name).unwrap();
        assert_eq!(parsed, expected);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p rimap-core -- --nocapture 2>&1 | head -40`
Expected: compilation error — `ToolName::SendEmail` does not exist.

- [ ] **Step 4: Add the 6 new variants to `ToolName` enum**

In `crates/rimap-core/src/tool.rs`, add after the `CreateDraft` variant (line 41):

```rust
    /// `send_email` (direct SMTP send, `full` posture).
    SendEmail,
    /// `delete_message` (move to Trash, `full` posture).
    DeleteMessage,
    /// `expunge` (permanently remove `\Deleted` messages, `destructive` posture).
    Expunge,
    /// `create_folder` (IMAP CREATE, `full` posture).
    CreateFolder,
    /// `rename_folder` (IMAP RENAME, `full` posture).
    RenameFolder,
    /// `delete_folder` (IMAP DELETE, `destructive` posture).
    DeleteFolder,
```

- [ ] **Step 5: Add `as_str()` arms for the new variants**

In the `as_str` match block, add after the `Self::CreateDraft` arm:

```rust
            Self::SendEmail => "send_email",
            Self::DeleteMessage => "delete_message",
            Self::Expunge => "expunge",
            Self::CreateFolder => "create_folder",
            Self::RenameFolder => "rename_folder",
            Self::DeleteFolder => "delete_folder",
```

- [ ] **Step 6: Remove `V2_TOOL_NAMES` and `ParseToolNameError::V2`**

Delete the `V2_TOOL_NAMES` constant (line 86) and its doc comment (lines 83-86).

Remove the `V2` variant from `ParseToolNameError`:

```rust
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseToolNameError {
    /// The name is not a recognized tool.
    #[error("unknown tool name `{0}`")]
    Unknown(String),
}
```

In the `FromStr` impl, remove the `V2_TOOL_NAMES` check. The simplified impl:

```rust
impl FromStr for ToolName {
    type Err = ParseToolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for tool in Self::all() {
            if tool.as_str() == s {
                return Ok(tool);
            }
        }
        Err(ParseToolNameError::Unknown(s.to_string()))
    }
}
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p rimap-core -- --nocapture`
Expected: all tests pass. The `v2_tool_names_return_v2_error` test was replaced, all other tests use `ToolName::all()` which now includes the new variants.

- [ ] **Step 8: Fix downstream compilation**

The `ParseToolNameError::V2` removal will break `rimap-config`. Fix `crates/rimap-config/src/error.rs` — the `ToolOverride(#[from] ParseToolNameError)` variant still works, but the test `override_v2_tool_fails_with_v2_error` in `validate.rs` needs updating.

Replace the test in `crates/rimap-config/src/validate.rs`:

```rust
#[test]
fn override_v2_tool_resolves_successfully() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security
        .tools
        .insert("delete_message".into(), Verdict::Allow);
    let v = validate(cfg).unwrap();
    assert_eq!(
        v.tool_overrides.get(&ToolName::DeleteMessage),
        Some(&Verdict::Allow)
    );
}
```

- [ ] **Step 9: Run full workspace build**

Run: `cargo test -p rimap-core -p rimap-config -- --nocapture`
Expected: all tests pass in both crates.

- [ ] **Step 10: Commit**

```bash
git add crates/rimap-core/src/tool.rs crates/rimap-config/src/validate.rs
git commit -m "feat(core): add 6 v2 ToolName variants, remove V2_TOOL_NAMES

SendEmail, DeleteMessage, Expunge, CreateFolder, RenameFolder,
DeleteFolder are now real enum variants. The V2_TOOL_NAMES constant
and ParseToolNameError::V2 are removed."
```

---

## Task 2: Add `Posture::Destructive`

**Files:**
- Modify: `crates/rimap-core/src/posture.rs`

- [ ] **Step 1: Update tests for 4 postures**

In `crates/rimap-core/src/posture.rs`, update `round_trip_all_postures`:

```rust
#[test]
fn round_trip_all_postures() {
    for posture in Posture::all() {
        let s = posture.as_str();
        let parsed = Posture::from_str(s).unwrap();
        assert_eq!(parsed, posture, "round-trip failed for {s}");
    }
}
```

Add a test for the new posture:

```rust
#[test]
fn destructive_parses_and_displays() {
    let p = Posture::from_str("destructive").unwrap();
    assert_eq!(p, Posture::Destructive);
    assert_eq!(p.to_string(), "destructive");
}
```

Update `display_matches_as_str`:

```rust
#[test]
fn display_matches_as_str() {
    assert_eq!(Posture::Readonly.to_string(), "readonly");
    assert_eq!(Posture::DraftSafe.to_string(), "draft-safe");
    assert_eq!(Posture::Full.to_string(), "full");
    assert_eq!(Posture::Destructive.to_string(), "destructive");
}
```

Update `unknown_posture_is_rejected` to include `destructive` in the expected list:

```rust
#[test]
fn unknown_posture_is_rejected() {
    let err = Posture::from_str("yolo").unwrap_err();
    assert_eq!(err, UnknownPosture("yolo".to_string()));
    assert!(err.to_string().contains("yolo"));
    assert!(err.to_string().contains("destructive"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rimap-core posture -- --nocapture 2>&1 | head -30`
Expected: compilation errors — `Posture::Destructive` does not exist.

- [ ] **Step 3: Add `Destructive` variant**

In `crates/rimap-core/src/posture.rs`, add after `Full` (line 19):

```rust
    /// Full permissions plus permanent deletion (`expunge`, `delete_folder`).
    Destructive,
```

- [ ] **Step 4: Update `as_str()`**

Add the new arm:

```rust
            Self::Destructive => "destructive",
```

- [ ] **Step 5: Update `all()`**

Change the return type and body:

```rust
    #[must_use]
    pub fn all() -> [Self; 4] {
        [Self::Readonly, Self::DraftSafe, Self::Full, Self::Destructive]
    }
```

- [ ] **Step 6: Update `FromStr`**

Add the match arm:

```rust
            "destructive" => Ok(Self::Destructive),
```

- [ ] **Step 7: Update `UnknownPosture` error message**

```rust
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown posture `{0}`; expected one of: readonly, draft-safe, full, destructive")]
pub struct UnknownPosture(pub String);
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p rimap-core posture -- --nocapture`
Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-core/src/posture.rs
git commit -m "feat(core): add Posture::Destructive above Full

New posture for permanent deletion operations (expunge,
delete_folder). Hierarchy: readonly < draft-safe < full < destructive."
```

---

## Task 3: Add `ProtectedFolder` and `ExpungeDenied` error codes

**Files:**
- Modify: `crates/rimap-core/src/error.rs`

- [ ] **Step 1: Add test cases for new error codes**

In `crates/rimap-core/src/error.rs`, extend the `every_error_code_has_stable_string` test's `cases` array:

```rust
            (ErrorCode::ProtectedFolder, "ERR_PROTECTED_FOLDER"),
            (ErrorCode::ExpungeDenied, "ERR_EXPUNGE_DENIED"),
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-core error -- --nocapture 2>&1 | head -20`
Expected: compilation error — `ErrorCode::ProtectedFolder` does not exist.

- [ ] **Step 3: Add the new variants**

In the `ErrorCode` enum, add after `AttachmentTooLarge`:

```rust
    /// Operation blocked because the folder is in `protected_folders`.
    ProtectedFolder,
    /// Expunge or delete_folder blocked because folder is not in `expunge_folders`.
    ExpungeDenied,
```

- [ ] **Step 4: Add `as_str()` arms**

```rust
            Self::ProtectedFolder => "ERR_PROTECTED_FOLDER",
            Self::ExpungeDenied => "ERR_EXPUNGE_DENIED",
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-core error -- --nocapture`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-core/src/error.rs
git commit -m "feat(core): add ProtectedFolder and ExpungeDenied error codes

Stable codes for folder safety checks: ERR_PROTECTED_FOLDER for
operations on protected folders, ERR_EXPUNGE_DENIED for folders
not in the expunge allowlist."
```

---

## Task 4: Add `SmtpConfig` and new config fields

**Files:**
- Modify: `crates/rimap-config/src/model.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Add `SmtpConfig` struct**

In `crates/rimap-config/src/model.rs`, add after the `ImapConfig` struct (after line 52):

```rust
/// SMTP encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// STARTTLS upgrade on port 587.
    Starttls,
    /// Implicit TLS on port 465.
    Tls,
    /// No encryption (testing only).
    None,
}

/// `[smtp]` block. Optional — required only when `send_email` is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 465 for implicit TLS).
    pub port: u16,
    /// Encryption mode.
    pub encryption: SmtpEncryption,
    /// SMTP username.
    pub username: String,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}
```

- [ ] **Step 2: Add `smtp` field to `Config`**

In the `Config` struct, add after the `imap` field:

```rust
    /// SMTP connection settings (optional — required when `send_email` is enabled).
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
```

- [ ] **Step 3: Add `protected_folders` and `expunge_folders` to `SecurityConfig`**

In the `SecurityConfig` struct, add after the `tools` field:

```rust
    /// Folders that cannot be deleted or renamed. Case-insensitive matching.
    /// Default: `["INBOX", "Sent", "Drafts", "Trash"]`.
    #[serde(default = "default_protected_folders")]
    pub protected_folders: Vec<String>,
    /// Folders where `expunge` and `delete_folder` are permitted.
    /// Default: empty (deny all).
    #[serde(default)]
    pub expunge_folders: Vec<String>,
```

Add the default function:

```rust
fn default_protected_folders() -> Vec<String> {
    vec![
        "INBOX".to_string(),
        "Sent".to_string(),
        "Drafts".to_string(),
        "Trash".to_string(),
    ]
}
```

Update the `Default` impl for `SecurityConfig` — currently it uses `#[derive(Default)]` via `#[serde(default)]` on the struct. Since we added `protected_folders` with a custom default, we need a manual `Default` impl. Replace `#[derive(Debug, Clone, Default, Serialize, Deserialize)]` with `#[derive(Debug, Clone, Serialize, Deserialize)]` and add:

```rust
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            posture: Posture::default(),
            tools: BTreeMap::new(),
            lookalike: LookalikeConfig::default(),
            protected_folders: default_protected_folders(),
            expunge_folders: Vec::new(),
        }
    }
}
```

- [ ] **Step 4: Add `sends_per_minute` to `LimitsConfig`**

In the `LimitsConfig` struct, add after `drafts_per_minute`:

```rust
    /// Per-minute email send cap.
    #[serde(default = "default_sends_per_min")]
    pub sends_per_minute: u32,
```

Add the default function:

```rust
fn default_sends_per_min() -> u32 {
    3
}
```

Update `LimitsConfig::default()` to include `sends_per_minute: default_sends_per_min()`.

- [ ] **Step 5: Re-export `SmtpConfig` and `SmtpEncryption` from `lib.rs`**

In `crates/rimap-config/src/lib.rs`, update the `model` re-export line:

```rust
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, SmtpConfig, SmtpEncryption, Verdict,
};
```

- [ ] **Step 6: Run build to verify compilation**

Run: `cargo build -p rimap-config 2>&1 | head -30`
Expected: compiles cleanly. Some downstream crates may have test breakage from the `SecurityConfig::default()` change — fix in the next step.

- [ ] **Step 7: Fix downstream test `base_config` helpers**

The `base_config` helper in `crates/rimap-config/src/validate.rs` constructs `SecurityConfig::default()` which now includes `protected_folders`. This should just work since `Default` is implemented. Verify:

Run: `cargo test -p rimap-config -- --nocapture`
Expected: all existing tests pass.

- [ ] **Step 8: Add a TOML round-trip test for `SmtpConfig`**

Add to `crates/rimap-config/src/validate.rs` tests:

```rust
#[test]
fn smtp_section_parses_from_toml() {
    let toml_str = r#"
[imap]
host = "imap.example.com"
port = 993
username = "alice@example.com"

[smtp]
host = "smtp.example.com"
port = 587
encryption = "starttls"
username = "alice@example.com"

[audit]
path = "/tmp/audit.jsonl"
"#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    let smtp = cfg.smtp.as_ref().unwrap();
    assert_eq!(smtp.host, "smtp.example.com");
    assert_eq!(smtp.port, 587);
    assert_eq!(smtp.encryption, SmtpEncryption::Starttls);
}
```

Add the import at the top of the test module:

```rust
use crate::model::SmtpEncryption;
```

- [ ] **Step 9: Add a test that config without `[smtp]` is valid**

```rust
#[test]
fn config_without_smtp_section_is_valid() {
    let dir = TempDir::new().unwrap();
    let cfg = base_config(dir.path());
    assert!(cfg.smtp.is_none());
    validate(cfg).unwrap();
}
```

- [ ] **Step 10: Run tests**

Run: `cargo test -p rimap-config -- --nocapture`
Expected: all tests pass.

- [ ] **Step 11: Commit**

```bash
git add crates/rimap-config/src/model.rs crates/rimap-config/src/lib.rs crates/rimap-config/src/validate.rs
git commit -m "feat(config): add SmtpConfig, protected_folders, expunge_folders, sends_per_minute

Optional [smtp] section for SMTP connection settings.
protected_folders defaults to [INBOX, Sent, Drafts, Trash].
expunge_folders defaults to empty (deny all).
sends_per_minute defaults to 3."
```

---

## Task 5: Add v2 config validation rules

**Files:**
- Modify: `crates/rimap-config/src/error.rs`
- Modify: `crates/rimap-config/src/validate.rs`

- [ ] **Step 1: Add `SmtpRequired` and `ConflictingFolders` error variants**

In `crates/rimap-config/src/error.rs`, add after the `NoCredential` variant:

```rust
    /// `send_email` is effectively enabled but no `[smtp]` section is configured.
    #[error(
        "send_email is enabled (posture = {posture}) but no [smtp] section \
         is configured; add [smtp] or deny send_email via \
         [security.tools] send_email = \"deny\""
    )]
    SmtpRequired {
        /// The posture that enabled send_email.
        posture: String,
    },
    /// A folder appears in both `protected_folders` and `expunge_folders`.
    #[error(
        "folder `{folder}` is in both protected_folders and expunge_folders; \
         a folder cannot be both protected and expungeable"
    )]
    ConflictingFolders {
        /// The conflicting folder name.
        folder: String,
    },
```

- [ ] **Step 2: Write tests for the new validation rules**

In `crates/rimap-config/src/validate.rs` test module:

```rust
#[test]
fn smtp_required_when_send_email_enabled_by_posture() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security.posture = Posture::Full;
    // No [smtp] section, no explicit deny on send_email → error
    let err = validate(cfg).unwrap_err();
    assert!(matches!(err, ConfigError::SmtpRequired { .. }));
}

#[test]
fn smtp_not_required_when_send_email_explicitly_denied() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security.posture = Posture::Full;
    cfg.security
        .tools
        .insert("send_email".into(), Verdict::Deny);
    // send_email denied → no SmtpRequired error
    validate(cfg).unwrap();
}

#[test]
fn smtp_not_required_for_draft_safe_posture() {
    let dir = TempDir::new().unwrap();
    let cfg = base_config(dir.path());
    // Default posture is draft-safe → send_email not enabled
    validate(cfg).unwrap();
}

#[test]
fn conflicting_folders_fails() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security.protected_folders = vec!["Trash".into()];
    cfg.security.expunge_folders = vec!["Trash".into()];
    let err = validate(cfg).unwrap_err();
    assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
}

#[test]
fn non_overlapping_folders_passes() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security.protected_folders = vec!["INBOX".into(), "Sent".into()];
    cfg.security.expunge_folders = vec!["Trash".into()];
    validate(cfg).unwrap();
}

#[test]
fn conflicting_folders_case_insensitive() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.security.protected_folders = vec!["trash".into()];
    cfg.security.expunge_folders = vec!["Trash".into()];
    let err = validate(cfg).unwrap_err();
    assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
}

#[test]
fn zero_sends_per_minute_fails() {
    let dir = TempDir::new().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.limits.sends_per_minute = 0;
    assert!(matches!(
        validate(cfg).unwrap_err(),
        ConfigError::InvalidLimit {
            field: "limits.sends_per_minute",
            ..
        }
    ));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p rimap-config -- --nocapture 2>&1 | head -30`
Expected: compilation errors for `ConfigError::SmtpRequired` etc., then test failures.

- [ ] **Step 4: Add `validate_sends_per_minute` check**

In `crates/rimap-config/src/validate.rs`, add to the `validate_limits` function after the `max_append_bytes` check:

```rust
    if limits.sends_per_minute == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.sends_per_minute",
            reason: "must be > 0".to_string(),
        });
    }
```

- [ ] **Step 5: Add `validate_folder_safety` function**

In `crates/rimap-config/src/validate.rs`:

```rust
fn validate_folder_safety(config: &Config) -> Result<(), ConfigError> {
    let protected: Vec<String> = config
        .security
        .protected_folders
        .iter()
        .map(|f| f.to_lowercase())
        .collect();
    for folder in &config.security.expunge_folders {
        if protected.contains(&folder.to_lowercase()) {
            return Err(ConfigError::ConflictingFolders {
                folder: folder.clone(),
            });
        }
    }
    Ok(())
}
```

- [ ] **Step 6: Add `validate_smtp_required` function**

In `crates/rimap-config/src/validate.rs`:

```rust
fn validate_smtp_required(
    config: &Config,
    tool_overrides: &BTreeMap<ToolName, Verdict>,
) -> Result<(), ConfigError> {
    use rimap_core::posture::Posture;

    let posture = config.security.posture;
    let send_email_base = matches!(posture, Posture::Full | Posture::Destructive);
    let send_email_effective = match tool_overrides.get(&ToolName::SendEmail) {
        Some(Verdict::Allow) => true,
        Some(Verdict::Deny) => false,
        None => send_email_base,
    };
    if send_email_effective && config.smtp.is_none() {
        return Err(ConfigError::SmtpRequired {
            posture: posture.to_string(),
        });
    }
    Ok(())
}
```

- [ ] **Step 7: Wire new validations into the `validate` function**

Update the `validate` function to call the new validators. Add `validate_folder_safety` before `resolve_tool_overrides`, and `validate_smtp_required` after it (since it needs the resolved overrides):

```rust
pub fn validate(config: Config) -> Result<ValidatedConfig, ConfigError> {
    let tls_fingerprint = parse_fingerprint(config.imap.tls_fingerprint_sha256.as_deref())?;
    validate_limits(&config)?;
    validate_audit(&config)?;
    validate_paths(&config)?;
    validate_folder_safety(&config)?;
    let tool_overrides = resolve_tool_overrides(&config)?;
    validate_smtp_required(&config, &tool_overrides)?;
    Ok(ValidatedConfig {
        config,
        tool_overrides,
        tls_fingerprint,
    })
}
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p rimap-config -- --nocapture`
Expected: all tests pass, including the 7 new validation tests.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-config/src/error.rs crates/rimap-config/src/validate.rs
git commit -m "feat(config): add SmtpRequired, ConflictingFolders, and sends_per_minute validation

Startup error if send_email is enabled without [smtp] config.
Startup error if a folder is in both protected_folders and
expunge_folders. Zero sends_per_minute is rejected."
```

---

## Task 6: Expand posture matrix to 19 tools × 4 postures

**Files:**
- Modify: `crates/rimap-authz/src/matrix.rs`

- [ ] **Step 1: Update `POSTURE_MATRIX` const**

Replace the entire `POSTURE_MATRIX` const:

```rust
/// Compile-time truth table. `true` = allowed by base posture.
///
/// Layout: outer by [`ToolName`] (19 tools), inner `[readonly, draft_safe, full, destructive]`.
pub(crate) const POSTURE_MATRIX: [(ToolName, [bool; 4]); 19] = [
    (ToolName::ListFolders,       [true,  true,  true,  true]),
    (ToolName::Search,            [true,  true,  true,  true]),
    (ToolName::SearchAdvanced,    [false, false, true,  true]),
    (ToolName::FetchMessage,      [true,  true,  true,  true]),
    (ToolName::FetchMessageHtml,  [false, false, true,  true]),
    (ToolName::ListAttachments,   [true,  true,  true,  true]),
    (ToolName::DownloadAttachment,[true,  true,  true,  true]),
    (ToolName::MarkRead,          [false, true,  true,  true]),
    (ToolName::MarkUnread,        [false, true,  true,  true]),
    (ToolName::Flag,              [false, true,  true,  true]),
    (ToolName::Unflag,            [false, true,  true,  true]),
    (ToolName::MoveMessage,       [false, true,  true,  true]),
    (ToolName::CreateDraft,       [false, true,  true,  true]),
    // v2 tools:
    (ToolName::SendEmail,         [false, false, true,  true]),
    (ToolName::DeleteMessage,     [false, false, true,  true]),
    (ToolName::CreateFolder,      [false, false, true,  true]),
    (ToolName::RenameFolder,      [false, false, true,  true]),
    (ToolName::Expunge,           [false, false, false, true]),
    (ToolName::DeleteFolder,      [false, false, false, true]),
];
```

- [ ] **Step 2: Update `posture_index`**

```rust
fn posture_index(p: Posture) -> usize {
    match p {
        Posture::Readonly => 0,
        Posture::DraftSafe => 1,
        Posture::Full => 2,
        Posture::Destructive => 3,
    }
}
```

- [ ] **Step 3: Update tests**

Replace `base_readonly_row_matches_spec`:

```rust
#[test]
fn base_readonly_row_matches_spec() {
    for t in [
        ToolName::ListFolders,
        ToolName::Search,
        ToolName::FetchMessage,
        ToolName::ListAttachments,
        ToolName::DownloadAttachment,
    ] {
        assert!(base_allows(Posture::Readonly, t), "{t} should be allowed");
    }
    for t in [
        ToolName::SearchAdvanced,
        ToolName::FetchMessageHtml,
        ToolName::MarkRead,
        ToolName::MarkUnread,
        ToolName::Flag,
        ToolName::Unflag,
        ToolName::MoveMessage,
        ToolName::CreateDraft,
        ToolName::SendEmail,
        ToolName::DeleteMessage,
        ToolName::Expunge,
        ToolName::CreateFolder,
        ToolName::RenameFolder,
        ToolName::DeleteFolder,
    ] {
        assert!(!base_allows(Posture::Readonly, t), "{t} should be denied");
    }
}
```

Replace `base_draft_safe_row_matches_spec`:

```rust
#[test]
fn base_draft_safe_row_matches_spec() {
    let denied = [
        ToolName::SearchAdvanced,
        ToolName::FetchMessageHtml,
        ToolName::SendEmail,
        ToolName::DeleteMessage,
        ToolName::Expunge,
        ToolName::CreateFolder,
        ToolName::RenameFolder,
        ToolName::DeleteFolder,
    ];
    for t in &denied {
        assert!(!base_allows(Posture::DraftSafe, *t), "{t} expected denied");
    }
    for t in ToolName::all() {
        if denied.contains(&t) {
            continue;
        }
        assert!(base_allows(Posture::DraftSafe, t), "{t} expected allowed");
    }
}
```

Replace `base_full_row_allows_everything`:

```rust
#[test]
fn base_full_allows_except_destructive() {
    let denied = [ToolName::Expunge, ToolName::DeleteFolder];
    for t in ToolName::all() {
        if denied.contains(&t) {
            assert!(!base_allows(Posture::Full, t), "{t} expected denied at full");
        } else {
            assert!(base_allows(Posture::Full, t), "{t} expected allowed at full");
        }
    }
}
```

Add a test for the destructive posture:

```rust
#[test]
fn base_destructive_allows_everything() {
    for t in ToolName::all() {
        assert!(
            base_allows(Posture::Destructive, t),
            "destructive should allow {t}"
        );
    }
}
```

Update `exhaustive_posture_times_tool_lookup_is_stable` — no code change needed, it already iterates `Posture::all()` and `ToolName::all()`.

Update `advertised_matches_allowed_set_in_order` to remain unchanged (it tests Readonly which is the same).

Update `rows_iterates_every_tool`:

```rust
#[test]
fn rows_iterates_every_tool() {
    let m = EffectiveMatrix::build(Posture::Destructive, &BTreeMap::new());
    let rows: Vec<_> = m.rows().collect();
    assert_eq!(rows.len(), ToolName::all().len());
    assert!(rows.iter().all(|(_, allowed)| *allowed));
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-authz matrix -- --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/matrix.rs
git commit -m "feat(authz): expand posture matrix to 19 tools × 4 postures

v2 tools: SendEmail, DeleteMessage, CreateFolder, RenameFolder
at full+. Expunge and DeleteFolder at destructive only."
```

---

## Task 7: Add `sends` rate limiter bucket

**Files:**
- Modify: `crates/rimap-authz/src/rate_limit.rs`

- [ ] **Step 1: Add test for sends bucket**

In `crates/rimap-authz/src/rate_limit.rs` tests:

```rust
#[test]
fn sends_bucket_is_separate() {
    let g = Governor::new(1000, 5, 3).unwrap();
    for _ in 0..3 {
        let _ = g.check(ToolName::SendEmail);
    }
    let send_err = g.check(ToolName::SendEmail).unwrap_err();
    assert!(matches!(send_err, AuthzError::RateLimited { .. }));
    // Other tools still work
    assert!(g.check(ToolName::Search).is_ok());
}

#[test]
fn zero_sends_per_minute_rejected_at_build() {
    assert!(Governor::new(10, 5, 0).is_err());
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p rimap-authz rate_limit -- --nocapture 2>&1 | head -20`
Expected: compilation error — `Governor::new` takes 2 args, not 3.

- [ ] **Step 3: Add `sends` bucket to `Governor`**

Update the struct:

```rust
pub struct Governor {
    global: DirectLimiter,
    drafts: DirectLimiter,
    sends: DirectLimiter,
    clock: DefaultClock,
}
```

Update the constructor:

```rust
    pub fn new(
        commands_per_second: u32,
        drafts_per_minute: u32,
        sends_per_minute: u32,
    ) -> Result<Self, AuthzError> {
        let cps = NonZeroU32::new(commands_per_second).ok_or_else(|| {
            AuthzError::MatrixBuild("commands_per_second must be > 0".to_string())
        })?;
        let dpm = NonZeroU32::new(drafts_per_minute)
            .ok_or_else(|| AuthzError::MatrixBuild("drafts_per_minute must be > 0".to_string()))?;
        let spm = NonZeroU32::new(sends_per_minute)
            .ok_or_else(|| AuthzError::MatrixBuild("sends_per_minute must be > 0".to_string()))?;
        let burst = NonZeroU32::new(commands_per_second.saturating_mul(2).max(1))
            .unwrap_or(NonZeroU32::MIN);
        let global_quota = Quota::per_second(cps).allow_burst(burst);
        let draft_quota = Quota::per_minute(dpm);
        let send_quota = Quota::per_minute(spm);
        Ok(Self {
            global: RateLimiter::direct(global_quota),
            drafts: RateLimiter::direct(draft_quota),
            sends: RateLimiter::direct(send_quota),
            clock: DefaultClock::default(),
        })
    }
```

Update the `check` method:

```rust
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.global.check().map_err(|nu| AuthzError::RateLimited {
            retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                .unwrap_or(u64::MAX),
        })?;
        if matches!(tool, ToolName::CreateDraft) {
            self.drafts.check().map_err(|nu| AuthzError::RateLimited {
                retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                    .unwrap_or(u64::MAX),
            })?;
        }
        if matches!(tool, ToolName::SendEmail) {
            self.sends.check().map_err(|nu| AuthzError::RateLimited {
                retry_after_ms: u64::try_from(nu.wait_time_from(self.clock.now()).as_millis())
                    .unwrap_or(u64::MAX),
            })?;
        }
        Ok(())
    }
```

- [ ] **Step 4: Fix existing tests and callers**

All existing `Governor::new(x, y)` calls need a third argument. Update in `rate_limit.rs` tests:

- `Governor::new(0, 5)` → `Governor::new(0, 5, 3)`
- `Governor::new(10, 0)` → `Governor::new(10, 0, 3)`
- `Governor::new(10, 5)` → `Governor::new(10, 5, 3)`
- `Governor::new(2, 5)` → `Governor::new(2, 5, 3)`
- `Governor::new(1000, 5)` → `Governor::new(1000, 5, 3)`
- `Governor::new(cps, 1)` → `Governor::new(cps, 1, 3)` (in proptest)

Update in `guard.rs` tests:

- `Governor::new(100, 5)` → `Governor::new(100, 5, 3)`

Find and update all other callers in the workspace:

Run: `grep -r 'Governor::new(' crates/ --include='*.rs'`

Update each call site to pass the third argument. The server's `main.rs` or bootstrap code will pass `config.limits.sends_per_minute`.

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-authz -- --nocapture`
Expected: all tests pass including the 2 new ones.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-authz/src/rate_limit.rs crates/rimap-authz/src/guard.rs
git commit -m "feat(authz): add sends_per_minute rate limiter bucket

Separate bucket for SendEmail, same pattern as the existing
drafts_per_minute bucket. Default 3 sends/min."
```

---

## Task 8: Add folder safety checks to `rimap-authz`

**Files:**
- Modify: `crates/rimap-authz/src/error.rs`
- Create: `crates/rimap-authz/src/folder_guard.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Add `ProtectedFolder` and `ExpungeDenied` to `AuthzError`**

In `crates/rimap-authz/src/error.rs`, add after `MatrixBuild`:

```rust
    /// Folder is in the `protected_folders` list.
    #[error(
        "folder `{folder}` is protected and cannot be {operation}d; \
         remove it from protected_folders to allow this"
    )]
    ProtectedFolder {
        /// The folder name.
        folder: String,
        /// "delete" or "rename".
        operation: &'static str,
    },
    /// Folder is not in the `expunge_folders` allowlist.
    #[error(
        "expunge denied for folder `{folder}`; add it to expunge_folders \
         in your config to allow permanent deletion"
    )]
    ExpungeDenied {
        /// The folder name.
        folder: String,
    },
```

Update the `code()` method:

```rust
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PostureDenied(_) => ErrorCode::PostureDenied,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::MatrixBuild(_) => ErrorCode::Config,
            Self::ProtectedFolder { .. } => ErrorCode::ProtectedFolder,
            Self::ExpungeDenied { .. } => ErrorCode::ExpungeDenied,
        }
    }
```

Update the test in `error.rs`:

```rust
#[test]
fn error_codes_match_spec() {
    assert_eq!(
        AuthzError::PostureDenied(ToolName::CreateDraft).code(),
        ErrorCode::PostureDenied
    );
    assert_eq!(
        AuthzError::RateLimited {
            retry_after_ms: 250
        }
        .code(),
        ErrorCode::RateLimited
    );
    assert_eq!(
        AuthzError::CircuitOpen {
            retry_after_ms: 15_000
        }
        .code(),
        ErrorCode::CircuitOpen
    );
    assert_eq!(
        AuthzError::MatrixBuild("x".into()).code(),
        ErrorCode::Config
    );
    assert_eq!(
        AuthzError::ProtectedFolder {
            folder: "INBOX".into(),
            operation: "delete",
        }
        .code(),
        ErrorCode::ProtectedFolder
    );
    assert_eq!(
        AuthzError::ExpungeDenied {
            folder: "Sent".into(),
        }
        .code(),
        ErrorCode::ExpungeDenied
    );
}
```

- [ ] **Step 2: Create `folder_guard.rs`**

Create `crates/rimap-authz/src/folder_guard.rs`:

```rust
//! Folder safety checks: protected folders and expunge allowlist.
//!
//! Defence-in-depth for destructive folder operations. The posture matrix
//! gates the tool itself; the folder guard gates which folders the tool
//! can act on.

use crate::error::AuthzError;

/// Runtime folder safety guard built from config.
#[derive(Debug, Clone)]
pub struct FolderGuard {
    /// Lowercased protected folder names.
    protected: Vec<String>,
    /// Lowercased expunge-allowed folder names.
    expunge_allowed: Vec<String>,
}

impl FolderGuard {
    /// Build from config values. Both lists are lowercased for
    /// case-insensitive matching.
    #[must_use]
    pub fn new(protected_folders: &[String], expunge_folders: &[String]) -> Self {
        Self {
            protected: protected_folders.iter().map(|f| f.to_lowercase()).collect(),
            expunge_allowed: expunge_folders.iter().map(|f| f.to_lowercase()).collect(),
        }
    }

    /// Check whether `folder` can be deleted or renamed. INBOX is always
    /// rejected regardless of configuration.
    ///
    /// # Errors
    /// Returns `AuthzError::ProtectedFolder` if the folder is protected.
    pub fn check_protected(
        &self,
        folder: &str,
        operation: &'static str,
    ) -> Result<(), AuthzError> {
        let lower = folder.to_lowercase();
        if lower == "inbox" || self.protected.contains(&lower) {
            return Err(AuthzError::ProtectedFolder {
                folder: folder.to_string(),
                operation,
            });
        }
        Ok(())
    }

    /// Check whether `folder` is in the expunge allowlist.
    ///
    /// # Errors
    /// Returns `AuthzError::ExpungeDenied` if the folder is not allowed.
    pub fn check_expunge(&self, folder: &str) -> Result<(), AuthzError> {
        let lower = folder.to_lowercase();
        if !self.expunge_allowed.contains(&lower) {
            return Err(AuthzError::ExpungeDenied {
                folder: folder.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FolderGuard;
    use crate::error::AuthzError;

    fn guard() -> FolderGuard {
        FolderGuard::new(
            &["INBOX".into(), "Sent".into(), "Drafts".into(), "Trash".into()],
            &["Trash".into()],
        )
    }

    #[test]
    fn inbox_always_protected_even_if_not_in_list() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_protected("INBOX", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("inbox", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("Inbox", "rename"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn protected_folder_rejected_case_insensitive() {
        let g = guard();
        assert!(matches!(
            g.check_protected("sent", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("SENT", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn unprotected_folder_allowed() {
        let g = guard();
        assert!(g.check_protected("Archives", "delete").is_ok());
        assert!(g.check_protected("Old Mail", "rename").is_ok());
    }

    #[test]
    fn expunge_allowed_for_listed_folder() {
        let g = guard();
        assert!(g.check_expunge("Trash").is_ok());
        assert!(g.check_expunge("trash").is_ok());
        assert!(g.check_expunge("TRASH").is_ok());
    }

    #[test]
    fn expunge_denied_for_unlisted_folder() {
        let g = guard();
        assert!(matches!(
            g.check_expunge("INBOX"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
        assert!(matches!(
            g.check_expunge("Sent"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn empty_expunge_list_denies_everything() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_expunge("Trash"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }
}
```

- [ ] **Step 3: Register `folder_guard` module in `lib.rs`**

In `crates/rimap-authz/src/lib.rs`, add the module declaration and re-export:

```rust
pub mod folder_guard;
```

Add to the re-exports:

```rust
pub use crate::folder_guard::FolderGuard;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-authz -- --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/error.rs crates/rimap-authz/src/folder_guard.rs crates/rimap-authz/src/lib.rs
git commit -m "feat(authz): add FolderGuard for protected_folders and expunge_folders

INBOX is hardcoded as always protected. Protected folders reject
delete and rename. Expunge allowlist gates expunge and delete_folder.
Case-insensitive matching on all checks."
```

---

## Task 9: Wire `FolderGuard` into server bootstrap

**Files:**
- Modify: `crates/rimap-server/src/server.rs`

This task adds the `FolderGuard` field to `ImapMcpServer` so Sprint 2c can use it in tool handlers. No behavioral change yet — just threading the config through.

- [ ] **Step 1: Add `FolderGuard` field to `ImapMcpServer`**

In `crates/rimap-server/src/server.rs`, add to the struct:

```rust
    /// Folder safety guard (protected folders + expunge allowlist).
    pub(crate) folder_guard: rimap_authz::FolderGuard,
```

- [ ] **Step 2: Update server construction**

Find where `ImapMcpServer` is constructed (likely in `main.rs` or a bootstrap function). Add `FolderGuard::new` from the validated config's `protected_folders` and `expunge_folders`.

Run: `grep -r 'ImapMcpServer {' crates/rimap-server/ --include='*.rs' -n` to find the construction site.

At the construction site, add:

```rust
folder_guard: rimap_authz::FolderGuard::new(
    &config.config.security.protected_folders,
    &config.config.security.expunge_folders,
),
```

- [ ] **Step 3: Run build**

Run: `cargo build -p rimap-server 2>&1 | head -20`
Expected: compiles. If there are other construction sites, fix them the same way.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace -- --nocapture 2>&1 | tail -30`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/server.rs
git commit -m "feat(server): thread FolderGuard into ImapMcpServer

Wire protected_folders and expunge_folders config into the server
struct for Sprint 2c tool handlers to use."
```

---

## Task 10: Final verification and lint

- [ ] **Step 1: Run full CI locally**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: no formatting issues, no clippy warnings, all tests pass.

- [ ] **Step 2: Fix any issues**

Address any clippy warnings or test failures discovered in Step 1.

- [ ] **Step 3: Run cargo deny**

Run: `cargo deny check 2>&1 | tail -20`
Expected: no new advisories or license issues (no new dependencies added in this sprint).

- [ ] **Step 4: Commit any fixes**

If Step 2 required changes:

```bash
git add -u
git commit -m "fix: address clippy warnings from Sprint 2a changes"
```
