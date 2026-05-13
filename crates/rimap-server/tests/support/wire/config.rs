//! Two-account multi-account TOML builder for Phase 3's wire-driven
//! Dovecot e2e. Both accounts target the same Dovecot user
//! (`rimap-test@dovecot`); the surface under test is the posture
//! matrix on the wire, not authentication isolation.

use std::path::Path;

/// Build the multi-account TOML for `e2e_wire.rs`. Caller is
/// responsible for writing the returned string to `config_path` and
/// for placing `audit_path` and `download_dir` inside `allowed_base`.
///
/// `fingerprint_hex` and `port` should be obtained from the
/// `DovecotHarness` at the call site:
/// ```ignore
/// let cfg = build_dovecot_config(
///     &dovecot.fingerprint().to_hex(),
///     dovecot.port(),
///     &audit_path,
///     &allowed_base,
///     &download_dir,
/// );
/// ```
#[expect(dead_code, reason = "Phase 3 e2e_wire.rs will use this")]
pub fn build_dovecot_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "draftsafe"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[[accounts]]
name = "readonly"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "read-only"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}
