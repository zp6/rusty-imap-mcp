//! Test-only helpers that build a real `Connection` against the
//! `DovecotHarness`. Split off from `container.rs` so the harness's
//! container-lifecycle half can be re-exported via `rimap-imap`'s
//! `test-support` feature without dragging the IMAP-connection
//! dependencies (`rimap-audit`, `rimap-config`, `tempfile`) into the
//! library compilation.

#![allow(dead_code)]

use std::sync::Arc;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringCredentialResolver};
use rimap_core::auth_sink::AuthEventSink;
use rimap_core::credential::CredentialResolver;
use rimap_imap::{Connection, ConnectionConfig};
use tempfile::TempDir;

use super::container::{DovecotHarness, HarnessError};

pub struct StaticCreds(pub String);

impl CredentialStore for StaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
        Ok(Some(secrecy::SecretString::from(self.0.clone())))
    }

    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}

pub struct ConnectedHarness {
    pub harness: DovecotHarness,
    pub audit_dir: TempDir,
    pub audit: AuditWriter,
    pub connection: Connection,
}

impl ConnectedHarness {
    /// Build a harness using implicit TLS on port 993. For STARTTLS, call
    /// `new_with_encryption` explicitly.
    pub fn new(pin_with: PinChoice) -> Result<Self, HarnessError> {
        Self::new_with_encryption(pin_with, rimap_imap::ImapEncryption::Tls)
    }

    pub fn new_with_encryption(
        pin_with: PinChoice,
        encryption: rimap_imap::ImapEncryption,
    ) -> Result<Self, HarnessError> {
        let harness = DovecotHarness::try_start()?;
        let audit_dir = TempDir::new().expect("tempdir");
        // `AuditWriter::open` (post-#147) refuses parents with looser modes;
        // `tempfile::TempDir::new()` may inherit 0755 from the system umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(audit_dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod 0700 on audit tempdir");
        }
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

#[derive(Debug, Clone, Copy)]
pub enum PinChoice {
    Correct,
    Wrong,
    None,
}
