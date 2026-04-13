//! Dovecot e2e smoke test: exercises the full MCP tool chain against
//! a real Dovecot IMAP server running in a container.
//!
//! Skips silently when no container runtime is available or the host
//! architecture is not `x86_64` (dovecot image is amd64-only).

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::CredentialStore;
use rimap_config::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, SecurityConfig,
};
use rimap_config::validate::ValidatedConfig;
use rimap_core::TlsFingerprint;
use rimap_core::posture::Posture;
use rimap_imap::{Connection, ConnectionConfig};
use tempfile::TempDir;

use crate::server::ImapMcpServer;

// ── Container harness (adapted from rimap-imap) ─────────────────────

fn runtime() -> &'static str {
    static TOOL: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    TOOL.get_or_init(|| {
        match std::env::var("RIMAP_CONTAINER_TOOL").as_deref() {
            Ok("docker") => return "docker",
            Ok("podman") => return "podman",
            _ => {}
        }
        if binary_present("docker") {
            "docker"
        } else if binary_present("podman") {
            "podman"
        } else {
            "docker"
        }
    })
}

fn binary_present(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn runtime_available() -> bool {
    binary_present("docker") || binary_present("podman")
}

fn container_name(project: &str) -> String {
    format!("{project}-dovecot")
}

struct DovecotHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    port: u16,
}

impl DovecotHarness {
    fn try_start() -> Option<Self> {
        if std::env::consts::ARCH != "x86_64" {
            return None;
        }
        if !runtime_available() {
            return None;
        }

        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("rimap-imap")
            .join("tests")
            .join("integration")
            .join("dovecot");

        let project = format!(
            "rimap-e2e-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let host_port = pick_free_port()?;

        let status = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(&project)
            .arg("up")
            .arg("-d")
            .env("RIMAP_DOVECOT_HOST_PORT", host_port.to_string())
            .current_dir(&compose_dir)
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }

        wait_for_ready(&project, host_port, &compose_dir)
    }

    /// Create a mailbox via `doveadm` inside the container.
    fn create_mailbox(&self, name: &str) {
        let status = Command::new(runtime())
            .arg("exec")
            .arg(container_name(&self.project))
            .arg("doveadm")
            .arg("mailbox")
            .arg("create")
            .arg("-u")
            .arg("rimap-test")
            .arg(name)
            .status()
            .expect("doveadm exec failed");
        assert!(status.success(), "doveadm mailbox create {name} failed",);
    }
}

fn wait_for_ready(
    project: &str,
    host_port: u16,
    compose_dir: &std::path::Path,
) -> Option<DovecotHarness> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], host_port));
    loop {
        if started.elapsed() > timeout {
            compose_down(project, compose_dir);
            return None;
        }
        let Ok(fp) = read_fingerprint(project) else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return Some(DovecotHarness {
                project: project.to_string(),
                compose_dir: compose_dir.to_path_buf(),
                fingerprint: fp,
                port: host_port,
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

impl Drop for DovecotHarness {
    fn drop(&mut self) {
        compose_down(&self.project, &self.compose_dir);
    }
}

fn compose_down(project: &str, compose_dir: &std::path::Path) {
    let _ = Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("down")
        .arg("-v")
        .arg("--remove-orphans")
        .current_dir(compose_dir)
        .status();
}

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, String> {
    let out = Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
        .arg("cat")
        .arg("/shared/fingerprint.hex")
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("not ready".into());
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    TlsFingerprint::from_hex(&s).map_err(|e| e.to_string())
}

fn pick_free_port() -> Option<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    Some(listener.local_addr().ok()?.port())
}

struct StaticCreds(String);

impl CredentialStore for StaticCreds {
    fn get_password(&self, _account: &str) -> Result<Option<String>, rimap_config::ConfigError> {
        Ok(Some(self.0.clone()))
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

// ── Server builder ──────────────────────────────────────────────────

struct TestEnv {
    _harness: DovecotHarness,
    _audit_dir: TempDir,
    _download_dir: TempDir,
    server: ImapMcpServer,
}

fn build_test_env(harness: DovecotHarness) -> TestEnv {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let download_dir = TempDir::new().expect("download tempdir");

    let audit = AuditWriter::open(&AuditOptions {
        path: audit_dir.path().join("audit.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("audit open");

    let config = test_config(&harness, &audit_dir);
    let imap = test_connection(&harness, &audit);
    let guard = test_guard(&config);
    let folder_guard = rimap_authz::FolderGuard::new(
        &config.config.security.protected_folders,
        &config.config.security.expunge_folders,
    );
    let from_address = config.config.imap.username.clone();

    let id = rimap_core::account::AccountId::default_account();
    let state = crate::registry::AccountState {
        id: id.clone(),
        from_address,
        imap,
        smtp: None,
        guard,
        folder_guard,
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, state);
    let registry = crate::registry::AccountRegistry::new(accounts);

    let server = ImapMcpServer {
        registry,
        audit,
        download_dir: download_dir.path().to_path_buf(),
    };

    TestEnv {
        _harness: harness,
        _audit_dir: audit_dir,
        _download_dir: download_dir,
        server,
    }
}

fn test_config(harness: &DovecotHarness, audit_dir: &TempDir) -> ValidatedConfig {
    ValidatedConfig {
        config: Config {
            imap: ImapConfig {
                host: "127.0.0.1".into(),
                port: harness.port,
                username: "rimap-test".into(),
                tls_fingerprint_sha256: None,
                connect_timeout_seconds: 10,
                command_timeout_seconds: 30,
            },
            smtp: None,
            security: SecurityConfig {
                posture: Posture::DraftSafe,
                ..SecurityConfig::default()
            },
            limits: LimitsConfig::default(),
            audit: AuditConfig {
                path: audit_dir.path().join("audit.jsonl"),
                rotate_bytes: 0,
                rotate_keep: 0,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: Some(audit_dir.path().to_path_buf()),
            },
            attachments: AttachmentsConfig::default(),
        },
        tool_overrides: BTreeMap::new(),
        tls_fingerprint: Some(harness.fingerprint),
    }
}

fn test_connection(harness: &DovecotHarness, audit: &AuditWriter) -> Connection {
    let conn_cfg = ConnectionConfig {
        host: "127.0.0.1".into(),
        port: harness.port,
        username: "rimap-test".into(),
        pinned_fingerprint: Some(harness.fingerprint),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(StaticCreds("testpass".into()));
    Connection::new(conn_cfg, audit.clone(), creds)
}

fn test_guard(config: &ValidatedConfig) -> DispatchGuard<SystemClock> {
    let matrix = EffectiveMatrix::from_validated(config);
    let breaker = CircuitBreaker::new(SystemClock::new(), BreakerConfig::default_spec());
    let governor = Governor::new(
        config.config.limits.commands_per_second,
        config.config.limits.drafts_per_minute,
        config.config.limits.sends_per_minute,
    )
    .expect("governor");
    DispatchGuard::new(matrix, breaker, governor)
}

// ── Tool dispatch helper ────────────────────────────────────────────

async fn call_tool(
    server: &ImapMcpServer,
    tool_name: &str,
    args: serde_json::Value,
) -> Result<crate::response::ToolResponse, rimap_core::RimapError> {
    let tool = std::str::FromStr::from_str(tool_name).map_err(
        |e: rimap_core::tool::ParseToolNameError| rimap_core::RimapError::Internal(e.to_string()),
    )?;

    let account = server.registry.resolve(None)?;

    crate::dispatch::pre_call_guards(&account.guard, tool)?;

    let args_map = match args {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };

    server.dispatch_tool(account, tool, &args_map).await
}

/// Extract a u32 from a JSON value (safe truncation check).
fn json_u32(val: &serde_json::Value) -> u32 {
    let n = val.as_u64().expect("expected u64");
    u32::try_from(n).expect("value exceeds u32")
}

// ── Seed message ────────────────────────────────────────────────────

fn test_message() -> Vec<u8> {
    concat!(
        "From: sender@example.com\r\n",
        "To: rimap-test@localhost\r\n",
        "Subject: e2e-test-smoke\r\n",
        "Date: Sat, 12 Apr 2026 10:00:00 +0000\r\n",
        "Message-ID: <e2e-smoke-001@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hello from the e2e smoke test.\r\n",
    )
    .as_bytes()
    .to_vec()
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_full_session() {
    let Some(harness) = DovecotHarness::try_start() else {
        return; // silent skip
    };

    harness.create_mailbox("Drafts");
    harness.create_mailbox("Trash");

    let env = build_test_env(harness);
    let server = &env.server;

    assert_list_folders(server).await;
    seed_message(server).await;
    let uid = assert_search(server).await;
    assert_fetch(server, uid).await;
    assert_mark_read(server, uid).await;
    assert_create_draft(server, uid).await;
    assert_move_and_gone(server, uid).await;
}

async fn assert_list_folders(server: &ImapMcpServer) {
    let result = call_tool(server, "list_folders", serde_json::json!({}))
        .await
        .expect("list_folders failed");
    let folders = result.meta["folders"].as_array().expect("folders");
    let names: Vec<&str> = folders.iter().filter_map(|f| f["name"].as_str()).collect();
    assert!(names.contains(&"INBOX"), "INBOX not in {names:?}",);
}

async fn seed_message(server: &ImapMcpServer) {
    let account = server.registry.resolve(None).expect("resolve account");
    account
        .imap
        .append_message("INBOX", &test_message(), &[], &[])
        .await
        .expect("APPEND failed");
}

async fn assert_search(server: &ImapMcpServer) -> u32 {
    let result = call_tool(
        server,
        "search",
        serde_json::json!({
            "folder": "INBOX",
            "subject": "e2e-test-smoke"
        }),
    )
    .await
    .expect("search failed");

    let total = result.meta["total_matched"].as_u64().unwrap();
    assert!(total >= 1, "expected at least one match");

    let messages = result.untrusted.as_ref().unwrap()["messages"]
        .as_array()
        .expect("messages array");
    let uid = json_u32(&messages[0]["uid"]);
    assert!(uid > 0);
    uid
}

async fn assert_fetch(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "fetch_message",
        serde_json::json!({"folder": "INBOX", "uid": uid}),
    )
    .await
    .expect("fetch_message failed");

    let body = result.untrusted.as_ref().unwrap()["body_text"]
        .as_str()
        .expect("body_text");
    assert!(
        body.contains("Hello from the e2e smoke test"),
        "unexpected body: {body}",
    );
    assert_eq!(json_u32(&result.meta["uid"]), uid);
}

async fn assert_mark_read(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "mark_read",
        serde_json::json!({"folder": "INBOX", "uid": uid}),
    )
    .await
    .expect("mark_read failed");

    let updated = result.meta["uids_updated"]
        .as_array()
        .expect("uids_updated");
    assert!(
        updated.iter().any(|u| json_u32(u) == uid),
        "uid {uid} not in updated list",
    );
}

async fn assert_create_draft(server: &ImapMcpServer, reply_uid: u32) {
    let result = call_tool(
        server,
        "create_draft",
        serde_json::json!({
            "to": [{"address": "reply@example.com"}],
            "subject": "Re: e2e-test-smoke",
            "body_text": "Acknowledged.",
            "in_reply_to_uid": reply_uid,
            "in_reply_to_folder": "INBOX"
        }),
    )
    .await
    .expect("create_draft failed");

    assert_eq!(result.meta["folder"].as_str().unwrap(), "Drafts",);
    let keywords = result.meta["keywords"].as_array().expect("keywords");
    assert!(
        keywords
            .iter()
            .any(|k| k.as_str() == Some("$PendingReview")),
        "missing $PendingReview keyword",
    );
}

async fn assert_move_and_gone(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "move_message",
        serde_json::json!({
            "source_folder": "INBOX",
            "dest_folder": "Trash",
            "uid": uid
        }),
    )
    .await
    .expect("move_message failed");

    let moves = result.meta["moves"].as_array().expect("moves");
    assert_eq!(moves.len(), 1);
    assert_eq!(json_u32(&moves[0]["old_uid"]), uid);

    // Verify message is gone from INBOX.
    let result = call_tool(
        server,
        "search",
        serde_json::json!({
            "folder": "INBOX",
            "subject": "e2e-test-smoke"
        }),
    )
    .await
    .expect("post-move search failed");
    assert_eq!(
        result.meta["total_matched"].as_u64().unwrap(),
        0,
        "message should be gone from INBOX after move",
    );
}
