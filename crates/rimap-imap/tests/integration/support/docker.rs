//! `DovecotHarness`: hand-rolled `docker compose up`/`down` lifecycle with a
//! Drop guard. Each test run gets a unique compose project name so parallel
//! tests don't collide.

#![allow(dead_code)]

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
    /// and skips the test silently in any of these cases (unless
    /// `RIMAP_REQUIRE_DOCKER=1` is set, in which case each becomes a
    /// hard error):
    ///
    /// - Docker is not installed.
    /// - The host architecture is not `x86_64`. The pinned
    ///   `dovecot/dovecot:2.3.21` image is amd64-only, and running it
    ///   under Rosetta/QEMU emulation crashes dovecot's worker processes
    ///   at startup with `mmap_anonymous_rw mmap failed` before anything
    ///   can bind port 993. See the comment in `docker-compose.yml` for
    ///   the full context and why a 2.4 bump isn't viable in Sprint 3.
    pub fn try_start() -> Result<Self, HarnessError> {
        let require_docker = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();

        if std::env::consts::ARCH != "x86_64" {
            if require_docker {
                return Err(HarnessError::DockerCommandFailed(format!(
                    "host arch {} cannot run amd64 dovecot image but RIMAP_REQUIRE_DOCKER=1",
                    std::env::consts::ARCH
                )));
            }
            return Err(HarnessError::DockerUnavailable);
        }

        if !docker_available() {
            if require_docker {
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

        let started = Instant::now();
        let timeout = Duration::from_secs(60);
        let result = loop {
            if started.elapsed() > timeout {
                break Err(HarnessError::Timeout);
            }
            if let (Ok(fp), Ok(p)) = (
                read_fingerprint(&project),
                read_port(&project, &compose_dir),
            ) {
                // Fingerprint + host-side port binding are available, but
                // dovecot inside the container may not be listening yet.
                // Probe the TCP port directly before handing the harness to
                // the test. Without this, fast callers hit "tls handshake eof"
                // on amd64-under-emulation hosts.
                if std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], p)),
                    Duration::from_millis(500),
                )
                .is_ok()
                {
                    break Ok((fp, p));
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        };
        match result {
            Ok((fingerprint, port)) => Ok(Self {
                project,
                compose_dir,
                fingerprint,
                port,
            }),
            Err(e) => {
                compose_down(&project, &compose_dir);
                Err(e)
            }
        }
    }

    #[must_use]
    pub fn host() -> &'static str {
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
    pub fn username() -> &'static str {
        "rimap-test"
    }

    #[must_use]
    pub fn password() -> &'static str {
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

    /// Stop and start the dovecot container, killing every in-flight TCP
    /// session the test client may have cached. Used by `case_11` to
    /// deterministically trigger the half-open recovery path.
    ///
    /// `pkill -9 imap` from inside the container is not a reliable
    /// substitute: dovecot's master process auto-respawns the worker
    /// before the client's next command lands, so the cached session
    /// transparently survives. A container stop+start sends SIGTERM
    /// (with a 5s grace period so dovecot can cleanly release its
    /// runtime state) to dovecot's master and tears down every worker
    /// fd with no respawn. The same self-signed cert survives the cycle
    /// (`entrypoint.sh` guards generation behind a file-existence
    /// check), so the pinned fingerprint is unchanged and the
    /// post-disconnect reconnect works.
    ///
    /// On failure, dumps the last container logs into the error message
    /// so CI runners can diagnose entrypoint regressions.
    pub fn restart(&self) -> Result<(), HarnessError> {
        let stop_status = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("stop")
            .arg("-t")
            .arg("5")
            .arg("dovecot")
            .current_dir(&self.compose_dir)
            .status()
            .map_err(|e| HarnessError::DockerCommandFailed(format!("stop: {e}")))?;
        if !stop_status.success() {
            return Err(HarnessError::DockerCommandFailed(format!(
                "compose stop exit {stop_status}"
            )));
        }
        let start_status = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("start")
            .arg("dovecot")
            .current_dir(&self.compose_dir)
            .status()
            .map_err(|e| HarnessError::DockerCommandFailed(format!("start: {e}")))?;
        if !start_status.success() {
            return Err(HarnessError::DockerCommandFailed(format!(
                "compose start exit {start_status}"
            )));
        }
        // Wait for dovecot to be accepting on the same host port again.
        let started = Instant::now();
        let timeout = Duration::from_secs(45);
        loop {
            if started.elapsed() > timeout {
                let logs = Command::new("docker")
                    .arg("compose")
                    .arg("-p")
                    .arg(&self.project)
                    .arg("logs")
                    .arg("--tail")
                    .arg("60")
                    .arg("dovecot")
                    .current_dir(&self.compose_dir)
                    .output()
                    .map_or_else(
                        |e| format!("logs fetch failed: {e}"),
                        |o| String::from_utf8_lossy(&o.stdout).into_owned(),
                    );
                return Err(HarnessError::DockerCommandFailed(format!(
                    "dovecot did not rebind port {} within 45s after stop/start. \
                     Last container logs:\n{logs}",
                    self.port
                )));
            }
            if std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], self.port)),
                Duration::from_millis(500),
            )
            .is_ok()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for DovecotHarness {
    fn drop(&mut self) {
        compose_down(&self.project, &self.compose_dir);
    }
}

fn compose_down(project: &str, compose_dir: &std::path::Path) {
    let _ = Command::new("docker")
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("down")
        .arg("-v")
        .arg("--remove-orphans")
        .current_dir(compose_dir)
        .status();
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
    TlsFingerprint::from_hex(&s).map_err(|e| HarnessError::FingerprintReadFailed(e.to_string()))
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

// ── Task 15 additions ────────────────────────────────────────────────────────

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::CredentialStore;
use rimap_imap::{Connection, ConnectionConfig};
use std::sync::Arc;
use tempfile::TempDir;

pub struct StaticCreds(pub String);

impl CredentialStore for StaticCreds {
    fn get_password(&self, _account: &str) -> Result<Option<String>, rimap_config::ConfigError> {
        Ok(Some(self.0.clone()))
    }

    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        unreachable!("tests do not write credentials")
    }
}

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
            PinChoice::Wrong => Some(rimap_core::TlsFingerprint::from_cert_der(
                b"deliberately-wrong",
            )),
            PinChoice::None => None,
        };

        let cfg = ConnectionConfig {
            host: DovecotHarness::host().to_string(),
            port: harness.port(),
            username: DovecotHarness::username().to_string(),
            pinned_fingerprint: pinned,
            connect_timeout: std::time::Duration::from_secs(10),
            command_timeout: std::time::Duration::from_secs(10),
            max_fetch_body_bytes: 5_242_880,
        };
        let creds: Arc<dyn CredentialStore> =
            Arc::new(StaticCreds(DovecotHarness::password().to_string()));
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
