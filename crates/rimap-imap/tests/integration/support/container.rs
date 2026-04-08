//! `DovecotHarness`: hand-rolled `compose up`/`down` lifecycle with a Drop
//! guard. Supports both `docker compose` and `podman compose` — the first
//! available binary wins, or `RIMAP_CONTAINER_TOOL={docker,podman}` forces
//! a choice. Each test run gets a unique compose project name so parallel
//! tests don't collide.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

/// Name of the container runtime binary to invoke (`docker` or `podman`).
/// Detected once per process. Falls back to `"docker"` even when nothing is
/// installed — callers gate on [`runtime_available`] before using it.
fn runtime() -> &'static str {
    static TOOL: OnceLock<&'static str> = OnceLock::new();
    TOOL.get_or_init(|| {
        // Explicit override wins. Unrecognized values fall through to
        // autodetect silently — the harness has no logger available and
        // `print_stderr` is denied by the workspace lint policy.
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

#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    DockerCommandFailed(String),
    FingerprintReadFailed(String),
    PortReadFailed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DockerUnavailable => {
                f.write_str("no container runtime (docker or podman) is available")
            }
            Self::DockerCommandFailed(s) => write!(f, "{} command failed: {s}", runtime()),
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
    /// - Neither `docker` nor `podman` is installed. Pick one explicitly
    ///   with `RIMAP_CONTAINER_TOOL={docker,podman}`.
    /// - The host architecture is not `x86_64`. The pinned
    ///   `dovecot/dovecot:2.3.21` image is amd64-only, and running it
    ///   under Rosetta/QEMU emulation crashes dovecot's worker processes
    ///   at startup with `mmap_anonymous_rw mmap failed` before anything
    ///   can bind port 993. See the comment in `docker-compose.yml` for
    ///   the full context and why a 2.4 bump isn't viable in Sprint 3.
    pub fn try_start() -> Result<Self, HarnessError> {
        let require_runtime = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();

        if std::env::consts::ARCH != "x86_64" {
            if require_runtime {
                return Err(HarnessError::DockerCommandFailed(format!(
                    "host arch {} cannot run amd64 dovecot image but RIMAP_REQUIRE_DOCKER=1",
                    std::env::consts::ARCH
                )));
            }
            return Err(HarnessError::DockerUnavailable);
        }

        if !runtime_available() {
            if require_runtime {
                return Err(HarnessError::DockerCommandFailed(
                    "neither docker nor podman found but RIMAP_REQUIRE_DOCKER=1".into(),
                ));
            }
            return Err(HarnessError::DockerUnavailable);
        }

        let project = format!("rimap-it-{}", uuid_like());
        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("integration")
            .join("dovecot");

        // Pre-allocate a free host port on 127.0.0.1 so that case_11's
        // force-recreate can reuse it. Docker's `0:993` dynamic allocation
        // picks a new port per container creation, which would strand the
        // cached client Connection after a recreate.
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
                // Dump container logs so the failure tells us WHY dovecot
                // never reached ready state instead of just "timeout".
                let logs = dump_logs(&project, &compose_dir);
                break Err(HarnessError::DockerCommandFailed(format!(
                    "dovecot container did not become ready within 60s. \
                     Last container logs:\n{logs}"
                )));
            }
            if let Ok(fp) = read_fingerprint(&project) {
                // Fingerprint is in place, but dovecot inside the container
                // may not be listening yet. Probe the TCP port directly
                // before handing the harness to the test.
                if std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], host_port)),
                    Duration::from_millis(500),
                )
                .is_ok()
                {
                    break Ok((fp, host_port));
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
    /// Goes through `<runtime> exec` directly against the pinned container
    /// name rather than `compose exec`, for the same reason the readiness
    /// probe does: podman-compose's exec is unreliable under parallel load.
    pub fn exec(&self, args: &[&str]) -> Result<std::process::Output, HarnessError> {
        let mut cmd = Command::new(runtime());
        cmd.arg("exec").arg(container_name(&self.project));
        for a in args {
            cmd.arg(a);
        }
        cmd.output()
            .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))
    }

    /// Recreate the dovecot container, killing every in-flight TCP
    /// session the test client may have cached. Used by `case_11` to
    /// deterministically trigger the half-open recovery path.
    ///
    /// Previous attempts used `pkill -9 imap` (too racy — master
    /// respawns) and `docker compose stop + start` (dovecot's imap-login
    /// failed to come back online inside the recycled container on CI).
    /// `docker compose up -d --force-recreate` destroys the container
    /// and rebuilds it cleanly, which sidesteps both bugs. The cert is
    /// persisted on the `shared` named volume (which is not touched by
    /// recreate) so the pinned fingerprint is unchanged and the
    /// post-disconnect reconnect works.
    ///
    /// On failure, dumps the last container logs into the error message
    /// so CI runners can diagnose entrypoint regressions.
    pub fn restart(&self) -> Result<(), HarnessError> {
        let status = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("up")
            .arg("-d")
            .arg("--force-recreate")
            .arg("--no-deps")
            .arg("dovecot")
            .env("RIMAP_DOVECOT_HOST_PORT", self.port.to_string())
            .current_dir(&self.compose_dir)
            .status()
            .map_err(|e| HarnessError::DockerCommandFailed(format!("recreate: {e}")))?;
        if !status.success() {
            return Err(HarnessError::DockerCommandFailed(format!(
                "compose up --force-recreate exit {status}"
            )));
        }
        // Wait for dovecot to be ready. Two gates: (1) the new entrypoint
        // must rewrite /shared/ready (which it only touches AFTER dovecot
        // has bound 993 inside the container), and (2) a direct TCP probe
        // from the host must succeed (catches the case where docker's
        // userland proxy is lagging the actual container state).
        let started = Instant::now();
        let timeout = Duration::from_secs(45);
        loop {
            if started.elapsed() > timeout {
                let logs = dump_logs(&self.project, &self.compose_dir);
                return Err(HarnessError::DockerCommandFailed(format!(
                    "dovecot did not rebind port {} within 45s after recreate. \
                     Last container logs:\n{logs}",
                    self.port
                )));
            }
            if probe_ready_marker(&self.project)
                && std::net::TcpStream::connect_timeout(
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

fn dump_logs(project: &str, compose_dir: &std::path::Path) -> String {
    match Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("logs")
        .arg("--tail")
        .arg("200")
        .arg("dovecot")
        .current_dir(compose_dir)
        .output()
    {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                out.push_str("\n--- stderr ---\n");
                out.push_str(&err);
            }
            if out.trim().is_empty() {
                "<no container logs>".into()
            } else {
                out
            }
        }
        Err(e) => format!("logs fetch failed: {e}"),
    }
}

/// The compose file pins `container_name: ${COMPOSE_PROJECT_NAME}-dovecot`,
/// so we can talk to the container directly via `<runtime> exec` and skip
/// `compose exec` entirely. podman-compose's `compose exec -T` has been
/// observed to return success without actually executing the command
/// against the service container when multiple compose projects are
/// running in parallel (nextest spawns 11 at once), which wedged the
/// readiness polling until the 60s harness timeout even though dovecot
/// was up and ready. `<runtime> exec` hits the container name directly
/// and has no such failure mode.
fn container_name(project: &str) -> String {
    format!("{project}-dovecot")
}

fn probe_ready_marker(project: &str) -> bool {
    Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
        .arg("test")
        .arg("-f")
        .arg("/shared/ready")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, HarnessError> {
    let out = Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
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
            rotate_keep: 0,
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
