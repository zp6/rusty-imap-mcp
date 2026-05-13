//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! on non-x86_64 hosts or when no container runtime is available.
//! See `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::unwrap_used, reason = "integration tests")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

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

pub struct DovecotHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    port: u16,
}

impl DovecotHarness {
    pub fn try_start() -> Option<Self> {
        const BACKOFF_MS: [u64; 2] = [50, 250];
        const MAX_ATTEMPTS: usize = BACKOFF_MS.len() + 1;

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

        let mut host_port = ReservedPort::acquire()?;

        // Attempt 0 is the initial try (no prior sleep). Attempts 1 and 2
        // are retries preceded by teardown + backoff sleep + fresh port.
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                compose_down(&project, &compose_dir);
                std::thread::sleep(std::time::Duration::from_millis(BACKOFF_MS[attempt - 1]));
                host_port = ReservedPort::acquire()?;
            }
            host_port.release();

            let output = Command::new(runtime())
                .arg("compose")
                .arg("-p")
                .arg(&project)
                .arg("up")
                .arg("-d")
                .env("RIMAP_DOVECOT_HOST_PORT", host_port.port().to_string())
                .current_dir(&compose_dir)
                .output()
                .ok()?;

            if output.status.success() {
                return wait_for_ready(&project, host_port.port(), &compose_dir);
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            if !is_port_collision(&stderr) {
                // Non-collision failure: stop retrying.
                return None;
            }
        }

        // All attempts hit port collisions.
        None
    }

    /// Create a mailbox via `doveadm` inside the container.
    pub fn create_mailbox(&self, name: &str) {
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

    pub fn fingerprint(&self) -> &TlsFingerprint {
        &self.fingerprint
    }

    pub fn port(&self) -> u16 {
        self.port
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

/// Host port reserved by binding `127.0.0.1:0` and reading the
/// kernel-assigned number. The `TcpListener` is kept open until
/// `release()` is called, holding the kernel-level lease so docker
/// (or any other process) cannot bind the same port in the meantime.
struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    fn acquire() -> Option<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        Some(Self {
            port,
            listener: Some(listener),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Drop the underlying `TcpListener`, releasing the kernel-level
    /// port lease. Idempotent.
    fn release(&mut self) {
        self.listener.take();
    }
}

/// Classify a stderr blob from a failed `compose up`: `true` when the
/// failure looks like a host-port bind collision.
fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for 127.0.0.1")
}
