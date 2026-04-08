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

        let started = Instant::now();
        let timeout = Duration::from_secs(30);
        loop {
            if started.elapsed() > timeout {
                return Err(HarnessError::Timeout);
            }
            if let (Ok(fp), Ok(p)) =
                (read_fingerprint(&project), read_port(&project, &compose_dir))
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
    #[expect(dead_code, reason = "consumed by Task 15 integration tests")]
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
    #[expect(dead_code, reason = "consumed by Task 15 integration tests")]
    pub fn username(&self) -> &str {
        "rimap-test"
    }

    #[must_use]
    #[expect(dead_code, reason = "consumed by Task 15 integration tests")]
    pub fn password(&self) -> &str {
        "testpass"
    }

    /// Run an arbitrary command inside the running dovecot container.
    #[expect(dead_code, reason = "consumed by Task 15 integration tests")]
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
