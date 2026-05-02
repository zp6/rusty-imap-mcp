//! User Service Template install + idempotent uninstall via `windows-service`.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Context as _;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::service::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME_DEFAULT};

/// Inputs to [`install`]. Captures the resolved service name, the absolute
/// binary path SCM should launch, and the absolute config path baked into
/// the registered command line.
#[derive(Debug)]
pub struct InstallInputs {
    /// Service name. Defaults to [`SERVICE_NAME_DEFAULT`] when `None`.
    pub name: Option<String>,
    /// Absolute path of the binary to register. Resolve via
    /// `std::env::current_exe` at the call site.
    pub binary_path: PathBuf,
    /// Absolute config path. Bake this into the SCM command line so the
    /// service does not depend on env-var inheritance.
    pub config_path: PathBuf,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn installinputs_defaults_to_constant_when_name_missing() {
        let i = InstallInputs {
            name: None,
            binary_path: PathBuf::from(r"C:\bin\rusty-imap-mcp.exe"),
            config_path: PathBuf::from(r"C:\rusty.toml"),
        };
        assert_eq!(resolved_name(&i), SERVICE_NAME_DEFAULT);
    }

    #[test]
    fn installinputs_uses_explicit_name() {
        let i = InstallInputs {
            name: Some("RustyImapMcpTest".to_owned()),
            binary_path: PathBuf::from(r"C:\bin\rusty-imap-mcp.exe"),
            config_path: PathBuf::from(r"C:\rusty.toml"),
        };
        assert_eq!(resolved_name(&i), "RustyImapMcpTest");
    }

    #[test]
    fn launch_arguments_include_run_subcommand_and_config_path() {
        let args = launch_arguments(&PathBuf::from(r"C:\rusty.toml"));
        assert_eq!(args, vec!["service", "run", "--config", r"C:\rusty.toml"]);
    }
}

/// Internal helper: resolve the effective service name.
fn resolved_name(inputs: &InstallInputs) -> &str {
    inputs.name.as_deref().unwrap_or(SERVICE_NAME_DEFAULT)
}

/// Internal helper: SCM command-line arguments stored alongside the binary.
fn launch_arguments(config_path: &std::path::Path) -> Vec<String> {
    vec![
        "service".to_owned(),
        "run".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ]
}

/// Register the daemon as a User Service Template via SCM. Requires
/// Administrator. Idempotency on a logically-equivalent existing
/// registration is **not** guaranteed — callers should `uninstall` first
/// if they need to update fields.
///
/// # Errors
/// Returns an error wrapping the underlying `windows-service` error.
/// The most common case is `ERROR_ACCESS_DENIED`, which we re-emit with
/// the hint to re-run from an elevated shell.
pub fn install(inputs: &InstallInputs) -> anyhow::Result<()> {
    let name = resolved_name(inputs);
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(map_access_denied)
    .context("opening Service Control Manager")?;

    let info = ServiceInfo {
        name: OsString::from(name),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        // `USER_OWN_PROCESS` maps to Win32 `SERVICE_USER_OWN_PROCESS`,
        // which is the User Service Template flag combination
        // (`OWN_PROCESS | USER_SERVICE`). SCM sets `USER_SERVICE_INSTANCE`
        // automatically when it spawns a per-user instance from the
        // template; install-time config does not (and cannot) set it.
        service_type: ServiceType::USER_OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: inputs.binary_path.clone(),
        launch_arguments: launch_arguments(&inputs.config_path)
            .into_iter()
            .map(OsString::from)
            .collect(),
        dependencies: vec![ServiceDependency::Service(OsString::from("Tcpip"))],
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(
            &info,
            ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(map_access_denied)
        .context("creating service registration")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(map_access_denied)
        .context("setting service description")?;

    apply_recovery_actions(&service)
        .map_err(map_access_denied)
        .context("setting service recovery (failure) actions")?;

    Ok(())
}

/// Apply restart-on-failure recovery: 30 s delay, twice, no-op on third
/// failure; reset failure counter after 1 hour clean run.
fn apply_recovery_actions(service: &Service) -> Result<(), windows_service::Error> {
    let actions = vec![
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: std::time::Duration::from_secs(30),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: std::time::Duration::from_secs(30),
        },
        ServiceAction {
            action_type: ServiceActionType::None,
            delay: std::time::Duration::from_secs(0),
        },
    ];
    let failure = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(3600)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    };
    service.update_failure_actions(failure)
}

/// Map `ERROR_ACCESS_DENIED` to a friendly hint; pass other errors through.
fn map_access_denied(e: windows_service::Error) -> anyhow::Error {
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(5) {
            return anyhow::anyhow!(
                "ERROR_ACCESS_DENIED — re-run this command from an elevated shell \
                 (Administrator). underlying error: {e}"
            );
        }
    }
    anyhow::Error::from(e)
}
