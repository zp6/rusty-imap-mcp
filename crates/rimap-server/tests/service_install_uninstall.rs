//! Integration test: round-trip install → query → uninstall against a
//! uniquely-named User Service Template. Requires Administrator;
//! skips cleanly when not elevated (`raw_os_error` 5 from
//! `ServiceManager::local_computer` with `CREATE_SERVICE` access).

#![cfg(windows)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::path::PathBuf;

use rimap_server::service::install::{InstallInputs, install, uninstall};
use windows_service::service::ServiceAccess;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

fn unique_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("RustyImapMcpTest_{nanos:x}_{}", std::process::id())
}

/// Returns true if SCM access is denied (test process not elevated).
fn elevation_denied(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("ERROR_ACCESS_DENIED")
}

#[test]
fn install_query_uninstall_round_trip() {
    let name = unique_name();
    let inputs = InstallInputs {
        name: Some(name.clone()),
        binary_path: std::env::current_exe().unwrap(),
        config_path: PathBuf::from(r"C:\nonexistent-test-config.toml"),
    };

    match install(&inputs) {
        Ok(()) => {}
        Err(e) if elevation_denied(&e) => {
            eprintln!("SKIP: install requires Administrator; ran as standard user. Error: {e:#}");
            return;
        }
        Err(e) => panic!("install failed: {e:#}"),
    }

    // Confirm the registration is visible to a fresh ServiceManager handle.
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
    let _service = manager
        .open_service(&name, ServiceAccess::QUERY_STATUS)
        .expect("service should be queryable after install");

    // Uninstall — first call deletes it.
    uninstall(Some(&name)).expect("uninstall");

    // Idempotent — second call against the same name succeeds.
    uninstall(Some(&name)).expect("idempotent uninstall");
}
