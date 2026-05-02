//! `ServiceMain` body, control-handler factory, and SCM dispatcher entry.

#![cfg(windows)]

/// Stable SCM `service_specific` exit codes for the boot-failure paths
/// in `run_with_shutdown`. SCM surfaces these in the System event log;
/// operators correlate them with `daemon.log` to identify the failure
/// class without reading source.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExitCode {
    /// Config loading or validation failed.
    ConfigLoad = 1,
    /// Audit log open / lock failed.
    AuditOpen = 2,
    /// Account registry build failed (per-account credential / IMAP setup).
    RegistryBuild = 3,
    /// Listener bind failed (named pipe creation).
    ListenerBind = 4,
    /// Generic runtime failure not covered by the more specific variants.
    RuntimeFailure = 5,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod exit_code_tests {
    use super::ServiceExitCode;

    #[test]
    fn variant_codes_are_stable_and_distinct() {
        assert_eq!(ServiceExitCode::ConfigLoad as u32, 1);
        assert_eq!(ServiceExitCode::AuditOpen as u32, 2);
        assert_eq!(ServiceExitCode::RegistryBuild as u32, 3);
        assert_eq!(ServiceExitCode::ListenerBind as u32, 4);
        assert_eq!(ServiceExitCode::RuntimeFailure as u32, 5);
    }
}
