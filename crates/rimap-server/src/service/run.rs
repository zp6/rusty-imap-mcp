//! `ServiceMain` body, control-handler factory, and SCM dispatcher entry.

#![cfg(windows)]

use std::sync::Arc;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode as WsExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

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

/// Abstraction over the SCM `ServiceStatusHandle` so the control-handler
/// closure can be unit-tested without an actual dispatcher.
pub(crate) trait StatusReporter: Send + Sync + 'static {
    fn report(&self, state: ServiceState);
}

/// Production `StatusReporter` wrapping an SCM-provided `ServiceStatusHandle`.
#[derive(Clone)]
pub(crate) struct ScmReporter {
    handle: ServiceStatusHandle,
    /// Cached `ServiceType` value used in every status update.
    service_type: ServiceType,
}

impl ScmReporter {
    pub(crate) fn new(handle: ServiceStatusHandle, service_type: ServiceType) -> Self {
        Self {
            handle,
            service_type,
        }
    }
}

impl StatusReporter for ScmReporter {
    fn report(&self, state: ServiceState) {
        let controls_accepted = match state {
            ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            _ => ServiceControlAccept::empty(),
        };
        let status = ServiceStatus {
            service_type: self.service_type,
            current_state: state,
            controls_accepted,
            exit_code: WsExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(5),
            process_id: None,
        };
        if let Err(e) = self.handle.set_service_status(status) {
            tracing::error!(error = %e, ?state, "set_service_status failed");
        }
    }
}

/// Build the closure SCM hands every control event. `Stop` and `Shutdown`
/// signal the daemon's shutdown `Notify` and report `StopPending` via
/// `reporter`. `Interrogate` returns `NoError` without changing state.
/// Any other control returns `NotImplemented`.
pub(crate) fn make_event_handler<R: StatusReporter + Clone>(
    shutdown: Arc<Notify>,
    reporter: R,
) -> impl FnMut(ServiceControl) -> ServiceControlHandlerResult + Send + 'static {
    move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            reporter.report(ServiceState::StopPending);
            shutdown.notify_waiters();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Register `make_event_handler(shutdown, ScmReporter::new(…))` with SCM
/// for the given service name. The returned `ScmReporter` shares the
/// `ServiceStatusHandle` SCM gave us so the caller can drive
/// `StartPending → Running → StopPending → Stopped` transitions.
pub(crate) fn register_handler(
    name: &str,
    shutdown: Arc<Notify>,
    service_type: ServiceType,
) -> Result<ScmReporter, windows_service::Error> {
    use std::sync::OnceLock;

    let cell: Arc<OnceLock<ScmReporter>> = Arc::new(OnceLock::new());

    #[derive(Clone)]
    struct DeferredReporter(Arc<OnceLock<ScmReporter>>);
    impl StatusReporter for DeferredReporter {
        fn report(&self, state: ServiceState) {
            if let Some(r) = self.0.get() {
                r.report(state);
            }
        }
    }

    let handler = make_event_handler(shutdown, DeferredReporter(Arc::clone(&cell)));
    let handle = service_control_handler::register(name, handler)?;
    let reporter = ScmReporter::new(handle, service_type);
    let _ = cell.set(reporter.clone());
    Ok(reporter)
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod control_handler_tests {
    use std::sync::{Arc, Mutex};

    use windows_service::service::{ServiceControl, ServiceState};
    use windows_service::service_control_handler::ServiceControlHandlerResult;

    use super::{StatusReporter, make_event_handler};

    /// In-memory `StatusReporter` recording every state transition.
    #[derive(Default, Clone)]
    struct RecordingReporter {
        events: Arc<Mutex<Vec<ServiceState>>>,
    }

    impl StatusReporter for RecordingReporter {
        fn report(&self, state: ServiceState) {
            self.events.lock().unwrap().push(state);
        }
    }

    #[tokio::test]
    async fn stop_control_signals_shutdown_and_reports_stop_pending() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let mut handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let waiter = {
            let n = Arc::clone(&shutdown);
            tokio::spawn(async move { n.notified().await })
        };
        // Yield once so the spawned waiter registers before we notify.
        tokio::task::yield_now().await;
        let result = handler(ServiceControl::Stop);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("shutdown signal was not delivered")
            .expect("waiter join");
        assert_eq!(
            reporter.events.lock().unwrap().as_slice(),
            &[ServiceState::StopPending],
        );
    }

    #[tokio::test]
    async fn shutdown_control_signals_shutdown_and_reports_stop_pending() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let mut handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let waiter = {
            let n = Arc::clone(&shutdown);
            tokio::spawn(async move { n.notified().await })
        };
        tokio::task::yield_now().await;
        let result = handler(ServiceControl::Shutdown);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("shutdown signal was not delivered")
            .expect("waiter join");
        assert_eq!(
            reporter.events.lock().unwrap().as_slice(),
            &[ServiceState::StopPending],
        );
    }

    #[test]
    fn interrogate_returns_no_error_without_signalling_shutdown() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let mut handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        let result = handler(ServiceControl::Interrogate);
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert!(reporter.events.lock().unwrap().is_empty());
    }

    #[test]
    fn unrecognised_control_returns_not_implemented() {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let reporter = RecordingReporter::default();
        let mut handler = make_event_handler(Arc::clone(&shutdown), reporter.clone());

        // ServiceControl is non-exhaustive; pick a control we don't handle.
        let result = handler(ServiceControl::ParamChange);
        assert!(matches!(
            result,
            ServiceControlHandlerResult::NotImplemented,
        ));
        assert!(reporter.events.lock().unwrap().is_empty());
    }
}
