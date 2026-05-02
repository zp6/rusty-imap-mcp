//! `ServiceMain` body, control-handler factory, and SCM dispatcher entry.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode as WsExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

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
}

impl ScmReporter {
    pub(crate) fn new(handle: ServiceStatusHandle) -> Self {
        Self { handle }
    }

    /// Build and emit a `ServiceStatus`. `controls_accepted` is derived
    /// from `state` (only `Running` accepts controls). All callers in
    /// this module go through here.
    fn set(&self, state: ServiceState, exit_code: WsExitCode, wait_hint: Duration) {
        let controls_accepted = if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        };
        let status = ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        };
        if let Err(e) = self.handle.set_service_status(status) {
            tracing::error!(error = %e, ?state, "set_service_status failed");
        }
    }
}

impl StatusReporter for ScmReporter {
    fn report(&self, state: ServiceState) {
        self.set(state, WsExitCode::Win32(0), Duration::from_secs(5));
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
///
/// The `OnceLock` dance breaks the chicken-and-egg between needing the
/// handler closure to register and needing the registered handle to
/// build the production reporter.
pub(crate) fn register_handler(
    name: &str,
    shutdown: Arc<Notify>,
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
    let reporter = ScmReporter::new(handle);
    let _ = cell.set(reporter.clone());
    Ok(reporter)
}

// `define_windows_service!` expands to `ffi_service_main` — the FFI shim
// SCM jumps to. The shim trampolines into `service_main_impl` below.
windows_service::define_windows_service!(ffi_service_main, service_main_impl);

/// Service type used in every status update.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Enter the SCM dispatcher. Called from the CLI handler for
/// `service run`. Returns when SCM disconnects (i.e. after `Stopped`
/// has been reported and `service_main` has returned).
///
/// # Errors
/// Returns an error if the dispatcher fails to start. The most common
/// case is `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when the verb is
/// run interactively rather than by SCM; we map that to a friendly
/// message at the CLI layer.
pub fn dispatch(name: &str) -> Result<(), windows_service::Error> {
    service_dispatcher::start(name, ffi_service_main)
}

fn service_main_impl(_args: Vec<OsString>) {
    if let Err(e) = run_service_main() {
        tracing::error!(error = %e, "service_main exited with error");
    }
}

fn run_service_main() -> anyhow::Result<()> {
    // Resolve the config path the install step baked into the SCM command
    // line. Falls back to the same env-var / platform-default chain
    // `daemon` uses when `--config` is omitted, so a misconfigured
    // registration still makes a best-effort start.
    let config_path = resolve_service_config_path()?;

    // Open the daemon log file BEFORE installing the tracing subscriber,
    // so the very first events land on disk. Stderr fallback when the
    // file cannot be created — under SCM that's lost unless the operator
    // configured `sc.exe failure` redirection, but the SCM exit code path
    // still surfaces the failure class.
    // The subscriber owns the writer for the process lifetime, and
    // `tracing-subscriber`'s `MakeWriter` blanket covers `Mutex<W: Write>`,
    // so no Arc wrapping is needed. Stderr fallback when the file cannot be
    // created — under SCM that's lost unless the operator configured
    // `sc.exe failure` redirection, but the SCM exit code path still
    // surfaces the failure class.
    match crate::service::tracing_sink::open_log_file() {
        Ok(file) => crate::boot::logging::init_to_writer(std::sync::Mutex::new(file)),
        Err(e) => {
            crate::boot::logging::init();
            tracing::warn!(error = %e, "could not open daemon log file; falling back to stderr");
        }
    }

    let shutdown = Arc::new(Notify::new());
    let reporter = register_handler(crate::service::SERVICE_NAME_DEFAULT, Arc::clone(&shutdown))
        .map_err(|e| anyhow::anyhow!("registering service control handler: {e}"))?;

    // StartPending while we boot the runtime + bind the listener.
    reporter.set(
        ServiceState::StartPending,
        WsExitCode::Win32(0),
        Duration::from_secs(5),
    );

    // Current-thread runtime so `run_with_shutdown`'s returned future does
    // not need to be `Send`. `boot::registry::build` has a rustc HRTB rough
    // edge that prevents `tokio::spawn`'ing it on a multi-thread runtime;
    // driving it directly via `block_on` here sidesteps the issue.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("building tokio runtime: {e}"))?;

    let reporter_for_async = reporter.clone();
    let result: anyhow::Result<()> = runtime.block_on(async move {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let daemon_fut =
            crate::daemon::run::run_with_shutdown(config_path, shutdown, Some(started_tx));
        tokio::pin!(daemon_fut);

        // Race the daemon future against the bind-ready signal and a
        // generous deadline. `biased` prevents an instant-error daemon
        // boot from being missed in favor of started_rx (which would
        // never fire in that case).
        let bind_ready: bool = tokio::select! {
            biased;
            join = &mut daemon_fut => return join,
            r = started_rx => r.is_ok(),
            () = tokio::time::sleep(BIND_DEADLINE) => {
                tracing::warn!(
                    deadline_secs = BIND_DEADLINE.as_secs(),
                    "bind-ready signal did not fire before deadline; awaiting daemon completion",
                );
                false
            }
        };

        if bind_ready {
            reporter_for_async.set(
                ServiceState::Running,
                WsExitCode::Win32(0),
                Duration::from_secs(0),
            );
        }
        daemon_fut.await
    });

    let exit = match &result {
        Ok(()) => WsExitCode::Win32(0),
        Err(e) => classify_boot_error(e),
    };
    reporter.set(ServiceState::Stopped, exit, Duration::from_secs(0));

    Ok(())
}

/// Maximum time we wait for `run_with_shutdown` to fire its bind-ready
/// signal before reporting `Running` regardless. SCM grants ~30 s for a
/// state transition before considering the service hung.
const BIND_DEADLINE: Duration = Duration::from_secs(30);

/// Inspect a daemon-future error and return the matching SCM exit code.
/// This is the boot-failure mapping the spec calls out.
fn classify_boot_error(e: &anyhow::Error) -> WsExitCode {
    // Match by error chain context. `with_context(|| "loading config …")`
    // and similar contexts emitted by `run_with_shutdown` surface in
    // `format!("{e:#}")` — match substrings.
    let s = format!("{e:#}");
    if s.contains("loading config") {
        WsExitCode::ServiceSpecific(ServiceExitCode::ConfigLoad as u32)
    } else if s.contains("opening audit log") {
        WsExitCode::ServiceSpecific(ServiceExitCode::AuditOpen as u32)
    } else if s.contains("building account registry") {
        WsExitCode::ServiceSpecific(ServiceExitCode::RegistryBuild as u32)
    } else if s.contains("creating named pipe") || s.contains("binding daemon socket") {
        WsExitCode::ServiceSpecific(ServiceExitCode::ListenerBind as u32)
    } else {
        WsExitCode::ServiceSpecific(ServiceExitCode::RuntimeFailure as u32)
    }
}

/// Resolve the config path the service should use. SCM passes a
/// fully-baked command line, so we don't take a CLI override here; the
/// install step's `--config` is what landed in the registered command
/// line. Falling back to the env-var / platform-default chain keeps a
/// misconfigured registration on a best-effort start path.
fn resolve_service_config_path() -> anyhow::Result<PathBuf> {
    crate::boot::config_path::resolve(None).map_err(|_| {
        anyhow::anyhow!(
            "no config path resolvable from env / platform default; \
             reinstall the service with `rusty-imap-mcp service install --config <path>`"
        )
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod classify_boot_error_tests {
    use super::{ServiceExitCode, WsExitCode, classify_boot_error};

    #[test]
    fn config_load_error_maps_to_config_load_exit() {
        let err = anyhow::anyhow!("loading config /missing/path");
        match classify_boot_error(&err) {
            WsExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::ConfigLoad as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }

    #[test]
    fn audit_open_error_maps_to_audit_open_exit() {
        let err = anyhow::anyhow!("opening audit log at /x");
        match classify_boot_error(&err) {
            WsExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::AuditOpen as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }

    #[test]
    fn unknown_error_maps_to_runtime_failure_exit() {
        let err = anyhow::anyhow!("something we did not categorize");
        match classify_boot_error(&err) {
            WsExitCode::ServiceSpecific(c) => {
                assert_eq!(c, ServiceExitCode::RuntimeFailure as u32);
            }
            other => panic!("expected ServiceSpecific, got {other:?}"),
        }
    }
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
