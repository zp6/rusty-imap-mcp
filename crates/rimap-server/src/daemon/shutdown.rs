//! Platform-aware shutdown-signal source for the daemon.

use std::sync::Arc;

use tokio::sync::Notify;

/// Spawn a task that listens for platform shutdown signals and triggers
/// the returned `Notify` on the first one received. Subsequent signals
/// are ignored at this layer (tokio's signal stream already coalesces).
#[must_use]
pub fn install_shutdown_handler() -> Arc<Notify> {
    let notify = Arc::new(Notify::new());
    let for_task = Arc::clone(&notify);
    tokio::spawn(async move {
        wait_for_signal().await;
        for_task.notify_waiters();
    });
    notify
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // expect() is justified: if we can't install these handlers, the daemon
    // cannot be gracefully stopped and should fail loudly at startup.
    #[expect(
        clippy::expect_used,
        reason = "signal handler install failure is unrecoverable"
    )]
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    #[expect(
        clippy::expect_used,
        reason = "signal handler install failure is unrecoverable"
    )]
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received"),
        _ = sigint.recv() => tracing::info!("SIGINT received"),
    }
}

#[cfg(windows)]
async fn wait_for_signal() {
    #[expect(
        clippy::expect_used,
        reason = "signal handler install failure is unrecoverable"
    )]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl+C handler");
    tracing::info!("Ctrl+C received");
}
