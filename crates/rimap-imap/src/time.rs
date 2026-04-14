//! `tokio::time::timeout` wrapper that maps the elapsed error into our
//! typed `ImapError::Timeout { op }`.

use std::future::Future;
use std::time::Duration;

use crate::error::ImapError;

/// Run `fut` under `dur`, mapping the elapsed error to `ImapError::Timeout`.
///
/// # Errors
/// Returns `ImapError::Timeout { op }` if the future does not complete within
/// `dur`. Otherwise propagates the future's own error.
pub async fn with_timeout<F, T>(op: &'static str, dur: Duration, fut: F) -> Result<T, ImapError>
where
    F: Future<Output = Result<T, ImapError>>,
{
    match tokio::time::timeout(dur, fut).await {
        Ok(inner) => inner,
        Err(_) => Err(ImapError::Timeout { op }),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::time::Duration;

    use super::with_timeout;
    use crate::error::ImapError;

    #[tokio::test(start_paused = true)]
    async fn returns_timeout_when_future_exceeds_deadline() {
        let result: Result<(), ImapError> =
            with_timeout("test_op", Duration::from_millis(50), async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            })
            .await;
        match result {
            Err(ImapError::Timeout { op }) => assert_eq!(op, "test_op"),
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn passes_through_value_when_future_completes_in_time() {
        let result: Result<i32, ImapError> =
            with_timeout("ok_op", Duration::from_secs(60), async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn passes_through_error_when_future_fails_in_time() {
        let result: Result<(), ImapError> =
            with_timeout("err_op", Duration::from_secs(60), async {
                Err(ImapError::ConnectionLost)
            })
            .await;
        match result {
            Err(ImapError::ConnectionLost) => {}
            other => panic!("expected ConnectionLost, got {other:?}"),
        }
    }
}
