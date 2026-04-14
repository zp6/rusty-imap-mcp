//! Async wrapper for the synchronous `rimap_content::parse_message`.

use std::sync::LazyLock;

use rimap_content::{Content, parse_message};
use rimap_core::RimapError;
use tokio::sync::Semaphore;

/// Limits concurrent `spawn_blocking` parse invocations to avoid
/// saturating the blocking threadpool (default 512 threads).
static PARSE_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(8));

/// Run `parse_message` on the blocking threadpool to avoid starving
/// the tokio runtime. `parse_message` is CPU-bound (~2 ms per message).
///
/// Classifies failures by source:
/// - `ContentError::Malformed` / `LimitExceeded` from the parser surface
///   as `RimapError::Authz { code: InvalidInput, ... }` because the
///   input bytes (an email body) are caller-supplied.
/// - Panics from the blocking task or a closed acquisition semaphore
///   surface as `RimapError::Internal` — those are infrastructure
///   failures, not content defects, and should trip the circuit breaker
///   rather than the user-error path.
///
/// # Errors
///
/// As described above — never returns `ContentError` directly so the
/// classification cannot drift at call sites.
pub async fn parse_message_async(raw: Vec<u8>) -> Result<Content, RimapError> {
    let _permit = PARSE_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| RimapError::Internal("parse semaphore closed".into()))?;
    match tokio::task::spawn_blocking(move || parse_message(&raw)).await {
        Ok(Ok(content)) => Ok(content),
        Ok(Err(e)) => Err(RimapError::invalid_input(e.to_string())),
        Err(join_err) => Err(crate::mcp::spawn_blocking_panic_error(&join_err)),
    }
}

/// Run `rimap_content::walk_attachment_parts` on the blocking
/// threadpool. Shares `PARSE_SEMAPHORE` with [`parse_message_async`]
/// so heavy attachment extractions cannot saturate the runtime.
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput, ... }` for `ContentError`
///   (malformed RFC 5322).
/// - `RimapError::Internal` for panics or a closed semaphore.
pub async fn walk_attachment_parts_async(
    raw: Vec<u8>,
) -> Result<Vec<rimap_content::RawPart>, RimapError> {
    let _permit = PARSE_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| RimapError::Internal("parse semaphore closed".into()))?;
    match tokio::task::spawn_blocking(move || rimap_content::walk_attachment_parts(&raw)).await {
        Ok(Ok(parts)) => Ok(parts),
        Ok(Err(e)) => Err(RimapError::invalid_input(e.to_string())),
        Err(join_err) => Err(crate::mcp::spawn_blocking_panic_error(&join_err)),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_message_async_matches_sync() {
        let raw = b"From: test@example.com\r\n\
                     Subject: async test\r\n\
                     \r\n\
                     Body.\r\n"
            .to_vec();

        let sync_result = parse_message(&raw).unwrap();
        let async_result = parse_message_async(raw).await.unwrap();

        assert_eq!(sync_result.meta.subject, async_result.meta.subject);
        assert_eq!(
            sync_result.untrusted.body_text,
            async_result.untrusted.body_text
        );
    }
}
