//! Async wrapper for the synchronous `rimap_content::parse_message`.

use rimap_content::{Content, ContentError, parse_message};

/// Run `parse_message` on the blocking threadpool to avoid starving
/// the tokio runtime. `parse_message` is CPU-bound (~2 ms per message).
///
/// # Errors
///
/// Returns `ContentError` from the inner call, or
/// `ContentError::Malformed` if the blocking task panicked.
pub async fn parse_message_async(raw: Vec<u8>) -> Result<Content, ContentError> {
    tokio::task::spawn_blocking(move || parse_message(&raw))
        .await
        .unwrap_or_else(|e| {
            Err(ContentError::Malformed {
                reason: format!("spawn_blocking panicked: {e}"),
            })
        })
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
