//! EXPUNGE: permanently remove messages flagged as `\Deleted`.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::Uid;

/// Count of `\Deleted`-flagged messages before expunge, for audit logging.
///
/// Issues `UID SEARCH DELETED` on the folder opened in `EXAMINE` mode.
///
/// # Errors
///
/// Propagates connection-lost or protocol errors.
pub(crate) async fn count_deleted(
    session: &mut ImapSession,
    folder: &str,
) -> Result<Vec<Uid>, ImapError> {
    super::folder_management::validate_folder_name(folder)?;
    super::folders::select(session, folder, true).await?;
    let uids = session
        .uid_search("DELETED")
        .await
        .map_err(super::folders::map_err)?;
    Ok(uids.into_iter().filter_map(Uid::new).collect())
}

/// Expunge all `\Deleted` messages from `folder`.
///
/// Caller must SELECT the folder in read-write mode before calling.
///
/// Returns the number of messages expunged (sequence numbers from the
/// server's EXPUNGE responses).
///
/// # Errors
///
/// Propagates connection-lost or protocol errors.
pub(crate) async fn expunge(session: &mut ImapSession) -> Result<u32, ImapError> {
    let stream = session.expunge().await.map_err(super::folders::map_err)?;
    futures_util::pin_mut!(stream);
    let mut count = 0u32;
    while let Some(item) = stream.next().await {
        let _seq = item.map_err(super::folders::map_err)?;
        count = count.saturating_add(1);
    }
    Ok(count)
}
