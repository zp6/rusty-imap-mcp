//! One-shot special-use discovery at account boot.
//!
//! Runs `LIST "" "*"` once against a freshly-opened `Connection` and
//! builds a `SpecialUseMap`. Called from the per-account boot path
//! before `FolderGuard` is constructed so the guard's protected list
//! can include discovered server-native folder names (e.g.
//! `[Gmail]/Sent Mail`) in addition to the config-supplied literals.
//!
//! Classification logic is unit-tested in `rimap_imap::special_use`;
//! the live LIST path is covered by the Dovecot integration harness.

use rimap_imap::{Connection, ImapError, SpecialUseMap};

/// Run one `LIST "*"` and classify the response into a `SpecialUseMap`.
///
/// Discovery failures propagate — if we cannot enumerate folders at
/// boot, the account is unusable regardless of what any downstream tool
/// call does later, so returning the error early gives the operator a
/// clean boot-time signal instead of a surprise on first compose.
///
/// # Errors
///
/// Returns `ImapError` when the underlying `LIST` call fails (transport
/// error, server protocol error, auth expired, etc.). The boot path
/// wraps this into a `BootError::SpecialUseDiscovery` so the failing
/// account name is recorded alongside the underlying error code.
pub async fn resolve_special_use(connection: &Connection) -> Result<SpecialUseMap, ImapError> {
    let folders = connection.list_folders("*").await?;
    Ok(SpecialUseMap::from_folders(&folders))
}
