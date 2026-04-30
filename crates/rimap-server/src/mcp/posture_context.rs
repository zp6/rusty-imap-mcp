//! Audit-envelope posture header types and the breaker-reason mapping.
//!
//! Lifted out of `mcp::dispatch` so neither `dispatch.rs` nor
//! `server.rs` has to import the other to read these types: previously
//! `dispatch.rs` added inherent impls to `ImapMcpServer` (defined in
//! `server.rs`) and `server.rs` re-imported `PostureContext` from
//! `dispatch.rs`, forming a real bidirectional file cycle.

/// Posture context recorded in audit envelope headers.
///
/// Per-account dispatches use the account's effective posture; the
/// infrastructure tools (`list_accounts`, `use_account`) bypass posture
/// gating by design and record the dedicated `Infrastructure` variant so
/// log readers can distinguish them from per-account dispatches.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PostureContext {
    Account(rimap_core::Posture),
    Infrastructure,
}

impl PostureContext {
    /// The per-account [`rimap_core::Posture`] this context represents, or
    /// `None` for the infrastructure dispatch path. The audit writer maps
    /// `None` to the `"infrastructure"` sentinel it records on disk.
    pub(crate) fn posture(self) -> Option<rimap_core::Posture> {
        match self {
            Self::Account(p) => Some(p),
            Self::Infrastructure => None,
        }
    }
}

/// Map a [`rimap_core::RimapError`] to the breaker's
/// [`rimap_authz::breaker::FailureReason`], or `None` when the error
/// represents a user/agent/policy failure (which the breaker must ignore
/// per its contract).
pub(crate) fn rimap_error_to_breaker_reason(
    err: &rimap_core::RimapError,
) -> Option<rimap_authz::breaker::FailureReason> {
    use rimap_authz::breaker::FailureReason;
    use rimap_core::ErrorCode;
    match err.code() {
        ErrorCode::ConnectionLost => Some(FailureReason::ConnectionLost),
        ErrorCode::Auth => Some(FailureReason::Auth),
        ErrorCode::Timeout => Some(FailureReason::Timeout),
        ErrorCode::ImapProtocol | ErrorCode::SmtpProtocol => Some(FailureReason::Protocol),
        ErrorCode::Tls => Some(FailureReason::Tls),
        ErrorCode::InvalidInput
        | ErrorCode::PostureDenied
        | ErrorCode::RateLimited
        | ErrorCode::CircuitOpen
        | ErrorCode::NotFound
        | ErrorCode::AttachmentTooLarge
        | ErrorCode::ProtectedFolder
        | ErrorCode::ExpungeDenied
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount
        | ErrorCode::Cancelled
        | ErrorCode::UidValidityChanged => None,
    }
}
