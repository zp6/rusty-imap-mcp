//! Cross-cutting helpers shared by the capability-named tool handler
//! groups (`admin`, `compose`, `mailbox`, `retrieval`).
//!
//! Code that lives here is consumed from at least two of those groups
//! and does not belong to any single capability. Per-handler logic
//! lives under the capability folders, not here.

pub(crate) mod fetch_by_uid;
pub(crate) mod validation;
