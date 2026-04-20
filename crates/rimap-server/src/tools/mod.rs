//! MCP tool handlers, grouped by concern:
//! - [`admin`]: account and folder discovery
//! - [`compose`]: outgoing message construction (send, draft)
//! - [`mailbox`]: server-side mutations (flags, labels, moves, deletes)
//! - [`retrieval`]: search, fetch, attachments
//!
//! Callers must reference the subdir path (`crate::tools::retrieval::fetch_message`);
//! no wildcard facade is provided so the partition stays meaningful.

pub(crate) mod admin;
pub(crate) mod compose;
pub(crate) mod fetch_by_uid;
pub(crate) mod mailbox;
pub(crate) mod retrieval;
pub(crate) mod validation;
