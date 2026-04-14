//! MCP tool handlers, grouped by concern:
//! - [`admin`]: account and folder discovery
//! - [`compose`]: outgoing message construction (send, draft)
//! - [`mailbox`]: server-side mutations (flags, labels, moves, deletes)
//! - [`retrieval`]: search, fetch, attachments
//!
//! The submodules are re-exported with `pub use` so existing callers that
//! reference `crate::tools::<module>::...` keep compiling after the split.

pub mod admin;
pub mod compose;
pub mod mailbox;
pub mod retrieval;
pub(crate) mod support;

pub use admin::*;
pub use compose::*;
pub use mailbox::*;
pub use retrieval::*;
