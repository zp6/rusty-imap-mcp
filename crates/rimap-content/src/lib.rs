//! MIME parsing, Unicode-safe sanitization, and look-alike detection for rusty-imap-mcp.
//!
//! Sprint 4a delivers the parse + unicode + output foundation. HTML
//! sanitization and look-alike detection are reserved for Sprint 4b.

#![deny(missing_docs)]

pub mod error;
pub mod output;

pub use error::ContentError;
pub use output::{
    AttachmentMeta, Content, ContentMeta, MailingListInfo, SecurityWarning, Untrusted, WarningCode,
};
