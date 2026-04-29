//! IMAP connection, TLS fingerprint pinning, and per-command operations
//! (fetch, search, store, move, append, expunge, folder management) for
//! rusty-imap-mcp. Public entry point: [`Connection`].

#![deny(missing_docs)]

pub(crate) mod auth;
pub mod connection;
pub mod error;
pub mod ops;
pub mod preflight;
pub mod special_use;
pub mod time;
pub mod tls;
pub mod types;

pub use crate::connection::{Connection, ConnectionConfig, ImapEncryption};
pub use crate::error::{AuthFailure, ImapError, StarttlsFailure, StarttlsRefusal};
pub use special_use::{SpecialUse, SpecialUseMap, classify_special_use};

// `test_support` re-exports `tests/integration/support/container.rs` via
// `#[path]` so the file is the single source of truth for both in-crate
// integration tests and the cross-crate `rimap-server` daemon-Dovecot
// suite. The included file references `rimap_imap::*` paths as if it
// were an external consumer; alias the current crate so those paths
// resolve when the file is compiled as part of this lib.
#[cfg(any(test, feature = "test-support"))]
extern crate self as rimap_imap;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
