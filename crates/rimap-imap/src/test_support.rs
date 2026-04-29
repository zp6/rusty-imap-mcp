//! Test-only harness API. Off by default; enabled via the
//! `test-support` feature for cross-crate integration tests.
//!
//! Re-exports the Dovecot Docker fixture so `rimap-server`'s daemon
//! integration tests can spin up a real IMAP backend without copying
//! the harness implementation. The `#[path]` directive points at the
//! existing test-tree file so there is a single source of truth.

// `container.rs` is primarily a test fixture and was authored with the
// looser test lint profile; mirror that here so cross-crate consumers
// don't have to re-document every public surface.
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

#[path = "../tests/integration/support/container.rs"]
pub mod container;
