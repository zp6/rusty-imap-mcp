//! Shared support for `rimap-server` integration tests. Re-exports
//! the wire driver (Phase 1 + Phase 3) and the Dovecot harness
//! (Phase 3 + the legacy `e2e_full_session`).
//!
//! Each integration-test file pulls this in with
//! `#[path = "support/mod.rs"] mod support;` at the top.

pub mod wire;
// `pub mod dovecot;` added in Task 6.
