//! Dovecot container harness and seeded-fixture helpers shared by
//! `e2e.rs` (in-process Rust API) and `e2e_wire.rs` (stdio wire).

pub mod fixtures;
pub mod harness;

pub use harness::DovecotHarness;
