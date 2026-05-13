//! Dovecot container harness and seeded-fixture helpers shared by
//! `e2e.rs` (in-process Rust API) and `e2e_wire.rs` (stdio wire).

pub mod harness;
// pub mod fixtures;  — seeded-fixture helpers, added when needed.

pub use harness::DovecotHarness;
