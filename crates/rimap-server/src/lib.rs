//! Library crate for the rusty-imap-mcp binary.
//!
//! The modules are exposed with `#[doc(hidden)] pub` so that the
//! binary entry point (`main.rs`) and integration tests in
//! `tests/` can reach internal types, without advertising a stable
//! library API. External consumers should not depend on this
//! surface — it is an implementation detail.
//!
//! # Submodule visibility convention
//!
//! Inside the top-level subfolders (`boot/`, `daemon/`, `mcp/`,
//! `tools/`), child modules use `pub mod` whenever any integration
//! test (the only out-of-crate consumer) needs to reach them, and
//! `pub(crate) mod` otherwise. The whole tree is `#[doc(hidden)]`
//! through the wrappers above, so the `pub` does not advertise a
//! stable library API — it just keeps integration-test reach
//! working without stamping `#[cfg(test)] pub use` re-exports
//! everywhere. New modules should default to `pub(crate) mod` and
//! switch to `pub mod` only when an integration test imports them.

#![deny(missing_docs)]

#[doc(hidden)]
pub mod boot;
#[doc(hidden)]
pub mod daemon;
#[doc(hidden)]
pub mod mcp;
#[doc(hidden)]
pub mod shim;
#[doc(hidden)]
pub mod tools;

/// Elapsed milliseconds since `start`, saturating at `u64::MAX`. Audit
/// records carry `duration_ms` as `u64`; the saturation handles the
/// theoretically-possible overflow when an `Instant` delta exceeds ~584
/// million years without requiring each call site to re-justify its
/// `.unwrap_or(u64::MAX)`.
#[must_use]
pub(crate) fn duration_ms_since(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}
