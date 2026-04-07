//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod matrix;
pub mod rate_limit;

pub use crate::error::AuthzError;
pub use crate::matrix::{EffectiveMatrix, base_allows};
pub use crate::rate_limit::Governor;
