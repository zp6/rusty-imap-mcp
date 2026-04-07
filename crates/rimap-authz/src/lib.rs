//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod matrix;

pub use crate::error::AuthzError;
pub use crate::matrix::{EffectiveMatrix, base_allows};
