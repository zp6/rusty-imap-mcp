//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::AuthzError;
