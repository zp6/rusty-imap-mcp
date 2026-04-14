//! Response envelope types for MCP tool responses.
//!
//! Every tool returns a JSON object with three top-level fields:
//! `meta` (trusted server metadata), `untrusted` (sanitized email
//! content), and `security_warnings` (structured observations).

use serde::Serialize;

/// Top-level tool response envelope.
#[derive(Debug, Serialize)]
pub struct ToolResponse {
    /// Server-controlled metadata. Trusted.
    pub meta: serde_json::Value,
    /// Sanitized content derived from email data. Untrusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<serde_json::Value>,
    /// Structured security observations. Trusted metadata.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<serde_json::Value>,
}
