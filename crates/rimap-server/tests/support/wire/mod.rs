//! Wire driver and MCP spec schema validators shared by Phase 1
//! (`mcp_wire_conformance.rs`) and Phase 3 (`e2e_wire.rs`).

pub mod harness;
pub mod schema;

#[expect(unused_imports, reason = "Phase 3 e2e_wire.rs will use these")]
pub use harness::{Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
pub use schema::assert_valid;
