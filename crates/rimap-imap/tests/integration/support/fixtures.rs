//! Path helpers for the seeded fixtures.

use std::path::PathBuf;

#[must_use]
#[expect(dead_code, reason = "consumed by Task 15 integration tests")]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("integration")
        .join("dovecot")
        .join("fixtures")
}
