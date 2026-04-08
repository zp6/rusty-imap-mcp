//! Path helpers for the seeded fixtures.

use std::path::PathBuf;

#[must_use]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("integration")
        .join("dovecot")
        .join("fixtures")
}
