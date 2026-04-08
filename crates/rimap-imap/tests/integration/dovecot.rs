//! Dovecot integration smoke test. Real test cases land in Task 15.

#![expect(clippy::unwrap_used, reason = "tests")]

mod support;

use support::docker::{DovecotHarness, HarnessError};

#[test]
fn dovecot_harness_starts_and_publishes_fingerprint() {
    let harness = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => {
            return; // pre-flight #1: silent skip — workspace denies print_stderr
        }
        Err(e) => panic!("harness failed: {e}"),
    };
    assert!(harness.port() > 0);
    let fp_hex = harness.pinned_fingerprint().to_hex();
    assert_eq!(fp_hex.len(), 64);
}
