//! Tests for TLS config construction and `last_observed` slot semantics.
//!
//! These are not end-to-end verifier tests — they exercise the `OnceLock`
//! capture path with synthetic cert DER bytes and confirm that each
//! `build_tls_config` call owns its own slot. The `ServerCertVerifier`
//! accept/reject paths (pinned fingerprint match/mismatch) require a real
//! handshake and are covered by the Dovecot integration test in
//! `tests/integration/dovecot.rs` (Task 15).

#![expect(clippy::expect_used, reason = "tests")]

use rimap_core::TlsFingerprint;
use rimap_imap::tls::build_tls_config;

#[test]
fn pinned_mode_builds_a_client_config() {
    let pin = TlsFingerprint::from_cert_der(b"synthetic-cert");
    let bundle = build_tls_config(Some(pin)).expect("pinned build_tls_config should succeed");
    // Slot starts empty; the verifier hasn't run yet.
    assert!(bundle.last_observed.get().is_none());
    // Two clones of the slot share state.
    let slot = bundle.last_observed.clone();
    assert!(slot.get().is_none());
}

#[test]
fn unpinned_mode_builds_a_client_config_with_webpki_roots() {
    let bundle = build_tls_config(None).expect("unpinned build_tls_config should succeed");
    assert!(bundle.last_observed.get().is_none());
    // We can't easily exercise the verifier without a real handshake; the
    // Dovecot integration test in Task 15 covers the success and failure
    // paths end-to-end.
}

#[test]
fn fingerprint_equality_holds_for_same_input() {
    let a = TlsFingerprint::from_cert_der(b"alpha");
    let b = TlsFingerprint::from_cert_der(b"alpha");
    let c = TlsFingerprint::from_cert_der(b"beta");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn fingerprint_is_stable_across_byte_lengths() {
    // Fingerprint output is a fixed-size SHA-256 digest regardless of the
    // input cert DER size. This protects against display or serialization
    // changes that might truncate under short inputs.
    let short = TlsFingerprint::from_cert_der(b"a");
    let long = TlsFingerprint::from_cert_der(&vec![0u8; 4096]);
    assert_eq!(short.to_string().len(), long.to_string().len());
    assert_ne!(short, long);
}

#[test]
fn pinned_config_and_unpinned_config_do_not_share_last_observed_slot() {
    // Two independent builds must produce independent slots, otherwise a
    // fingerprint observed on one connection could leak into another.
    let pinned = TlsFingerprint::from_cert_der(b"pinned");
    let pinned_cfg = build_tls_config(Some(pinned)).expect("pinned ok");
    let unpinned_cfg = build_tls_config(None).expect("unpinned ok");
    assert!(!std::sync::Arc::ptr_eq(
        &pinned_cfg.last_observed,
        &unpinned_cfg.last_observed,
    ));
}

#[test]
fn two_pinned_configs_have_independent_slots() {
    // Every build_tls_config call owns its own slot — sharing would cause
    // a stale fingerprint to persist across a pin-change config reload.
    let pin = TlsFingerprint::from_cert_der(b"same-pin");
    let a = build_tls_config(Some(pin)).expect("a ok");
    let b = build_tls_config(Some(pin)).expect("b ok");
    assert!(!std::sync::Arc::ptr_eq(&a.last_observed, &b.last_observed));
}

#[test]
fn last_observed_slot_is_a_onelock_with_only_one_write() {
    // The verifier uses `OnceLock::set`; a second set is silently ignored.
    // Documenting the semantics here prevents a future refactor from
    // replacing OnceLock with a mutable slot without understanding that
    // the first observation is what the audit record captures.
    let bundle = build_tls_config(None).expect("ok");
    let a = TlsFingerprint::from_cert_der(b"first");
    let b = TlsFingerprint::from_cert_der(b"second");
    bundle.last_observed.set(a).expect("first set ok");
    let second_set_result = bundle.last_observed.set(b);
    assert!(second_set_result.is_err());
    assert_eq!(*bundle.last_observed.get().expect("value present"), a);
}
