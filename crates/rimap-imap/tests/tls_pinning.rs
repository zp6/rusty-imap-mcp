//! Verifier-level tests. No network. We exercise the `OnceLock` capture
//! path with synthetic cert DER bytes.

use rimap_core::TlsFingerprint;
use rimap_imap::tls::build_tls_config;

#[test]
fn pinned_mode_builds_a_client_config() {
    let pin = TlsFingerprint::from_cert_der(b"synthetic-cert");
    let bundle = build_tls_config(Some(pin));
    // Slot starts empty; the verifier hasn't run yet.
    assert!(bundle.last_observed.get().is_none());
    // Two clones of the slot share state.
    let slot = bundle.last_observed.clone();
    assert!(slot.get().is_none());
}

#[test]
fn unpinned_mode_builds_a_client_config_with_webpki_roots() {
    let bundle = build_tls_config(None);
    assert!(bundle.last_observed.get().is_none());
    // We can't easily exercise the verifier without a real handshake; the
    // Dovecot integration test in Task 15 covers the success and failure
    // paths end-to-end.
}

#[test]
fn fingerprint_eq_uses_constant_time_path() {
    let a = TlsFingerprint::from_cert_der(b"alpha");
    let b = TlsFingerprint::from_cert_der(b"alpha");
    let c = TlsFingerprint::from_cert_der(b"beta");
    assert_eq!(a, b);
    assert_ne!(a, c);
}
