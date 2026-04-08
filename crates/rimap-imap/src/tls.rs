//! `PinningVerifier` and `TlsConfig` builder. Two modes: pinned (skip chain
//! validation) and system trust (`webpki-roots`).
//!
//! ## Capturing the observed fingerprint
//!
//! Both modes wrap their verifier so the fingerprint is recorded in a
//! `OnceLock` regardless of whether the handshake succeeds. After the
//! `tokio_rustls::TlsConnector::connect` call returns, `Connection` reads
//! the slot and uses it to populate the `Auth` audit record.

use std::sync::{Arc, OnceLock};

use rimap_core::TlsFingerprint;
use tokio_rustls::rustls::DistinguishedName;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Pinned-mode verifier. Skips chain validation and accepts any cert whose
/// SHA-256 fingerprint matches the configured pin.
#[derive(Debug)]
pub(crate) struct PinningVerifier {
    pinned: TlsFingerprint,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
    /// Default rustls crypto provider we delegate to for signature scheme
    /// verification (chain validation is skipped, but signature algorithm
    /// enforcement is not — rustls requires us to honor valid signatures
    /// even when we skip chain-of-trust).
    provider: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        if self.pinned == observed {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "tls fingerprint mismatch: observed={observed}, expected={pinned}",
                pinned = self.pinned,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wraps the system-trust verifier so we still capture the observed
/// fingerprint into the same `OnceLock` slot used by pinned mode.
#[derive(Debug)]
pub(crate) struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// A `ClientConfig` plus the slot the verifier writes the observed
/// fingerprint into. Construct via [`build_tls_config`]; pass the
/// `last_observed` handle to `Connection` so it can read the value after
/// the handshake.
pub struct TlsConfigBundle {
    /// The `rustls::ClientConfig` ready to hand to `tokio_rustls::TlsConnector`.
    pub config: Arc<ClientConfig>,
    /// Slot the verifier sets exactly once during `verify_server_cert`.
    /// Empty if the handshake failed before the verifier ran.
    pub last_observed: Arc<OnceLock<TlsFingerprint>>,
}

/// Build a `TlsConfigBundle`. If `pinned.is_some()`, uses `PinningVerifier`
/// (skips chain validation). Otherwise uses webpki-roots with
/// `CapturingVerifier`.
///
/// # Errors
/// - `Error::TlsHandshake` if rustls cannot construct a `ClientConfig` with
///   the workspace's safe default protocol versions (would only fire if a
///   future ring provider drops every cipher suite or kx group).
/// - `Error::TlsHandshake` if `WebPkiServerVerifier::builder.build()` fails
///   (would only fire if `webpki_roots::TLS_SERVER_ROOTS` is somehow empty,
///   e.g. a corrupt webpki-roots release).
pub fn build_tls_config(
    pinned: Option<TlsFingerprint>,
) -> Result<TlsConfigBundle, crate::error::Error> {
    let last_observed = Arc::new(OnceLock::new());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());

    let config = if let Some(pin) = pinned {
        let verifier = Arc::new(PinningVerifier {
            pinned: pin,
            last_observed: Arc::clone(&last_observed),
            provider: Arc::clone(&provider),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::Error::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner_verifier =
            tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|e| {
                crate::error::Error::TlsHandshake(tokio_rustls::rustls::Error::General(format!(
                    "WebPkiServerVerifier builder failed: {e}"
                )))
            })?;
        let capturing = Arc::new(CapturingVerifier {
            inner: inner_verifier,
            last_observed: Arc::clone(&last_observed),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::Error::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(capturing)
            .with_no_client_auth()
    };

    Ok(TlsConfigBundle {
        config: Arc::new(config),
        last_observed,
    })
}
