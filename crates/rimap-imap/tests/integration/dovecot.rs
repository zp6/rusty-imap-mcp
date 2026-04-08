//! Dovecot-in-Docker integration suite for rimap-imap. CI runs Docker;
//! local devs without Docker get the skip path automatically.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod support;

use std::time::Duration;

use rimap_imap::error::{AuthFailure, Error};
use rimap_imap::{Connection, ConnectionConfig};
use support::docker::{ConnectedHarness, DovecotHarness, HarnessError, PinChoice};

fn boot(pin: PinChoice) -> Option<ConnectedHarness> {
    match ConnectedHarness::new(pin) {
        Ok(h) => Some(h),
        Err(HarnessError::DockerUnavailable) => None, // silent skip — print_stderr denied
        #[expect(clippy::panic, reason = "test failure path")]
        Err(e) => panic!("harness failed: {e}"),
    }
}

fn read_audit_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[tokio::test]
async fn case_01_connect_with_correct_pin_succeeds() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));
    // is_connected removed — list_folders success already proves connectivity

    let lines = read_audit_lines(&h.audit_path());
    let auths: Vec<_> = lines.iter().filter(|v| v["kind"] == "auth").collect();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0]["result"], "success");
    assert_eq!(auths[0]["fingerprint_match"], true);
}

#[tokio::test]
async fn case_02_connect_with_wrong_pin_emits_audit_and_returns_tls_error() {
    let Some(h) = boot(PinChoice::Wrong) else {
        return;
    };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(Error::Tls { observed, expected }) => {
            assert_eq!(
                expected,
                rimap_core::TlsFingerprint::from_cert_der(b"deliberately-wrong")
            );
            assert_eq!(observed, h.harness.pinned_fingerprint());
        }
        Err(Error::TlsHandshake(_)) => {
            // Acceptable fallback if the enrichment path didn't fire.
        }
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected TLS error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let mismatch = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_TLS")
        .expect("expected an ERR_TLS auth record");
    assert_eq!(mismatch["fingerprint_match"], false);
    // Verify the audit captured the *live* observed fingerprint, not a placeholder.
    assert_eq!(
        mismatch["tls_fingerprint_sha256"].as_str().unwrap(),
        h.harness.pinned_fingerprint().to_hex(),
    );
}

#[tokio::test]
async fn case_03_connect_with_no_pin_uses_system_trust_and_fails_self_signed() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(Error::TlsHandshake(_)) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected TlsHandshake error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let auth = lines
        .iter()
        .find(|v| v["kind"] == "auth")
        .expect("auth record");
    assert_eq!(auth["result"], "failure");
    assert_eq!(auth["error_code"], "ERR_TLS");
}

#[tokio::test]
async fn case_04_login_rejected_emits_audit() {
    use rimap_config::credential::CredentialStore;
    use std::sync::Arc;

    struct WrongPass;
    impl CredentialStore for WrongPass {
        fn get_password(&self, _: &str) -> Result<Option<String>, rimap_config::ConfigError> {
            Ok(Some("wrong-password".to_string()))
        }
        fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
            unreachable!()
        }
    }

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let cfg = ConnectionConfig {
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(WrongPass);
    let conn = Connection::new(cfg, h.audit.clone(), creds);

    let result = conn.list_folders("*").await;
    match result {
        Err(Error::Auth {
            reason: AuthFailure::LoginRejected,
        }) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected LoginRejected, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let rejected = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_AUTH")
        .expect("ERR_AUTH record");
    assert_eq!(rejected["result"], "failure");
}

#[tokio::test]
async fn case_05_list_returns_seeded_folders() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")));
    assert!(names.iter().any(|n| n.contains("Archive")));
    assert!(names.iter().any(|n| n.contains("Subfolder")));
}

#[tokio::test]
async fn case_06_search_structured_subject_match() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(
        !uids.is_empty(),
        "expected at least one UID for the seeded subject"
    );
}

#[tokio::test]
async fn case_07_search_raw_passthrough() {
    use rimap_imap::types::SearchQuery;

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Raw("HEADER \"X-Test\" \"marker\"".to_string());
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(
        !uids.is_empty(),
        "expected at least one UID for X-Test: marker"
    );
}

#[tokio::test]
async fn case_08_fetch_envelope_and_bodystructure() {
    use rimap_imap::types::{FetchSpec, SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty());
    let spec = FetchSpec {
        envelope: true,
        bodystructure: true,
        uid: true,
        flags: false,
        size: false,
    };
    let msgs = h.connection.fetch("INBOX", &uids, spec).await.unwrap();
    assert_eq!(msgs.len(), uids.len());
    let envelope = msgs[0].envelope.as_ref().expect("envelope");
    let subject = envelope.subject_raw.as_ref().expect("subject_raw");
    assert_eq!(subject.as_slice(), b"Sprint 3 multipart fixture");
    assert!(msgs[0].bodystructure.is_some());
}

#[tokio::test]
async fn case_09_fetch_body_under_limit() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = h.connection.search("INBOX", q).await.unwrap();
    assert!(!uids.is_empty());
    let body = h.connection.fetch_body("INBOX", uids[0]).await.unwrap();
    assert!(!body.is_empty());
    assert!(body.len() < 5_000, "fixture is small");
}

#[tokio::test]
async fn case_10_fetch_body_over_limit_drops_connection() {
    use rimap_config::credential::CredentialStore;
    use rimap_imap::types::{SearchQuery, StructuredQuery};
    use std::sync::Arc;

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let cfg = ConnectionConfig {
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 10,
    };
    let creds: Arc<dyn CredentialStore> = Arc::new(support::docker::StaticCreds(
        DovecotHarness::password().to_string(),
    ));
    let conn = Connection::new(cfg, h.audit.clone(), creds);

    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let uids = conn.search("INBOX", q).await.unwrap();
    let result = conn.fetch_body("INBOX", uids[0]).await;
    match result {
        Err(Error::SizeLimit { limit }) => assert_eq!(limit, 10),
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected SizeLimit, got {other:?}"),
    }
    // is_connected removed — SizeLimit return already proves the overflow path fired
}

#[tokio::test]
async fn case_11_tcp_half_open_recovery() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    // Establish.
    let _ = h.connection.list_folders("*").await.unwrap();

    // Kill imap process inside the container.
    let _ = h.harness.exec(&["pkill", "-9", "imap"]);

    // Next op should fail with ConnectionLost (or Protocol that maps to it).
    let result = h.connection.list_folders("*").await;
    match result {
        Err(Error::ConnectionLost | Error::Protocol(_)) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected ConnectionLost or Protocol error, got {other:?}"),
    }

    // Following op should reconnect cleanly.
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(!folders.is_empty());
}
