//! Insta snapshot tests for every corpus fixture.
//!
//! Each fixture's `parse_message` output is serialized to JSON and
//! compared against a committed `.snap` file. A sanitizer change
//! that alters output produces a visible diff that a reviewer must
//! approve via `cargo insta review`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code may unwrap/expect/panic on fixture I/O"
)]

use std::fs;
use std::path::{Path, PathBuf};

use rimap_content::parse_message;

fn corpus_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("tests").join("injection-corpus"))
        .expect("could not resolve repo-root from CARGO_MANIFEST_DIR")
}

fn snapshot_one(name: &str) {
    let path = corpus_root().join(name).join("input.eml");
    let raw = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let result = parse_message(&raw);
    let value = match result {
        Ok(content) => serde_json::to_value(&content).unwrap(),
        Err(err) => serde_json::json!({
            "error_kind": error_kind_str(&err),
            "error": err.to_string(),
        }),
    };
    insta::with_settings!({ snapshot_suffix => name }, {
        insta::assert_json_snapshot!(value);
    });
}

fn error_kind_str(err: &rimap_content::ContentError) -> &'static str {
    match err {
        rimap_content::ContentError::Malformed { .. } => "Malformed",
        rimap_content::ContentError::LimitExceeded { .. } => "LimitExceeded",
        rimap_content::ContentError::Decoding { .. } => "Decoding",
        _ => "Unknown",
    }
}

#[test]
fn snapshot_prompt_injection_plaintext() {
    snapshot_one("prompt-injection-plaintext");
}

#[test]
fn snapshot_zero_width_poisoning() {
    snapshot_one("zero-width-poisoning");
}

#[test]
fn snapshot_trojan_source_bidi() {
    snapshot_one("trojan-source-bidi");
}

#[test]
fn snapshot_rfc2047_crlf_smuggling() {
    snapshot_one("rfc2047-crlf-smuggling");
}

#[test]
fn snapshot_mime_type_spoofing() {
    snapshot_one("mime-type-spoofing");
}

#[test]
fn snapshot_oversized_body() {
    snapshot_one("oversized-body");
}

#[test]
fn snapshot_multipart_bomb() {
    snapshot_one("multipart-bomb");
}

#[test]
fn snapshot_nested_rfc822() {
    snapshot_one("nested-rfc822");
}

#[test]
fn snapshot_mailing_list() {
    snapshot_one("mailing-list");
}

#[test]
fn snapshot_multilingual_negative() {
    snapshot_one("multilingual-negative");
}

#[test]
fn snapshot_attachment_path_traversal() {
    snapshot_one("attachment-path-traversal");
}

#[test]
fn snapshot_html_only_hidden_instructions() {
    snapshot_one("html-only-hidden-instructions");
}
