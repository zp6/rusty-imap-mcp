//! Adversarial corpus test harness.
//!
//! Iterates every fixture under `tests/injection-corpus/` (repo-root)
//! and runs assertions derived from the fixture's `expected.json`
//! against the output of `rimap_content::parse_message`. A single
//! `#[test]` drives all fixtures so a failure in one fixture does
//! not short-circuit the rest — instead, all failures are reported
//! in a single panic at the end.

#![expect(clippy::unwrap_used, reason = "test code may unwrap on fixture I/O")]
#![expect(clippy::expect_used, reason = "test code may expect on fixture I/O")]
#![expect(clippy::panic, reason = "test failures are reported via panic")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rimap_content::{Content, ContentError, WarningCode, parse_message};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    #[expect(dead_code, reason = "deserialized for schema compatibility, not read")]
    description: String,
    #[serde(default = "default_expect_ok")]
    expect: ExpectKind,
    #[serde(default)]
    must_contain: Vec<String>,
    #[serde(default)]
    must_not_contain: Vec<String>,
    #[serde(default)]
    warning_codes: Vec<String>,
    #[serde(default)]
    forbidden_warning_codes: Vec<String>,
    #[serde(default)]
    meta: Option<ExpectedMeta>,
    #[serde(default)]
    error_kind: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ExpectKind {
    Ok,
    Error,
}

fn default_expect_ok() -> ExpectKind {
    ExpectKind::Ok
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedMeta {
    #[serde(default)]
    mailing_list_present: Option<bool>,
    #[serde(default)]
    attachment_count: Option<usize>,
    #[serde(default)]
    body_truncated: Option<bool>,
}

fn corpus_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/rimap-content/.
    // Corpus lives at repo-root/tests/injection-corpus/.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(Path::parent) // repo-root
        .map(|root| root.join("tests").join("injection-corpus"))
        .expect("could not resolve repo-root from CARGO_MANIFEST_DIR")
}

fn load_fixtures() -> BTreeMap<String, (PathBuf, Expected)> {
    let root = corpus_root();
    let mut out = BTreeMap::new();
    let entries = match fs::read_dir(&root) {
        Ok(e) => e,
        Err(err) => panic!("could not read {}: {err}", root.display()),
    };
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let expected_path = dir.join("expected.json");
        if !expected_path.exists() {
            continue;
        }
        let json = fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", expected_path.display()));
        let expected: Expected = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("parse {}: {e}", expected_path.display()));
        out.insert(name, (dir, expected));
    }
    out
}

fn warning_code_to_label(code: WarningCode) -> &'static str {
    match code {
        WarningCode::UnicodeZeroWidthStripped => "unicode_zero_width_stripped",
        WarningCode::UnicodeBidiOverrideStripped => "unicode_bidi_override_stripped",
        WarningCode::UnicodeC0C1Stripped => "unicode_c0_c1_stripped",
        WarningCode::ParseHeaderSmugglingBlocked => "parse_header_smuggling_blocked",
        WarningCode::ParseMimeTypeMismatch => "parse_mime_type_mismatch",
        WarningCode::ParseAttachmentPolyglot => "parse_attachment_polyglot",
        WarningCode::ParseBodyTruncated => "parse_body_truncated",
        WarningCode::ParseMimeDepthExceeded => "parse_mime_depth_exceeded",
        WarningCode::ParseMimePartCountExceeded => "parse_mime_part_count_exceeded",
        WarningCode::ParseHeaderCountExceeded => "parse_header_count_exceeded",
        WarningCode::ParseAttachmentFilenameRewritten => "parse_attachment_filename_rewritten",
        WarningCode::HtmlHiddenContentDetected => "html_hidden_content_detected",
        WarningCode::HtmlLinkTextHrefMismatch => "html_link_text_href_mismatch",
        WarningCode::HtmlScriptStripped => "html_script_stripped",
        WarningCode::HtmlStyleStripped => "html_style_stripped",
        WarningCode::HtmlRemoteImageStripped => "html_remote_image_stripped",
        WarningCode::HtmlAnchorUnparsableHref => "html_anchor_unparsable_href",
        WarningCode::LookalikeMixedScript => "lookalike_mixed_script",
        WarningCode::LookalikeHomographDomain => "lookalike_homograph_domain",
        WarningCode::LookalikeIdnPunycode => "lookalike_idn_punycode",
        WarningCode::LookalikeFilenameExtensionSpoof => "lookalike_filename_extension_spoof",
        // Required because WarningCode is #[non_exhaustive] (exhaustive
        // match is not allowed outside the defining crate). Any future
        // variant reaching this arm is a test-harness gap and should
        // cause the corpus run to fail loudly.
        _ => panic!("corpus harness encountered unclassified WarningCode variant {code:?}"),
    }
}

fn error_kind_label(err: &ContentError) -> &'static str {
    match err {
        ContentError::Malformed { .. } => "Malformed",
        ContentError::LimitExceeded { .. } => "LimitExceeded",
        ContentError::Decoding { .. } => "Decoding",
        // Required because ContentError is #[non_exhaustive]. Any
        // future variant reaching this arm should fail the corpus run.
        _ => panic!("corpus harness encountered unclassified ContentError variant {err:?}"),
    }
}

fn assert_fixture(name: &str, dir: &Path, expected: &Expected) -> Result<(), String> {
    let input_path = dir.join("input.eml");
    let raw = fs::read(&input_path).map_err(|e| format!("read {}: {e}", input_path.display()))?;

    let result = parse_message(&raw);

    match (&expected.expect, result) {
        (ExpectKind::Ok, Ok(content)) => assert_ok_body(name, &content, expected),
        (ExpectKind::Ok, Err(err)) => Err(format!("{name}: expected Ok but got Err({err})")),
        (ExpectKind::Error, Ok(_)) => Err(format!("{name}: expected Err but got Ok")),
        (ExpectKind::Error, Err(err)) => assert_err_kind(name, &err, expected),
    }
}

fn assert_ok_body(name: &str, content: &Content, expected: &Expected) -> Result<(), String> {
    let body = &content.untrusted.body_text;
    for needle in &expected.must_contain {
        if !body.contains(needle) {
            return Err(format!(
                "{name}: body missing required substring {needle:?} (body={body:?})"
            ));
        }
    }
    for needle in &expected.must_not_contain {
        if body.contains(needle) {
            return Err(format!(
                "{name}: body contains forbidden substring {needle:?} (body={body:?})"
            ));
        }
    }
    let observed: Vec<&'static str> = content
        .security_warnings
        .iter()
        .map(|w| warning_code_to_label(w.code))
        .collect();
    for required in &expected.warning_codes {
        if !observed.contains(&required.as_str()) {
            return Err(format!(
                "{name}: missing required warning_code {required:?} (observed={observed:?})"
            ));
        }
    }
    for forbidden in &expected.forbidden_warning_codes {
        if observed.contains(&forbidden.as_str()) {
            return Err(format!(
                "{name}: forbidden warning_code {forbidden:?} was emitted"
            ));
        }
    }
    if let Some(meta) = &expected.meta {
        if let Some(want) = meta.mailing_list_present {
            let got = content.meta.mailing_list.is_some();
            if got != want {
                return Err(format!(
                    "{name}: meta.mailing_list_present want={want} got={got}"
                ));
            }
        }
        if let Some(want) = meta.attachment_count {
            let got = content.meta.attachments.len();
            if got != want {
                return Err(format!(
                    "{name}: meta.attachment_count want={want} got={got}"
                ));
            }
        }
        if let Some(want) = meta.body_truncated
            && content.meta.body_truncated != want
        {
            return Err(format!(
                "{name}: meta.body_truncated want={want} got={}",
                content.meta.body_truncated
            ));
        }
    }
    Ok(())
}

fn assert_err_kind(name: &str, err: &ContentError, expected: &Expected) -> Result<(), String> {
    let Some(want) = expected.error_kind.as_deref() else {
        return Err(format!("{name}: expect=error requires error_kind field"));
    };
    let got = error_kind_label(err);
    if got == want {
        Ok(())
    } else {
        Err(format!("{name}: error_kind want={want:?} got={got:?}"))
    }
}

#[test]
fn all_corpus_fixtures_pass() {
    let fixtures = load_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no fixtures found under {}",
        corpus_root().display()
    );

    let mut failures: Vec<String> = Vec::new();
    for (name, (dir, expected)) in &fixtures {
        if let Err(msg) = assert_fixture(name, dir, expected) {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n  - {}",
        failures.join("\n  - ")
    );
}
