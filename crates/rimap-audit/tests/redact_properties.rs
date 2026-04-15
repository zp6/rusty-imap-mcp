//! Property tests for argument redaction.

#![expect(clippy::unwrap_used, reason = "tests")]

use proptest::prelude::*;
use rimap_audit::{FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments};
use rimap_core::tool::ToolName;
use serde_json::{Map, Value};

fn schema() -> RedactionSchema {
    // Property-test fixture; the specific ToolName is irrelevant — only the
    // per-field policies are exercised. Reuse an existing variant rather
    // than inventing one.
    RedactionSchema::new(
        ToolName::Search,
        &[
            ("folder", FieldPolicy::Verbatim),
            ("uid", FieldPolicy::Verbatim),
            ("subject", FieldPolicy::RedactString),
            ("body", FieldPolicy::RedactString),
            ("to", FieldPolicy::SaltedHash),
            ("password", FieldPolicy::Forbidden),
        ],
    )
}

fn salt() -> RedactionSalt {
    RedactionSalt::from_bytes([0x42_u8; 32])
}

prop_compose! {
    fn arb_input()(
        folder in prop::option::of("[A-Za-z]{1,10}"),
        uid in prop::option::of(any::<u32>()),
        subject in prop::option::of("[^\\n]{0,40}"),
        body in prop::option::of("[^\\n]{0,200}"),
        to in prop::option::of("[a-z]{1,8}@[a-z]{1,8}\\.test"),
        password in prop::option::of("[^\\n]{1,20}"),
        mystery in prop::option::of("[a-z]{1,8}"),
    ) -> Value {
        let mut m = Map::new();
        if let Some(v) = folder { m.insert("folder".into(), Value::String(v)); }
        if let Some(v) = uid { m.insert("uid".into(), Value::from(v)); }
        if let Some(v) = subject { m.insert("subject".into(), Value::String(v)); }
        if let Some(v) = body { m.insert("body".into(), Value::String(v)); }
        if let Some(v) = to { m.insert("to".into(), Value::String(v)); }
        if let Some(v) = password { m.insert("password".into(), Value::String(v)); }
        if let Some(v) = mystery { m.insert("mystery".into(), Value::String(v)); }
        Value::Object(m)
    }
}

proptest! {
    #[test]
    fn forbidden_fields_never_appear(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let obj = out.as_object().unwrap();
        prop_assert!(!obj.contains_key("password"));
    }

    #[test]
    fn verbatim_fields_pass_through_unchanged(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let in_obj = input.as_object().unwrap();
        prop_assume!(in_obj.contains_key("folder") || in_obj.contains_key("uid"));
        let out = r.apply(&input);
        let out_obj = out.as_object().unwrap();
        if let Some(v) = in_obj.get("folder") {
            prop_assert_eq!(out_obj.get("folder"), Some(v));
        }
        if let Some(v) = in_obj.get("uid") {
            prop_assert_eq!(out_obj.get("uid"), Some(v));
        }
    }

    #[test]
    fn forbidden_field_is_always_dropped_when_present(
        pw in "[^\\n]{1,20}",
        subject in prop::option::of("[^\\n]{0,40}"),
    ) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let mut m = Map::new();
        m.insert("password".to_string(), Value::String(pw));
        if let Some(v) = subject {
            m.insert("subject".to_string(), Value::String(v));
        }
        let input = Value::Object(m);
        let out = r.apply(&input);
        let obj = out.as_object().unwrap();
        prop_assert!(!obj.contains_key("password"));
    }

    #[test]
    fn redacted_strings_have_length_marker(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let in_obj = input.as_object().unwrap();
        let out_obj = out.as_object().unwrap();
        for key in ["subject", "body"] {
            if let Some(Value::String(orig)) = in_obj.get(key) {
                let v = out_obj.get(key).unwrap();
                let s = v.as_str().unwrap();
                let expected = format!("<redacted:{}>", orig.len());
                prop_assert_eq!(s, &expected);
            }
        }
    }

    #[test]
    fn output_is_always_an_object(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        prop_assert!(out.is_object());
    }

    #[test]
    fn hash_arguments_is_deterministic(input in arb_input()) {
        let a = hash_arguments(&input);
        let b = hash_arguments(&input);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn salted_hash_is_deterministic_within_process(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let a = r.apply(&input);
        let b = r.apply(&input);
        prop_assert_eq!(a, b);
    }
}
