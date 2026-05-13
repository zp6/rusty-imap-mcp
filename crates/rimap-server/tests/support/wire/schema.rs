//! MCP-spec JSON Schema validators shared by Phase 1 and Phase 3.
//! `validator_for(fragment)` caches per-fragment validators in a
//! process-wide map; the parsed spec document is parsed exactly once.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Value, json};

use super::harness::MCP_SCHEMA_JSON;

/// Compile (once) and return a validator for a top-level definition in
/// the vendored MCP schema. `fragment` is the key under
/// `definitions` / `$defs` (e.g. `"InitializeResult"`). Returns an
/// `Arc` so multiple parallel tests can share the compiled validator
/// without lifetime gymnastics.
pub(crate) fn validator_for(fragment: &'static str) -> Arc<jsonschema::Validator> {
    // All function-scoped items declared up front so cache and parsed
    // schema lifetimes are visible from the top of the body
    // (clippy::items_after_statements).
    type Cache = Mutex<HashMap<&'static str, Arc<jsonschema::Validator>>>;
    static PARSED: OnceLock<(Value, &'static str)> = OnceLock::new();
    static CACHE: OnceLock<Cache> = OnceLock::new();

    // Parse the vendored schema exactly once and detect the
    // definitions key (`$defs` for Draft 2020-12, `definitions` for
    // older dialects). The full Value and the detected key are
    // immutable for the lifetime of the test process.
    let parsed = PARSED.get_or_init(|| {
        let full: Value = serde_json::from_str(MCP_SCHEMA_JSON).expect("parse vendored MCP schema");
        let defs_key = if full.get("$defs").is_some() {
            "$defs"
        } else {
            "definitions"
        };
        (full, defs_key)
    });
    let full = &parsed.0;
    let defs_key: &'static str = parsed.1;

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Fast path: read under the lock, return if cached.
    {
        let guard = cache.lock().expect("validator cache mutex poisoned");
        if let Some(v) = guard.get(fragment) {
            return Arc::clone(v);
        }
    }

    // Slow path: compile the fragment validator WITHOUT holding the
    // cache lock, so parallel tests compiling different fragments
    // don't serialize.
    let wrapper = json!({
        "$ref": format!("#/{defs_key}/{fragment}"),
        defs_key: full.get(defs_key).cloned().unwrap_or(json!({})),
    });
    let new_validator =
        Arc::new(jsonschema::validator_for(&wrapper).expect("compile fragment validator"));

    // Insert. If a concurrent thread already inserted while we were
    // compiling, prefer the existing entry to keep the Arc stable.
    let mut guard = cache.lock().expect("validator cache mutex poisoned");
    let entry = guard
        .entry(fragment)
        .or_insert_with(|| Arc::clone(&new_validator));
    Arc::clone(entry)
}

/// Validate a value against a vendored fragment, panicking with the
/// list of errors on failure.
pub fn assert_valid(value: &Value, fragment: &'static str) {
    let v = validator_for(fragment);
    if !v.is_valid(value) {
        let errors: Vec<String> = v.iter_errors(value).map(|e| e.to_string()).collect();
        panic!(
            "schema validation failed for fragment {fragment}:\n  {}",
            errors.join("\n  ")
        );
    }
}

/// Validate the FULL JSON-RPC envelope returned by `Harness::request`.
/// Success responses validate against `JSONRPCResultResponse`; error
/// responses validate against `JSONRPCErrorResponse`. Asserts the
/// `jsonrpc` version field on both paths. Codex adversarial review
/// finding #2 (PR #270): the previous negative-path tests checked only
/// `code` and `message` and would have missed a regression that
/// stripped `jsonrpc` or otherwise mangled the envelope.
pub fn assert_envelope_valid(response: &Value) {
    assert_eq!(
        response["jsonrpc"],
        json!("2.0"),
        "envelope must declare jsonrpc=\"2.0\"; got {response}",
    );

    let has_result = response.get("result").is_some();
    let has_error = response.get("error").is_some();
    match (has_result, has_error) {
        (true, false) => assert_valid(response, "JSONRPCResultResponse"),
        (false, true) => assert_valid(response, "JSONRPCErrorResponse"),
        (true, true) => {
            panic!("envelope must not contain both `result` and `error`; got {response}",)
        }
        (false, false) => {
            panic!("envelope must contain either `result` or `error`; got {response}",)
        }
    }
}

/// Compile (lazily, cached) a validator for the per-tool response
/// schema at `tests/fixtures/rimap-tool-schemas/<tool>.schema.json`.
/// Panics in the test process if the fixture is missing — that's the
/// signal that `just regen-tool-schemas` was not run.
#[expect(
    dead_code,
    reason = "Phase 3 e2e_wire.rs will call this to validate tool responses"
)]
pub fn validator_for_tool_response(tool: &'static str) -> Arc<jsonschema::Validator> {
    type Cache = Mutex<HashMap<&'static str, Arc<jsonschema::Validator>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let guard = cache.lock().expect("tool schema cache mutex poisoned");
        if let Some(v) = guard.get(tool) {
            return Arc::clone(v);
        }
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rimap-tool-schemas")
        .join(format!("{tool}.schema.json"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing tool-response schema fixture for {tool} at {}: {e}\n\
             Run `just regen-tool-schemas` to regenerate.",
            path.display()
        )
    });
    let parsed: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));
    let compiled = jsonschema::validator_for(&parsed)
        .unwrap_or_else(|e| panic!("invalid JSON Schema in {}: {e}", path.display()));
    let arc = Arc::new(compiled);

    let mut guard = cache.lock().expect("tool schema cache mutex poisoned");
    let entry = guard.entry(tool).or_insert_with(|| Arc::clone(&arc));
    Arc::clone(entry)
}
