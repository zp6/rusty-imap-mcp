//! Build script for rimap-content.
//!
//! Parses `data/confusables.txt` (Unicode TR39) and emits a
//! `phf::Map<char, &'static str>` to `$OUT_DIR/confusables.rs`.
//! The library crate includes the generated file at compile time.

// build.rs is exempt from the workspace panic lint: any failure here must
// fail the build loudly rather than be swallowed.
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stderr)]

use std::env;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=data/confusables.txt");
    println!("cargo:rerun-if-changed=build.rs");

    let input = fs::read_to_string("data/confusables.txt")
        .expect("build: failed to read data/confusables.txt");

    let mut map_builder = phf_codegen::Map::<char>::new();
    let mut seen: std::collections::HashSet<char> = std::collections::HashSet::new();
    // phf_codegen::Map::entry borrows the value string for the lifetime of
    // the builder, so we must own the formatted literals until build() runs.
    let mut value_strings: Vec<(char, String)> = Vec::new();

    for (lineno, raw_line) in input.lines().enumerate() {
        let line = match raw_line.split_once('#') {
            Some((before, _comment)) => before,
            None => raw_line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        // TR39 confusables.txt MA format:
        //   SOURCE ; TARGET ; MA    # comment
        // where SOURCE is a single codepoint in U+HHHH form and TARGET is
        // one or more codepoints separated by spaces.
        let mut fields = line.split(';').map(str::trim);
        let src = fields.next().unwrap_or("");
        let tgt = fields.next().unwrap_or("");
        let kind = fields.next().unwrap_or("").trim();
        if !kind.starts_with("MA") {
            continue;
        }
        let Some(src_char) = parse_single_codepoint(src) else {
            continue;
        };
        if seen.contains(&src_char) {
            // Duplicate source row — TR39 has a few; we take the first.
            continue;
        }
        let Some(target_string) = parse_codepoint_sequence(tgt) else {
            panic!(
                "build: malformed target at line {}: {raw_line}\n\
                 Bump EXPECTED_MIN and re-audit when regenerating \
                 from a new Unicode version.",
                lineno + 1
            );
        };
        // phf_codegen stores values as Rust source; we emit the escaped
        // string literal directly so targets with quotes/backslashes are
        // handled correctly.
        value_strings.push((src_char, format!("{target_string:?}")));
        seen.insert(src_char);
    }
    for (src_char, value_src) in &value_strings {
        map_builder.entry(*src_char, value_src.as_str());
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join("confusables.rs");
    let mut out = BufWriter::new(
        fs::File::create(&out_path).expect("build: failed to open OUT_DIR/confusables.rs"),
    );
    writeln!(
        &mut out,
        "/// TR39 confusables map generated from data/confusables.txt."
    )
    .unwrap();
    writeln!(
        &mut out,
        "pub(crate) static CONFUSABLES: phf::Map<char, &'static str> = {};",
        map_builder.build()
    )
    .unwrap();

    eprintln!(
        "build: emitted {} confusable entries to {}",
        seen.len(),
        out_path.display()
    );
    // Unicode 16.0 produces ~6355 MA rows. This floor catches silent
    // format drift that drops more than ~2.5% of entries. Bump this
    // value and re-audit when regenerating from a new Unicode version.
    assert!(
        seen.len() >= 6200,
        "build: suspiciously small confusables map ({} entries, \
         expected >= 6200) — is data/confusables.txt the right file?",
        seen.len()
    );
}

/// Parse a single hex codepoint like `0430` into a `char`.
fn parse_single_codepoint(src: &str) -> Option<char> {
    let hex = src.trim();
    if hex.is_empty() {
        return None;
    }
    let code = u32::from_str_radix(hex, 16).ok()?;
    char::from_u32(code)
}

/// Parse a space-separated sequence of hex codepoints into a `String`.
fn parse_codepoint_sequence(src: &str) -> Option<String> {
    let mut out = String::new();
    for hex in src.split_whitespace() {
        let c = parse_single_codepoint(hex)?;
        out.push(c);
    }
    if out.is_empty() { None } else { Some(out) }
}
