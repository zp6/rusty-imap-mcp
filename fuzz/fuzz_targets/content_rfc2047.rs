#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_content::output::SecurityWarning;

fuzz_target!(|data: &[u8]| {
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = rimap_content::testutil::scrub_header_smuggling(data, &mut warnings);

    // The scrubber only operates on inputs that contain a recognizable
    // RFC 5322 header/body separator (CRLF CRLF or LF LF). For inputs
    // without one, it returns the bytes unchanged with no warning, and
    // the bare-LF-inside-encoded-word invariant below does not apply
    // (encoded-word runs in body bytes are not the smuggling concern;
    // mail-parser would reject the message before any header is read).
    //
    // Reuse the scrubber's own header-boundary detection so the harness
    // asserts on the exact header slice the scrubber processes.
    let Some((header_end, _)) = rimap_content::testutil::find_header_end(&scrubbed) else {
        return;
    };
    if !warnings.is_empty() {
        return;
    }
    let header = &scrubbed[..header_end];

    // Encoded words require `?` (=?charset?encoding?text?=); without one,
    // `in_eword` cannot flip and the scan is a no-op. Skips most fuzzer
    // inputs (random bytes rarely contain the trigger).
    if !header.contains(&b'?') {
        return;
    }

    // Invariant: when the scrubber processed a real header structure and
    // emitted no SecurityWarning, the header never contains a non-fold
    // bare LF inside an encoded-word run. Bare LF (LF not preceded by
    // CR, not followed by SP/HT fold continuation) is the smuggling
    // signal a lenient parser would treat as a header boundary.
    let mut in_eword = false;
    let mut prev = 0u8;
    for (i, &b) in header.iter().enumerate() {
        if b == b'?' && prev == b'=' {
            in_eword = true;
        }
        let is_bare_lf = b == b'\n' && prev != b'\r';
        let next = header.get(i + 1).copied().unwrap_or(0);
        let is_fold = next == b' ' || next == b'\t';
        if in_eword && is_bare_lf && !is_fold {
            panic!(
                "bare non-fold LF inside encoded-word slipped through \
                 scrub_header_smuggling"
            );
        }
        if b == b'=' && prev == b'?' {
            in_eword = false;
        }
        prev = b;
    }
});
