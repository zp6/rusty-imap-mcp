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
    let Some((header_end, _sep_len)) = rimap_content::testutil::find_header_end(&scrubbed) else {
        return; // no header structure: scrubber returned data as-is
    };

    // Invariant: when the scrubber processed a real header structure
    // and emitted no SecurityWarning, the *header* output never contains
    // a non-fold bare LF inside an encoded-word run.
    //
    // "Non-fold" means the LF is not followed by SP or HT — RFC 5322
    // folded whitespace (LF + SP/HT) is valid header continuation and
    // cannot inject a new header line; mail-parser unfolds it to a
    // single space. The smuggling signal is a bare LF that is *not* a
    // fold continuation, i.e. one that a lenient parser would interpret
    // as a header boundary.
    //
    // CRLF (LF preceded by CR) is normal header line ending and is also
    // not the smuggling signal.
    if warnings.is_empty() {
        let header = &scrubbed[..header_end];
        let mut in_eword = false;
        let mut prev = 0u8;
        for (i, &b) in header.iter().enumerate() {
            if b == b'?' && prev == b'=' {
                in_eword = true;
            }
            if in_eword && b == b'\n' && prev != b'\r' {
                // Only flag if this is not a fold continuation.
                // A fold is LF followed immediately by SP or HT.
                let next = header.get(i + 1).copied().unwrap_or(0);
                if next != b' ' && next != b'\t' {
                    panic!(
                        "bare non-fold LF inside encoded-word slipped through \
                         scrub_header_smuggling"
                    );
                }
            }
            if b == b'=' && prev == b'?' {
                in_eword = false;
            }
            prev = b;
        }
    }
});
