#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Drive the public entry point. parse_message must:
    //   - never panic
    //   - reject input over MAX_MESSAGE_BYTES with a clean LimitExceeded error
    //   - never allocate beyond the configured per-part / total caps
    //
    // Crashes/panics surface as libfuzzer findings. Resource caps are
    // verified by the existing unit tests in parse/mod.rs; the fuzzer's
    // job is to find the inputs that bypass those caps.
    let _ = rimap_content::parse_message(data);
});
