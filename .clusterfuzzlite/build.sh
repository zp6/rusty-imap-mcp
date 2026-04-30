#!/bin/bash -eu
#
# ClusterFuzzLite build entry point. Compiles each fuzz target in
# `fuzz/fuzz_targets/` and copies the resulting binary plus its seed
# corpus to $OUT, where ClusterFuzzLite expects them.
#
# `cargo +nightly fuzz build -O` matches the local `just fuzz` invocation
# pattern; the `-O` flag is load-bearing because mail-parser 0.11.2 trips
# internal `debug_assert!` guards on malformed multipart input in debug
# builds.

cd "$SRC/rusty-imap-mcp/fuzz"

cargo +nightly fuzz build -O

FUZZ_TARGET_OUTPUT_DIR="target/x86_64-unknown-linux-gnu/release"

for f in fuzz_targets/*.rs; do
    name="$(basename "${f%.*}")"
    cp "$FUZZ_TARGET_OUTPUT_DIR/$name" "$OUT/"
    if [ -d "corpus/$name" ]; then
        zip -j -r "$OUT/${name}_seed_corpus.zip" "corpus/$name"
    fi
done
