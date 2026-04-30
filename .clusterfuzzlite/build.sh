#!/usr/bin/env bash
#
# ClusterFuzzLite build entry point. Builds every fuzz target in
# `fuzz/fuzz_targets/` and copies binary + seed corpus to $OUT.
#
# Release mode (-O) is required: debug builds trip upstream
# `debug_assert!` guards on malformed input.
set -euo pipefail

cd "$SRC/rusty-imap-mcp/fuzz"

cargo +nightly fuzz build -O

host_triple="$(cargo +nightly -vV | awk '/^host:/ {print $2}')"
fuzz_out_dir="target/${host_triple}/release"

for f in fuzz_targets/*.rs; do
    name="$(basename "${f%.*}")"
    cp "$fuzz_out_dir/$name" "$OUT/"
    if [ -d "corpus/$name" ]; then
        zip -j -r "$OUT/${name}_seed_corpus.zip" "corpus/$name"
    fi
done
