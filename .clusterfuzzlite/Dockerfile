# ClusterFuzzLite Rust integration for rusty-imap-mcp.
#
# The base-builder-rust image ships nightly Rust + cargo-fuzz pre-installed.
# We copy the whole repo so build.sh can reach both `fuzz/` (the cargo-fuzz
# crate) and `crates/rimap-content` (its path dependency).

FROM gcr.io/oss-fuzz-base/base-builder-rust

COPY . $SRC/rusty-imap-mcp
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/rusty-imap-mcp
