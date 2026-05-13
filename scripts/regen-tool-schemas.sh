#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="crates/rimap-server/tests/fixtures/rimap-tool-schemas"
mkdir -p "$out_dir"
# Pipe the dump on stdin instead of passing it as an argv element so
# the script does not trip ARG_MAX on Linux when schemas grow large.
# `python3 -c` keeps the script inline (a heredoc would shadow the
# piped stdin).
# Split the top-level object into one file per tool. Sort keys
# so the on-disk byte order is deterministic across runs.
cargo run --quiet -p rimap-server --features test-support \
    --bin rusty-imap-mcp --locked -- dump-tool-schemas |
    python3 -c '
import json, sys, pathlib
out_dir = pathlib.Path(sys.argv[1])
data = json.load(sys.stdin)
for tool, schema in sorted(data.items()):
    path = out_dir / f"{tool}.schema.json"
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
' "$out_dir"
