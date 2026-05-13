#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="crates/rimap-server/tests/fixtures/rimap-tool-schemas"
mkdir -p "$out_dir"
dump="$(cargo run --quiet -p rimap-server --features test-support \
    --bin rusty-imap-mcp --locked -- dump-tool-schemas)"
# Split the top-level object into one file per tool. Sort keys
# so the on-disk byte order is deterministic across runs.
python3 - "$dump" "$out_dir" <<'PY'
import json, sys, pathlib
dump, out_dir = sys.argv[1], pathlib.Path(sys.argv[2])
data = json.loads(dump)
for tool, schema in sorted(data.items()):
    path = out_dir / f"{tool}.schema.json"
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
PY
