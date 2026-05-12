#!/usr/bin/env bash
#
# Refresh (or drift-check) the vendored MCP spec schema used by the
# wire-conformance harness in crates/rimap-server/tests/. See
# docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md
# §3.4 and §3.5.
#
# Usage:
#   scripts/refresh-mcp-spec.sh <version>           # overwrite vendored copy
#   scripts/refresh-mcp-spec.sh --check <version>   # exit non-zero on drift

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures_dir="${repo_root}/crates/rimap-server/tests/fixtures/mcp-spec"
upstream_base="https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema"

mode="refresh"
if [[ "${1:-}" == "--check" ]]; then
    mode="check"
    shift
fi

version="${1:-}"
if [[ -z "${version}" ]]; then
    echo "usage: $0 [--check] <version>" >&2
    exit 64
fi

local_path="${fixtures_dir}/${version}/schema.json"
upstream_url="${upstream_base}/${version}/schema.json"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

curl --fail --show-error --silent --location "${upstream_url}" -o "${tmp}"

if ! jq empty "${tmp}" >/dev/null 2>&1; then
    echo "fetched payload is not valid JSON: ${upstream_url}" >&2
    exit 65
fi

case "${mode}" in
refresh)
    mkdir -p "$(dirname "${local_path}")"
    mv "${tmp}" "${local_path}"
    trap - EXIT
    echo "refreshed ${local_path}"
    ;;
check)
    if [[ ! -f "${local_path}" ]]; then
        echo "vendored copy missing: ${local_path}" >&2
        exit 1
    fi
    if ! diff -u "${local_path}" "${tmp}" >&2; then
        echo "DRIFT: vendored ${version}/schema.json differs from upstream" >&2
        exit 1
    fi
    echo "no drift: ${local_path}"
    ;;
esac
