#!/usr/bin/env bash
# Compare a tag-style argument against the workspace version in Cargo.toml.
#
# Usage:
#   scripts/check-release-version.sh v0.1.0
#
# Exits 0 when the tag matches the workspace version, non-zero otherwise.
# Mirrors the verify-tag job in .github/workflows/release.yml so contributors
# can sanity-check before pushing a tag.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $(basename "$0") <vX.Y.Z>" >&2
    exit 64
fi

tag="$1"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: tag must match ^v[0-9]+\.[0-9]+\.[0-9]+\$ (got '$tag')" >&2
    exit 65
fi

# Strip the leading 'v'.
tag_version="${tag#v}"

# Parse workspace version. Match `version = "X.Y.Z"` only under [workspace.package].
# awk pattern: enter range on [workspace.package], exit on next section header.
workspace_version=$(
    awk '
        /^\[workspace\.package\]/ {in_section=1; next}
        in_section && /^\[/ {in_section=0}
        in_section && /^version = / {
            sub(/^version = "/, "")
            sub(/"$/, "")
            print
            exit
        }
    ' Cargo.toml
)

if [ -z "$workspace_version" ]; then
    echo "error: could not parse [workspace.package].version from Cargo.toml" >&2
    exit 66
fi

if [[ "$workspace_version" == *-* ]]; then
    echo "error: Cargo.toml workspace version contains '-' (got '$workspace_version'); release tags must point at a clean semver" >&2
    exit 67
fi

if [ "$tag_version" != "$workspace_version" ]; then
    echo "error: tag '$tag' does not match Cargo.toml workspace version '$workspace_version'" >&2
    exit 68
fi

echo "ok: tag '$tag' matches Cargo.toml workspace version '$workspace_version'"
