#!/usr/bin/env bash
# Refuse to commit on main or master. Enforces the global rule that all work
# happens on feature branches.
set -euo pipefail

branch="$(git rev-parse --abbrev-ref HEAD)"
case "$branch" in
main | master)
    echo "refusing to commit on protected branch: $branch" >&2
    echo "create a feature branch: git checkout -b feat/your-feature" >&2
    exit 1
    ;;
esac
