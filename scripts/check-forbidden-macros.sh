#!/usr/bin/env bash
# Block println!/dbg!/todo! from non-test Rust source. Clippy also catches
# these, but this hook fails faster and gives a clearer error. Test files and
# benches are exempt because debug output there is legitimate.
set -euo pipefail

files=()
while IFS= read -r f; do
    files+=("$f")
done < <(git diff --cached --name-only --diff-filter=ACMR -- '*.rs' |
    grep -vE '(^|/)tests?/' |
    grep -vE '(^|/)benches/' ||
    true)

if [ "${#files[@]}" -eq 0 ]; then
    exit 0
fi

bad=0
for f in "${files[@]}"; do
    if grep -nE '\b(println|dbg|todo)!' "$f" >/dev/null 2>&1; then
        echo "forbidden macro in $f:" >&2
        grep -nE '\b(println|dbg|todo)!' "$f" >&2 || true
        bad=1
    fi
done

exit "$bad"
