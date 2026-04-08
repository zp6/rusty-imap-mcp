#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage: scripts/test-epvme.sh [--dataset-dir DIR] [--download] [--cache-dir DIR] [--limit N] [--json-out PATH]

Runs the rimap-content EPVME bulk regression runner against an extracted
dataset tree of .eml files.

Options:
  --dataset-dir DIR  Use an existing extracted dataset directory.
  --download         Download and extract EPVME archives into the cache dir.
  --cache-dir DIR    Cache directory for downloaded zips and extracted data.
                     Default: target/epvme-cache
  --limit N          Process at most N .eml files.
  --json-out PATH    Write a JSON summary report.
  --help             Show this help text.
EOF
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

resolve_zip_dir() {
    local cache_dir="$1"

    if [ -f "$cache_dir/EPVME_1.zip" ]; then
        printf '%s\n' "$cache_dir"
        return
    fi

    printf '%s\n' "$cache_dir/zips"
}

download_archives() {
    local zip_dir="$1"
    mkdir -p "$zip_dir"

    local base_url="https://raw.githubusercontent.com/sunknighteric/EPVME-Dataset/main"
    local archive
    for archive in EPVME_1.zip EPVME_2.zip EPVME_3.zip EPVME_4.zip EPVME_5.zip EPVME_6.zip EPVME_7.zip EPVME_8.zip; do
        if [ -f "$zip_dir/$archive" ]; then
            continue
        fi
        echo "downloading $archive"
        curl -fL --retry 3 --output "$zip_dir/$archive" "$base_url/$archive"
    done
}

extract_archives() {
    local zip_dir="$1"
    local extract_dir="$2"
    local marker="$extract_dir/.extracted-complete"

    if [ -f "$marker" ]; then
        return
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"

    local archive
    for archive in "$zip_dir"/EPVME_*.zip; do
        unzip -oq "$archive" -d "$extract_dir"
    done

    touch "$marker"
}

dataset_dir=""
cache_dir="target/epvme-cache"
download_mode=0
limit=""
json_out=""

while [ "$#" -gt 0 ]; do
    case "$1" in
    --dataset-dir)
        if [ "$#" -lt 2 ]; then
            echo "--dataset-dir requires a value" >&2
            exit 2
        fi
        dataset_dir="$2"
        shift 2
        ;;
    --download)
        download_mode=1
        shift
        ;;
    --cache-dir)
        if [ "$#" -lt 2 ]; then
            echo "--cache-dir requires a value" >&2
            exit 2
        fi
        cache_dir="$2"
        shift 2
        ;;
    --limit)
        if [ "$#" -lt 2 ]; then
            echo "--limit requires a value" >&2
            exit 2
        fi
        limit="$2"
        shift 2
        ;;
    --json-out)
        if [ "$#" -lt 2 ]; then
            echo "--json-out requires a value" >&2
            exit 2
        fi
        json_out="$2"
        shift 2
        ;;
    --help | -h)
        usage
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
done

require_tool cargo

if [ -n "$dataset_dir" ] && [ "$download_mode" -eq 1 ]; then
    echo "choose either --dataset-dir or --download" >&2
    exit 2
fi

if [ "$download_mode" -eq 1 ]; then
    require_tool curl
    require_tool unzip
    mkdir -p "$cache_dir"
    zip_dir="$(resolve_zip_dir "$cache_dir")"
    download_archives "$zip_dir"
    extract_archives "$zip_dir" "$cache_dir/extracted"
    dataset_dir="$cache_dir/extracted"
fi

if [ -z "$dataset_dir" ]; then
    echo "either --dataset-dir or --download is required" >&2
    usage >&2
    exit 2
fi

runner_args=("$dataset_dir")
if [ -n "$limit" ]; then
    runner_args+=(--limit "$limit")
fi
if [ -n "$json_out" ]; then
    runner_args+=(--json-out "$json_out")
fi

cargo run -p rimap-content --locked --bin epvme_runner -- "${runner_args[@]}"
