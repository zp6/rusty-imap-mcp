# Developer entry points for rusty-imap-mcp.
#
# Golden rule: if `just ci` passes locally, CI will pass. Never run bare cargo
# for checks — use these targets so CI and local dev stay in lockstep.

set shell := ["bash", "-uc"]

MSRV := "1.88.0"

# Default: print available targets.
default:
    @just --list

# Verify required tooling is installed. Idempotent — run this on first clone
# and any time tooling seems off.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    # Detect host OS / Linux distro family once, then build one install hint
    # per tool targeted at that platform. Language-native package managers
    # (cargo, go) are the fallback when a distro does not ship the tool.
    os="$(uname -s)"
    flavor="unknown"
    if [ "$os" = "Darwin" ]; then
        flavor="mac"
    elif [ "$os" = "Linux" ] && [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        for id in ${ID:-} ${ID_LIKE:-}; do
            case "$id" in
                fedora|rhel|centos)  flavor="fedora"; break ;;
                debian|ubuntu)       flavor="debian"; break ;;
                arch)                flavor="arch";   break ;;
                opensuse*|suse|sles) flavor="suse";   break ;;
            esac
        done
    fi
    # Per-flavor install commands. Only the selected flavor's hints are built.
    case "$flavor" in
        mac)
            H_JUST='brew install just'
            H_PREK='brew install prek'
            H_SHELLCHECK='brew install shellcheck'
            H_SHFMT='brew install shfmt'
            H_ACTIONLINT='brew install actionlint'
            H_ZIZMOR='brew install zizmor'
            H_TYPOS='brew install typos-cli'
            ;;
        fedora)
            H_JUST='sudo dnf install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo dnf install ShellCheck'
            H_SHFMT='sudo dnf install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            ;;
        debian)
            H_JUST='sudo apt install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo apt install shellcheck'
            H_SHFMT='sudo apt install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            ;;
        arch)
            H_JUST='sudo pacman -S just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo pacman -S shellcheck'
            H_SHFMT='sudo pacman -S shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            ;;
        suse)
            H_JUST='sudo zypper install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo zypper install ShellCheck'
            H_SHFMT='sudo zypper install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            ;;
        *)
            H_JUST='cargo install --locked just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='install shellcheck via your package manager'
            H_SHFMT='go install mvdan.cc/sh/v3/cmd/shfmt@latest'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            ;;
    esac
    missing=()
    need() {
        if ! command -v "$1" >/dev/null 2>&1; then
            missing+=("$1 ($2)")
        fi
    }
    need rustup     "install from https://rustup.rs"
    need cargo      "bundled with rustup"
    need just       "$H_JUST"
    need prek       "$H_PREK"
    need shellcheck "$H_SHELLCHECK"
    need shfmt      "$H_SHFMT"
    need actionlint "$H_ACTIONLINT"
    need zizmor     "$H_ZIZMOR"
    need typos      "$H_TYPOS"
    if [ "${#missing[@]}" -ne 0 ]; then
        echo "Missing required tools:"
        printf '  - %s\n' "${missing[@]}"
        exit 1
    fi
    # Ensure MSRV toolchain is installed.
    rustup toolchain install {{MSRV}} --component clippy --component rustfmt --profile minimal
    # Ensure dev toolchain components are present (rust-toolchain.toml installs the channel).
    rustup component add clippy rustfmt
    # Cargo subcommands — check then optionally install.
    cargo deny --version >/dev/null 2>&1 || cargo install --locked cargo-deny
    cargo nextest --version >/dev/null 2>&1 || cargo install --locked cargo-nextest
    cargo msrv --version >/dev/null 2>&1 || cargo install --locked cargo-msrv
    # Optional, warn only.
    cargo mutants --version >/dev/null 2>&1 || echo "warn: cargo-mutants not installed (optional)"
    # Install pre-commit hooks.
    prek install
    echo "setup complete"

# Fast inner loop: compile-check only.
check:
    cargo check --workspace --all-targets

# Format the entire workspace in place.
fmt:
    cargo fmt --all

# Verify formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check

# Strict clippy — same flags CI uses.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Remove stale rimap-it-* pods/volumes left by SIGKILL'd test runs.
# Operates below compose to avoid the lock-exhaustion cascade where
# compose-down itself fails because podman has no free locks.
[private]
prune-containers:
    #!/usr/bin/env bash
    set -euo pipefail
    tool="${RIMAP_CONTAINER_TOOL:-}"
    if [ -z "$tool" ]; then
        if command -v docker >/dev/null 2>&1; then tool=docker
        elif command -v podman >/dev/null 2>&1; then tool=podman
        else exit 0; fi
    fi
    cutoff=$(($(date +%s) - 1800))
    # Remove stale pods (podman) or containers (docker) whose names
    # start with rimap-it- and that were created more than 30min ago.
    if [ "$tool" = "podman" ]; then
        podman pod ls --format '{{{{.Name}}' --noheading 2>/dev/null \
        | grep '^rimap-it-' \
        | while read -r pod; do
            created=$(podman pod inspect "$pod" --format '{{{{.Created}}' 2>/dev/null) || continue
            ts=$(date -d "$created" +%s 2>/dev/null) || continue
            if [ "$ts" -lt "$cutoff" ]; then
                podman pod rm -f "$pod" 2>/dev/null || true
            fi
        done || true
    fi
    # Prune orphaned rimap-it-* volumes regardless of runtime.
    "$tool" volume ls --format '{{{{.Name}}' 2>/dev/null \
    | grep '^rimap-it-' \
    | while read -r vol; do
        "$tool" volume rm -f "$vol" 2>/dev/null || true
    done || true

# Unit and fast tests (no Proton Bridge).
test: prune-containers
    cargo nextest run --workspace --locked --no-tests=pass

# Verify the MSRV toolchain still builds and tests the workspace.
test-msrv:
    cargo +{{MSRV}} check --workspace --all-targets --all-features --locked
    cargo +{{MSRV}} nextest run --workspace --locked --no-tests=pass

# Cargo-mutants survey (in-place; see docs/security/cargo-mutants-runbook.md for #235 context).
mutants *args:
    cargo mutants --in-place {{args}}

# Proton Bridge integration suite (gated on PROTON_BRIDGE_TEST=1).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${PROTON_BRIDGE_TEST:-0}" != "1" ]; then
        echo "set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests"
        exit 1
    fi
    cargo nextest run --workspace --locked --features proton-bridge-tests

# Adversarial email corpus against the content pipeline.
test-injection:
    cargo nextest run -p rimap-content --locked --test injection_corpus

# Bulk regression runner for the external EPVME malicious-email dataset.
test-epvme *args:
    ./scripts/test-epvme.sh {{args}}

# Supply-chain audit.
deny:
    cargo deny check

# Verify declared MSRV is still accurate.
audit-msrv:
    cargo msrv verify

# Full local-CI equivalent. If this passes, CI will pass.
ci: fmt-check lint test test-msrv deny
    typos

# Re-run pre-commit hooks across all files.
hooks:
    prek install
    prek run --all-files
