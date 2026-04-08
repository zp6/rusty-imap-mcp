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
    # Pick install hints based on host OS and (on Linux) distro family. We emit
    # a single concrete command per tool so the user can copy/paste it directly.
    os="$(uname -s)"
    flavor="unknown"
    if [ "$os" = "Darwin" ]; then
        flavor="mac"
    elif [ "$os" = "Linux" ] && [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        for id in ${ID:-} ${ID_LIKE:-}; do
            case "$id" in
                fedora|rhel|centos)            flavor="fedora"; break ;;
                debian|ubuntu)                 flavor="debian"; break ;;
                arch)                          flavor="arch";   break ;;
                opensuse*|suse|sles)           flavor="suse";   break ;;
            esac
        done
    fi
    hint() {
        # hint <mac> <fedora> <debian> <arch> <suse> <fallback>
        case "$flavor" in
            mac)    echo "$1" ;;
            fedora) echo "$2" ;;
            debian) echo "$3" ;;
            arch)   echo "$4" ;;
            suse)   echo "$5" ;;
            *)      echo "$6" ;;
        esac
    }
    missing=()
    need() {
        if ! command -v "$1" >/dev/null 2>&1; then
            missing+=("$1 ($2)")
        fi
    }
    CARGO_JUST='cargo install --locked just'
    CARGO_PREK='cargo install --locked prek'
    CARGO_ZIZMOR='cargo install --locked zizmor'
    GO_SHFMT='go install mvdan.cc/sh/v3/cmd/shfmt@latest'
    GO_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
    need rustup     "install from https://rustup.rs"
    need cargo      "bundled with rustup"
    need just       "$(hint 'brew install just'       'sudo dnf install just'       'sudo apt install just'       'sudo pacman -S just'       'sudo zypper install just'       "$CARGO_JUST")"
    need prek       "$(hint 'brew install prek'       "$CARGO_PREK"                 "$CARGO_PREK"                 "$CARGO_PREK"              "$CARGO_PREK"                    "$CARGO_PREK")"
    need shellcheck "$(hint 'brew install shellcheck' 'sudo dnf install ShellCheck' 'sudo apt install shellcheck' 'sudo pacman -S shellcheck' 'sudo zypper install ShellCheck' 'install shellcheck via your package manager')"
    need shfmt      "$(hint 'brew install shfmt'      'sudo dnf install shfmt'      'sudo apt install shfmt'      'sudo pacman -S shfmt'     'sudo zypper install shfmt'      "$GO_SHFMT")"
    need actionlint "$(hint 'brew install actionlint' "$GO_ACTIONLINT"              "$GO_ACTIONLINT"              "$GO_ACTIONLINT"           "$GO_ACTIONLINT"                 "$GO_ACTIONLINT")"
    need zizmor     "$(hint 'brew install zizmor'     "$CARGO_ZIZMOR"               "$CARGO_ZIZMOR"               "$CARGO_ZIZMOR"            "$CARGO_ZIZMOR"                  "$CARGO_ZIZMOR")"
    need typos      "cargo install --locked typos-cli"
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

# Unit and fast tests (no Proton Bridge).
test:
    cargo nextest run --workspace --locked --no-tests=pass

# Verify the MSRV toolchain still builds and tests the workspace.
test-msrv:
    cargo +{{MSRV}} check --workspace --all-targets --all-features --locked
    cargo +{{MSRV}} nextest run --workspace --locked --no-tests=pass

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
