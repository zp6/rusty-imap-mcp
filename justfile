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
    # Pick install hints based on host OS. On Linux we prefer language-native
    # package managers (cargo, pipx, go) since distro packages lag or are missing.
    os="$(uname -s)"
    hint() {
        local tool="$1" mac="$2" linux="$3"
        case "$os" in
            Darwin) echo "$mac" ;;
            Linux)  echo "$linux" ;;
            *)      echo "$mac (unknown OS: $os)" ;;
        esac
    }
    missing=()
    need() {
        local tool="$1"
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool ($2)")
        fi
    }
    need rustup       "install from https://rustup.rs"
    need cargo        "bundled with rustup"
    need just         "$(hint just         'brew install just'         'cargo install --locked just')"
    need prek         "$(hint prek         'brew install prek'         'cargo install --locked prek')"
    need shellcheck   "$(hint shellcheck   'brew install shellcheck'   'apt install shellcheck | dnf install ShellCheck | pacman -S shellcheck')"
    need shfmt        "$(hint shfmt        'brew install shfmt'        'go install mvdan.cc/sh/v3/cmd/shfmt@latest | apt install shfmt')"
    need actionlint   "$(hint actionlint   'brew install actionlint'   'go install github.com/rhysd/actionlint/cmd/actionlint@latest')"
    need zizmor       "$(hint zizmor       'brew install zizmor'       'cargo install --locked zizmor | pipx install zizmor')"
    need typos        "cargo install --locked typos-cli"
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
