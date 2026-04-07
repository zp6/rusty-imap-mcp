# Sprint 0 — Repo Scaffolding & Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a `rusty-imap-mcp` repo that compiles an empty workspace, refuses unformatted/unlinted/unsafe code via both local hooks and CI, pins MSRV to 1.85.1, and has docs/license/changelog scaffolding in place. Zero feature code. The gate that every future sprint passes through.

**Architecture:** Cargo workspace with seven empty member crates (six libs + one bin), shared `[workspace.dependencies]` and `[workspace.lints]`, dev toolchain pinned via `rust-toolchain.toml`, MSRV verified independently in CI, `just` as the developer entry point, `prek` enforcing the same checks pre-commit. Supply-chain gated by `cargo-deny`. GitHub Actions SHA-pinned with `zizmor` self-check.

**Tech Stack:** Rust 1.85.1 MSRV (dev toolchain: current stable 1.94.0), Cargo workspace, `cargo-deny`, `cargo-nextest`, `cargo-msrv`, `just`, `prek`, `shellcheck`, `shfmt`, `actionlint`, `zizmor`, `typos`.

**Spec reference:** `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md` — this plan implements Sprint 0 (Section 12 "Development Roadmap").

---

## Context for the implementing engineer

You're starting from a clean repo with only the design spec committed. There is no feature code to test, so "TDD" in this sprint means: **set up each guardrail, prove it rejects bad input, prove it accepts the clean state, commit.** Every task has a negative verification step where you intentionally break something and watch the guardrail catch it, then revert.

Working directory is `/Users/dave/src/rusty-imap-mcp` throughout this plan.

**Starting branch state:** the repo is currently on `spec/initial-design` with the design spec committed. Sprint 0 work starts from a new branch off `spec/initial-design` so the spec travels with it; `main` will receive both the spec and Sprint 0 as one merge when Sprint 0 is complete.

**Do not add dependencies beyond what this plan specifies.** Feature crates (`async-imap`, `rmcp`, `mail-parser`, etc.) land in Sprints 1–5, not here. The member crates in this sprint are *empty* placeholders.

**Important constraints from the global CLAUDE.md:**
- Never commit on `main`/`master`.
- Never skip hooks (`--no-verify`) unless explicitly asked.
- 100-char line length.
- No relative imports (Rust: absolute paths from crate root).
- Fix every warning; zero-warnings baseline.

## File Structure (end state of Sprint 0)

```
rusty-imap-mcp/
├── Cargo.toml                        # workspace root
├── Cargo.lock                        # committed
├── rust-toolchain.toml               # dev toolchain pin
├── rustfmt.toml                      # formatter config
├── deny.toml                         # cargo-deny policy
├── justfile                          # developer entry points
├── .pre-commit-config.yaml           # prek hooks
├── .gitignore
├── README.md                         # rewritten from existing
├── SECURITY.md                       # new
├── CHANGELOG.md                      # new, seeded [Unreleased]
├── LICENSE-MIT                       # new
├── LICENSE-APACHE                    # new
├── typos.toml                        # typo-checker allowlist
├── crates/
│   ├── rimap-core/{Cargo.toml,src/lib.rs}
│   ├── rimap-config/{Cargo.toml,src/lib.rs}
│   ├── rimap-imap/{Cargo.toml,src/lib.rs}
│   ├── rimap-content/{Cargo.toml,src/lib.rs}
│   ├── rimap-audit/{Cargo.toml,src/lib.rs}
│   ├── rimap-authz/{Cargo.toml,src/lib.rs}
│   └── rimap-server/{Cargo.toml,src/main.rs}
├── scripts/
│   ├── check-branch-name.sh          # pre-commit: reject commits on main/master
│   └── check-forbidden-macros.sh     # pre-commit: reject println!/dbg!/todo!
└── .github/
    ├── workflows/ci.yml
    └── dependabot.yml
```

---

## Task 1: Create feature branch

**Files:** none (git state only)

- [ ] **Step 1: Verify current state**

Run: `git status && git branch --show-current`
Expected: working tree clean, branch `spec/initial-design`.

- [ ] **Step 2: Create and switch to feature branch**

Run: `git checkout -b feat/sprint-0-scaffold`
Expected: `Switched to a new branch 'feat/sprint-0-scaffold'`.

- [ ] **Step 3: Verify**

Run: `git branch --show-current`
Expected: `feat/sprint-0-scaffold`.

---

## Task 2: Workspace root `Cargo.toml`

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore`

- [ ] **Step 1: Write `.gitignore`**

Create `.gitignore`:

```gitignore
/target
**/*.rs.bk
*.pdb
.DS_Store
.idea/
.vscode/
*.swp
```

- [ ] **Step 2: Write workspace `Cargo.toml`**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/rimap-core",
    "crates/rimap-config",
    "crates/rimap-imap",
    "crates/rimap-content",
    "crates/rimap-audit",
    "crates/rimap-authz",
    "crates/rimap-server",
]

[workspace.package]
version = "0.0.0"
edition = "2024"
rust-version = "1.85.1"
license = "MIT OR Apache-2.0"
repository = "https://github.com/davidchristensen/rusty-imap-mcp"
authors = ["David Christensen"]
readme = "README.md"

# Dependency versions are declared once here and inherited by member crates via
# `foo = { workspace = true }`. No member crate may declare a version directly.
# Sprint 0 intentionally declares zero runtime dependencies — features land in
# later sprints.
[workspace.dependencies]

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
# Panic prevention
unwrap_used = "deny"
expect_used = "warn"
panic = "deny"
panic_in_result_fn = "deny"
unimplemented = "deny"
# No cheating
allow_attributes = "deny"
# Code hygiene
dbg_macro = "deny"
todo = "deny"
print_stdout = "deny"
print_stderr = "deny"
# Safety
await_holding_lock = "deny"
large_futures = "deny"
exit = "deny"
mem_forget = "deny"
# Pedantic relaxations (too noisy in practice)
module_name_repetitions = "allow"
similar_names = "allow"

[profile.release]
lto = "thin"
codegen-units = 1
strip = "debuginfo"
```

- [ ] **Step 3: Verify the file is syntactically well-formed**

Run: `cargo metadata --no-deps --format-version 1 > /dev/null 2>&1 ; echo exit=$?`

This will fail because the member crates don't exist yet — that's expected. The point of this step is to catch TOML syntax errors before moving on. If the error message mentions "failed to load manifest" for a crates/ path, the TOML parsed correctly and we're good. If it mentions "expected" or a line/column number in `Cargo.toml` itself, fix the TOML.

Expected: non-zero exit, error about missing `crates/rimap-core/Cargo.toml` (or similar missing member). **Not** a TOML parse error on the root manifest.

---

## Task 3: Create empty member crates

**Files:**
- Create: `crates/rimap-core/Cargo.toml`
- Create: `crates/rimap-core/src/lib.rs`
- Create: `crates/rimap-config/Cargo.toml`
- Create: `crates/rimap-config/src/lib.rs`
- Create: `crates/rimap-imap/Cargo.toml`
- Create: `crates/rimap-imap/src/lib.rs`
- Create: `crates/rimap-content/Cargo.toml`
- Create: `crates/rimap-content/src/lib.rs`
- Create: `crates/rimap-audit/Cargo.toml`
- Create: `crates/rimap-audit/src/lib.rs`
- Create: `crates/rimap-authz/Cargo.toml`
- Create: `crates/rimap-authz/src/lib.rs`
- Create: `crates/rimap-server/Cargo.toml`
- Create: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Write each library crate**

For each of `rimap-core`, `rimap-config`, `rimap-imap`, `rimap-content`, `rimap-audit`, `rimap-authz`, create `crates/<name>/Cargo.toml`:

```toml
[package]
name = "<name>"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "<one-line description from list below>"

[lints]
workspace = true

[dependencies]
```

Use these descriptions (copy exactly, including quotes):

| Crate | Description |
|---|---|
| `rimap-core` | `"Shared core types for rusty-imap-mcp: Message, Folder, Posture, audit records."` |
| `rimap-config` | `"Configuration loading, validation, and credential resolution for rusty-imap-mcp."` |
| `rimap-imap` | `"Async IMAP session wrapper with TLS fingerprint pinning for rusty-imap-mcp."` |
| `rimap-content` | `"MIME parsing, Unicode-safe sanitization, and look-alike detection for rusty-imap-mcp."` |
| `rimap-audit` | `"Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp."` |
| `rimap-authz` | `"Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp."` |

And create `crates/<name>/src/lib.rs` for each of those six library crates:

```rust
//! <description, copied from the Cargo.toml `description` field, without surrounding quotes>
//!
//! This crate is a placeholder during Sprint 0. Real functionality lands in later sprints.

#![deny(missing_docs)]
```

- [ ] **Step 2: Write the server (binary) crate manifest**

Create `crates/rimap-server/Cargo.toml`:

```toml
[package]
name = "rimap-server"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Rusty IMAP MCP server: security-first MCP server for IMAP email access."

[lints]
workspace = true

[[bin]]
name = "rusty-imap-mcp"
path = "src/main.rs"

[dependencies]
```

- [ ] **Step 3: Write the server `main.rs`**

Create `crates/rimap-server/src/main.rs`:

```rust
//! Rusty IMAP MCP server entry point.
//!
//! Sprint 0 placeholder: prints a banner and exits. Real MCP wiring lands in Sprint 5.

fn main() {
    eprintln!("rusty-imap-mcp (sprint 0 placeholder) — no functionality yet");
}
```

Note: we use `eprintln!` intentionally — `println!` is denied by the workspace lints because stdout is reserved for MCP transport. `eprintln!` is permitted.

Wait — re-check: the workspace lint set has `print_stdout = "deny"` and `print_stderr = "deny"`. Both are denied. That means this `eprintln!` will fail clippy.

Resolution: use `tracing` later, but for Sprint 0 we have no dependencies. Instead, write main as a silent exit:

```rust
//! Rusty IMAP MCP server entry point.
//!
//! Sprint 0 placeholder: exits immediately. Real MCP wiring lands in Sprint 5.

fn main() {
    // Intentionally silent: stdout is reserved for MCP transport, and the
    // workspace lint set denies stderr printing as well. Real logging via
    // `tracing` lands in Sprint 1.
}
```

- [ ] **Step 4: Verify the workspace builds**

Run: `cargo build --workspace --all-targets`
Expected: successful build of all seven crates, no warnings. If warnings appear, fix them before moving on.

- [ ] **Step 5: Verify clippy passes**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean exit, no warnings, no errors.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore crates/
git commit -m "chore: bootstrap cargo workspace with empty member crates"
```

---

## Task 4: `rust-toolchain.toml` (dev toolchain pin)

**Files:**
- Create: `rust-toolchain.toml`

- [ ] **Step 1: Write the file**

Create `rust-toolchain.toml`:

```toml
# Pins the *development* toolchain. MSRV is a separate concern enforced by CI.
# Developers working on this repo will automatically get this toolchain via
# rustup when they cd into the directory.
[toolchain]
channel = "1.94.0"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

- [ ] **Step 2: Verify**

Run: `rustc --version`
Expected: `rustc 1.94.0 (...)` (rustup will auto-install if missing).

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add rust-toolchain.toml
git commit -m "chore: pin development toolchain to 1.94.0"
```

---

## Task 5: `rustfmt.toml` and verify formatting

**Files:**
- Create: `rustfmt.toml`

- [ ] **Step 1: Write the file**

Create `rustfmt.toml`:

```toml
# Stable-compatible formatter settings. Nightly-only options are commented out.
edition = "2024"
max_width = 100
use_small_heuristics = "Default"
newline_style = "Unix"
hard_tabs = false
tab_spaces = 4
```

- [ ] **Step 2: Format the workspace**

Run: `cargo fmt --all`
Expected: no output (nothing to change) or minor whitespace adjustments.

- [ ] **Step 3: Verify clean**

Run: `cargo fmt --all -- --check`
Expected: clean exit, zero diff.

- [ ] **Step 4: Commit**

```bash
git add rustfmt.toml crates/
git commit -m "chore: add rustfmt config (100-char lines, edition 2024)"
```

---

## Task 6: `cargo-deny` policy

**Files:**
- Create: `deny.toml`

- [ ] **Step 1: Install cargo-deny if missing**

Run: `cargo deny --version || cargo install --locked cargo-deny`
Expected: prints a version, installing if necessary.

- [ ] **Step 2: Write `deny.toml`**

Create `deny.toml`:

```toml
# cargo-deny policy for rusty-imap-mcp. Four concerns: advisories, licenses,
# bans (duplicate versions, disallowed crates), and sources (registry allowlist).

[graph]
targets = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
]

[advisories]
version = 2
yanked = "deny"
ignore = []

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "CC0-1.0",
    "MPL-2.0",
]
confidence-threshold = 0.93

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"
# Documented exceptions go here. Must stay empty until proven necessary.
skip = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

- [ ] **Step 3: Run cargo-deny**

Run: `cargo deny check`
Expected: four checks (advisories, bans, licenses, sources) all pass. With zero runtime dependencies in Sprint 0 this should be trivially green.

- [ ] **Step 4: Commit**

```bash
git add deny.toml
git commit -m "chore: add cargo-deny policy (advisories, licenses, bans, sources)"
```

---

## Task 7: `typos` allowlist

**Files:**
- Create: `typos.toml`

- [ ] **Step 1: Install typos if missing**

Run: `typos --version || cargo install --locked typos-cli`
Expected: prints version.

- [ ] **Step 2: Write `typos.toml`**

Create `typos.toml`:

```toml
[default]
extend-ignore-re = [
    # Allow hex blobs used in doc examples
    "[0-9a-f]{32,}",
]

[default.extend-words]
# Intentional project vocabulary. Add sparingly with a comment.
imap = "imap"
rimap = "rimap"

[files]
extend-exclude = [
    "target/",
    "Cargo.lock",
]
```

- [ ] **Step 3: Run**

Run: `typos`
Expected: no typos found.

- [ ] **Step 4: Commit**

```bash
git add typos.toml
git commit -m "chore: add typos config with project vocabulary"
```

---

## Task 8: `justfile`

**Files:**
- Create: `justfile`

- [ ] **Step 1: Install `just` if missing**

Run: `just --version || brew install just`
Expected: prints version.

- [ ] **Step 2: Write `justfile`**

Create `justfile`:

```makefile
# Developer entry points for rusty-imap-mcp.
#
# Golden rule: if `just ci` passes locally, CI will pass. Never run bare cargo
# for checks — use these targets so CI and local dev stay in lockstep.

set shell := ["bash", "-uc"]

MSRV := "1.85.1"

# Default: print available targets.
default:
    @just --list

# Verify required tooling is installed. Idempotent — run this on first clone
# and any time tooling seems off.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=()
    need() {
        if ! command -v "$1" >/dev/null 2>&1; then
            missing+=("$1 ($2)")
        fi
    }
    need rustup "install from https://rustup.rs"
    need cargo "bundled with rustup"
    need just "brew install just"
    need prek "brew install prek"
    need shellcheck "brew install shellcheck"
    need shfmt "brew install shfmt"
    need actionlint "brew install actionlint"
    need zizmor "brew install zizmor"
    need typos "cargo install --locked typos-cli"
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
    cargo nextest run --workspace --locked

# Verify the MSRV toolchain still builds and tests the workspace.
test-msrv:
    cargo +{{MSRV}} check --workspace --all-targets --all-features --locked
    cargo +{{MSRV}} nextest run --workspace --locked

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
```

Note: `just` uses Makefile-style tabs for recipe bodies. Verify with `just --list` after saving.

- [ ] **Step 3: Verify `just` parses the file**

Run: `just --list`
Expected: a table of targets.

- [ ] **Step 4: Run the fast targets to verify they work**

Run: `just check && just fmt-check && just lint`
Expected: all three green.

- [ ] **Step 5: Commit**

```bash
git add justfile
git commit -m "chore: add justfile with setup, check, lint, test, ci targets"
```

---

## Task 9: Pre-commit hook scripts

**Files:**
- Create: `scripts/check-branch-name.sh`
- Create: `scripts/check-forbidden-macros.sh`

- [ ] **Step 1: Write `scripts/check-branch-name.sh`**

Create `scripts/check-branch-name.sh`:

```bash
#!/usr/bin/env bash
# Refuse to commit on main or master. Enforces the global rule that all work
# happens on feature branches.
set -euo pipefail

branch="$(git rev-parse --abbrev-ref HEAD)"
case "$branch" in
    main|master)
        echo "refusing to commit on protected branch: $branch" >&2
        echo "create a feature branch: git checkout -b feat/your-feature" >&2
        exit 1
        ;;
esac
```

Make it executable: `chmod +x scripts/check-branch-name.sh`

- [ ] **Step 2: Write `scripts/check-forbidden-macros.sh`**

Create `scripts/check-forbidden-macros.sh`:

```bash
#!/usr/bin/env bash
# Block println!/dbg!/todo! from non-test Rust source. Clippy also catches
# these, but this hook fails faster and gives a clearer error. Test files and
# benches are exempt because debug output there is legitimate.
set -euo pipefail

files=()
while IFS= read -r f; do
    files+=("$f")
done < <(git diff --cached --name-only --diff-filter=ACMR -- '*.rs' \
    | grep -vE '(^|/)tests?/' \
    | grep -vE '(^|/)benches/' \
    || true)

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
```

Make it executable: `chmod +x scripts/check-forbidden-macros.sh`

- [ ] **Step 3: Verify both scripts pass shellcheck**

Run: `shellcheck scripts/check-branch-name.sh scripts/check-forbidden-macros.sh`
Expected: clean, no findings.

- [ ] **Step 4: Verify `shfmt` is happy**

Run: `shfmt -i 4 -d scripts/`
Expected: no diff output.

- [ ] **Step 5: Test `check-branch-name.sh` positive case**

On `feat/sprint-0-scaffold`, run: `bash scripts/check-branch-name.sh`
Expected: exit 0, no output.

- [ ] **Step 6: Test `check-branch-name.sh` negative case (without actually switching)**

Run: `HEAD_OVERRIDE=main bash -c 'git() { if [ "$1" = "rev-parse" ]; then echo main; else command git "$@"; fi; }; export -f git; bash scripts/check-branch-name.sh' ; echo exit=$?`

This temporarily shims `git rev-parse` to return `main`. Expected output includes `refusing to commit on protected branch: main` and `exit=1`.

- [ ] **Step 7: Commit**

```bash
git add scripts/
git commit -m "chore: add branch-name and forbidden-macro pre-commit hook scripts"
```

---

## Task 10: `prek` pre-commit config

**Files:**
- Create: `.pre-commit-config.yaml`

- [ ] **Step 1: Install `prek` if missing**

Run: `prek --version || brew install prek`
Expected: prints version.

- [ ] **Step 2: Write `.pre-commit-config.yaml`**

Create `.pre-commit-config.yaml`:

```yaml
# prek (pre-commit-in-Rust) configuration for rusty-imap-mcp.
#
# Fast blocking checks run on every commit; slower checks run on push.
# Hook revs are cooldown-managed via `prek auto-update --cooldown-days 7`.

default_install_hook_types: [pre-commit, pre-push]
fail_fast: false

repos:
  # Generic whitespace and basic hygiene.
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-merge-conflict
      - id: check-toml
      - id: check-yaml
      - id: check-added-large-files
        args: ["--maxkb=500"]
      - id: mixed-line-ending
        args: ["--fix=lf"]

  # Rust formatting and linting (pre-commit stage).
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all -- --check
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --all-targets --locked -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]

      - id: branch-name
        name: refuse commits on main/master
        entry: scripts/check-branch-name.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]

      - id: forbidden-macros
        name: forbid println!/dbg!/todo! in non-test Rust source
        entry: scripts/check-forbidden-macros.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]

  # Shell script hygiene.
  - repo: https://github.com/shellcheck-py/shellcheck-py
    rev: v0.10.0.1
    hooks:
      - id: shellcheck
        files: \.sh$

  - repo: https://github.com/scop/pre-commit-shfmt
    rev: v3.10.0-2
    hooks:
      - id: shfmt
        args: ["-i", "4", "-d"]

  # GitHub Actions lint + security audit (only when touched).
  - repo: https://github.com/rhysd/actionlint
    rev: v1.7.7
    hooks:
      - id: actionlint
        files: ^\.github/workflows/.*\.ya?ml$

  - repo: https://github.com/woodruffw/zizmor-pre-commit
    rev: v1.5.2
    hooks:
      - id: zizmor
        files: ^\.github/workflows/.*\.ya?ml$

  # Typo checker.
  - repo: https://github.com/crate-ci/typos
    rev: v1.29.4
    hooks:
      - id: typos

  # Pre-push stage: slower tests and audits.
  - repo: local
    hooks:
      - id: cargo-nextest
        name: cargo nextest run --workspace
        entry: cargo nextest run --workspace --locked
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-push]

      - id: cargo-deny
        name: cargo deny check advisories bans
        entry: cargo deny check advisories bans
        language: system
        pass_filenames: false
        stages: [pre-push]
```

- [ ] **Step 3: Install the hooks**

Run: `prek install`
Expected: `pre-commit installed at .git/hooks/pre-commit` and similar for pre-push.

- [ ] **Step 4: Run the hooks against all files**

Run: `prek run --all-files`
Expected: all hooks pass. If `cargo-clippy` or `cargo-fmt` touches files unexpectedly, investigate — the workspace should be clean at this point.

Note: `prek` will download and pin the upstream hook repos on first run. This can take a minute.

- [ ] **Step 5: Negative test — verify `branch-name` blocks a main commit**

Run (simulating main, does not actually switch branches):
```bash
git update-ref refs/heads/sprint-0-backup HEAD
git checkout -B main
touch /tmp/dummy-sprint-0.txt
git add /tmp/dummy-sprint-0.txt 2>/dev/null || true  # this will no-op outside repo
# attempt the hook directly
bash scripts/check-branch-name.sh ; echo exit=$?
git checkout feat/sprint-0-scaffold
```
Expected: the `bash scripts/check-branch-name.sh` line prints a refusal and exits 1.

If uncomfortable creating a local `main` ref, skip this step — the direct script test in Task 9 Step 6 already covered the logic.

- [ ] **Step 6: Negative test — verify `forbidden-macros` blocks a `println!`**

Run:
```bash
# Inject a forbidden macro into main.rs temporarily.
cat >> crates/rimap-server/src/main.rs <<'EOF'

fn _forbidden() {
    println!("this should be rejected");
}
EOF
git add crates/rimap-server/src/main.rs
bash scripts/check-forbidden-macros.sh ; echo exit=$?
git reset crates/rimap-server/src/main.rs
git checkout -- crates/rimap-server/src/main.rs
```
Expected: the hook script prints `forbidden macro in crates/rimap-server/src/main.rs:` and exits 1. After the `git checkout --`, the file is restored.

Verify restoration: `git diff -- crates/rimap-server/src/main.rs` should show no diff.

- [ ] **Step 7: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "chore: add prek pre-commit and pre-push hook configuration"
```

The commit itself goes through the hooks you just installed; if any hook fails, fix the issue and commit again (no `--amend`, no `--no-verify`).

---

## Task 11: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Look up current action SHAs**

Before writing the workflow, fetch the latest release SHAs for each action you'll pin. Use `gh` if available, otherwise the GitHub API directly.

Run:
```bash
for repo in actions/checkout dtolnay/rust-toolchain Swatinem/rust-cache taiki-e/install-action EmbarkStudios/cargo-deny-action; do
    echo "=== $repo ==="
    gh api "repos/$repo/releases/latest" --jq '.tag_name + " " + .target_commitish' 2>/dev/null \
        || curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep -E '"tag_name"|"target_commitish"'
done
```

For each action, resolve the tag to a full commit SHA:
```bash
for ref in "actions/checkout@<tag>" "Swatinem/rust-cache@<tag>" "taiki-e/install-action@<tag>" "EmbarkStudios/cargo-deny-action@<tag>"; do
    repo="${ref%@*}"; tag="${ref#*@}"
    gh api "repos/$repo/git/ref/tags/$tag" --jq '.object.sha' 2>/dev/null \
        || curl -fsSL "https://api.github.com/repos/$repo/git/refs/tags/$tag" | grep '"sha"' | head -1
done
```

For `dtolnay/rust-toolchain`, pin to the tag matching the MSRV directly (`dtolnay/rust-toolchain@1.85.1`) — this action publishes per-version tags that resolve to specific SHAs. Resolve that tag to a SHA the same way.

Record the resolved SHAs in your shell history or a scratchpad. You'll substitute them into the workflow template below.

- [ ] **Step 2: Write `.github/workflows/ci.yml`**

Create `.github/workflows/ci.yml`. Replace the `<SHA>` placeholders with the SHAs you resolved in Step 1. Keep the version comment next to each SHA so human review can verify the pin at a glance.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"
  CARGO_INCREMENTAL: 0

jobs:
  fmt:
    name: rustfmt
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # 1.94.0
        with:
          toolchain: 1.94.0
          components: rustfmt
      - run: cargo fmt --all -- --check

  clippy:
    name: clippy
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # 1.94.0
        with:
          toolchain: 1.94.0
          components: clippy
      - uses: Swatinem/rust-cache@<SHA>  # v2.x.y
      - run: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

  test:
    name: test (stable)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # 1.94.0
        with:
          toolchain: 1.94.0
      - uses: Swatinem/rust-cache@<SHA>  # v2.x.y
      - uses: taiki-e/install-action@<SHA>  # v2.x.y
        with:
          tool: cargo-nextest
      - run: cargo nextest run --workspace --locked

  msrv:
    name: test (MSRV 1.85.1)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # 1.85.1
        with:
          toolchain: 1.85.1
      - uses: Swatinem/rust-cache@<SHA>  # v2.x.y
        with:
          key: msrv
      - run: cargo check --workspace --all-targets --all-features --locked
      - uses: taiki-e/install-action@<SHA>  # v2.x.y
        with:
          tool: cargo-nextest
      - run: cargo nextest run --workspace --locked

  deny:
    name: cargo-deny
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: EmbarkStudios/cargo-deny-action@<SHA>  # v2.x.y
        with:
          command: check advisories licenses bans sources

  zizmor:
    name: zizmor self-check
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.y
        with:
          persist-credentials: false
      - uses: taiki-e/install-action@<SHA>  # v2.x.y
        with:
          tool: zizmor
      - run: zizmor .github/workflows/
```

- [ ] **Step 3: Lint the workflow locally**

Run: `actionlint .github/workflows/ci.yml`
Expected: clean.

Run: `zizmor .github/workflows/ci.yml`
Expected: clean. If zizmor flags the SHA pins as outdated, that's a false positive for freshly-fetched SHAs — verify the SHA does resolve to the expected tag and move on.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "chore: add SHA-pinned GitHub Actions CI (fmt, clippy, test, msrv, deny, zizmor)"
```

---

## Task 12: Dependabot config

**Files:**
- Create: `.github/dependabot.yml`

- [ ] **Step 1: Write `.github/dependabot.yml`**

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    cooldown:
      default-days: 7
    groups:
      cargo-minor-patch:
        update-types:
          - "minor"
          - "patch"
      cargo-major:
        update-types:
          - "major"
    commit-message:
      prefix: "deps"
      include: "scope"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    cooldown:
      default-days: 7
    groups:
      actions-minor-patch:
        update-types:
          - "minor"
          - "patch"
      actions-major:
        update-types:
          - "major"
    commit-message:
      prefix: "ci"
      include: "scope"
```

- [ ] **Step 2: Verify with actionlint**

`actionlint` does not validate `dependabot.yml`, but verify YAML syntax by loading it:

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))" && echo OK`
Expected: `OK`.

If Python/yaml is not available, run: `prek run --all-files` — the `check-yaml` hook will validate it.

- [ ] **Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: add Dependabot config with 7-day cooldowns and grouped updates"
```

---

## Task 13: License files

**Files:**
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`

- [ ] **Step 1: Write `LICENSE-MIT`**

Create `LICENSE-MIT` with the standard MIT license text:

```
MIT License

Copyright (c) 2026 David Christensen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Write `LICENSE-APACHE`**

Fetch the canonical Apache 2.0 license text from the local system (no network):

Run: `curl -fsSLo LICENSE-APACHE https://www.apache.org/licenses/LICENSE-2.0.txt`

If network fetch is disallowed in your environment, copy the text from the canonical Apache 2.0 document and save it to `LICENSE-APACHE`. The file must be the unmodified text of the Apache License, Version 2.0.

Verify: `head -5 LICENSE-APACHE` should show:
```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/
```

- [ ] **Step 3: Commit**

```bash
git add LICENSE-MIT LICENSE-APACHE
git commit -m "docs: add dual MIT/Apache-2.0 license files"
```

---

## Task 14: README, SECURITY, CHANGELOG

**Files:**
- Modify: `README.md`
- Create: `SECURITY.md`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Rewrite `README.md`**

Overwrite `README.md`:

```markdown
# rusty-imap-mcp

A security-first [Model Context Protocol](https://modelcontextprotocol.io/) server
for IMAP email, written in Rust. Primary target: Proton Mail via Proton Bridge.
Compatible with standard IMAP servers (Dovecot, Cyrus, Gmail app password, etc.).

**Status:** Sprint 0 — scaffolding only. No functionality yet. See
[`docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`](docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md)
for the full design.

## Why

LLM agents reading email are an attractive target for prompt injection. A single
crafted message can contain hidden instructions that induce the agent to send mail,
leak data, or pivot to other tools. `rusty-imap-mcp` is built around that threat:
every byte of email content is treated as untrusted input, sanitized aggressively,
tagged structurally, and accompanied by server-generated security warnings about
look-alike domains, hidden content, and content provenance.

## Security postures

Three presets with per-tool overrides:

- **`readonly`** — list, search, fetch, download. No mutations. Safest.
- **`draft-safe`** (default) — read + flag + move + *create drafts* (appended to
  Drafts with a `$PendingReview` keyword). **Never opens an SMTP connection.**
- **`full`** — everything above plus advanced search, HTML bodies, and (in v2)
  direct SMTP send, delete, and expunge.

## Building

```bash
just setup    # install required tooling and pre-commit hooks
just ci       # run the full local-CI equivalent
```

Developer toolchain is pinned in `rust-toolchain.toml`. MSRV is 1.85.1, verified
independently in CI.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure and the threat model
summary.
```

- [ ] **Step 2: Write `SECURITY.md`**

Create `SECURITY.md`:

```markdown
# Security Policy

## Reporting a vulnerability

Please report security issues by opening a private security advisory on GitHub:
<https://github.com/davidchristensen/rusty-imap-mcp/security/advisories/new>

Do not report security issues in public issues, discussions, or pull requests.

You can expect an initial response within one week. Coordinated disclosure is
appreciated — we will work with you to understand the issue, prepare a fix, and
credit you in the release notes if you want credit.

## Threat model summary

The primary adversary is a crafted email that, when read by an agent through this
MCP server, attempts to induce the agent to take a harmful action: exfiltrate data,
send mail on the attacker's behalf, modify mailbox state, or pivot to other tools.
Secondary adversaries include a hostile IMAP server (MITM, malformed responses)
and local malware with the user's file-system privileges.

**The server does not trust:** email bodies, headers, sender addresses, display
names, attachment filenames, link targets, or any server-provided content. These
are parsed, sanitized, tagged, and structurally separated from server-controlled
metadata before being returned to an MCP client.

**The server does trust:** its own configuration file, its own keychain entries,
its own audit log, and (within limits defined by fingerprint pinning) the TLS
identity of its configured IMAP server.

For the full threat model and defenses, see
[`docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`](docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md),
especially Sections 1, 6, 7, 8, 9, and 10.

## Supported versions

During pre-v1 development, only the latest commit on `main` is supported. Once
v1.0.0 ships, a supported-versions table will appear here.
```

- [ ] **Step 3: Write `CHANGELOG.md`**

Create `CHANGELOG.md`:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial design specification (`docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`).
- Sprint 0 scaffolding: cargo workspace, seven empty member crates, MSRV pin at
  1.85.1, rustfmt/clippy/cargo-deny/typos configuration, justfile, prek
  pre-commit hooks, SHA-pinned GitHub Actions CI, dual MIT/Apache-2.0 licensing.
```

- [ ] **Step 4: Verify nothing broke**

Run: `just ci`
Expected: all targets green.

- [ ] **Step 5: Commit**

```bash
git add README.md SECURITY.md CHANGELOG.md
git commit -m "docs: rewrite README, add SECURITY.md and CHANGELOG.md"
```

---

## Task 15: End-to-end verification and negative tests

**Files:** none (verification only)

- [ ] **Step 1: Run the full local CI**

Run: `just ci`
Expected: `fmt-check`, `lint`, `test`, `test-msrv`, `deny`, and `typos` all green.

If `test` or `test-msrv` fails with "no tests to run", that's fine — `cargo nextest run` exits 0 when there are no tests in the workspace. If it exits non-zero with a different message, investigate.

- [ ] **Step 2: Run `prek` across all files**

Run: `prek run --all-files`
Expected: every hook green.

- [ ] **Step 3: Negative test — commit rejection on clippy warning**

Introduce a deliberate clippy warning and verify the pre-commit hook rejects it.

```bash
cat >> crates/rimap-core/src/lib.rs <<'EOF'

#[allow(dead_code)]
fn deliberately_bad() {
    let x = 1;
    let y = x;
    let _ = y + 0;  // clippy::identity_op
}
EOF

git add crates/rimap-core/src/lib.rs
git commit -m "test: deliberate clippy violation" ; echo exit=$?
```

Expected: the commit attempt fails. Output mentions `cargo clippy` failing with a warning treated as error. `exit` is non-zero.

Revert:
```bash
git checkout -- crates/rimap-core/src/lib.rs
git reset crates/rimap-core/src/lib.rs 2>/dev/null || true
git diff -- crates/rimap-core/src/lib.rs  # should be empty
```

- [ ] **Step 4: Negative test — commit rejection on unformatted code**

```bash
printf '\n\nfn    bad_format(){}\n' >> crates/rimap-core/src/lib.rs
git add crates/rimap-core/src/lib.rs
git commit -m "test: deliberate formatting violation" ; echo exit=$?
```

Expected: commit fails on the `cargo fmt` check. `exit` is non-zero.

Revert:
```bash
git checkout -- crates/rimap-core/src/lib.rs
git reset crates/rimap-core/src/lib.rs 2>/dev/null || true
```

- [ ] **Step 5: Negative test — commit rejection on `println!` in non-test source**

```bash
cat >> crates/rimap-server/src/main.rs <<'EOF'

#[allow(dead_code)]
fn bad() {
    println!("hi");
}
EOF

git add crates/rimap-server/src/main.rs
git commit -m "test: deliberate println violation" ; echo exit=$?
```

Expected: commit fails. Output mentions either `forbidden-macros` (the custom hook) or `cargo-clippy` (which also denies it). `exit` is non-zero.

Revert:
```bash
git checkout -- crates/rimap-server/src/main.rs
git reset crates/rimap-server/src/main.rs 2>/dev/null || true
```

- [ ] **Step 6: Final clean state verification**

Run: `git status`
Expected: clean working tree (nothing staged, nothing modified).

Run: `just ci`
Expected: all green.

- [ ] **Step 7: No commit for this task**

This task is verification only. There is nothing new to commit.

---

## Task 16: Sprint 0 completion commit and summary

**Files:**
- Modify: `CHANGELOG.md` (optional — add a note that Sprint 0 is complete)

- [ ] **Step 1: Review the branch history**

Run: `git log --oneline feat/sprint-0-scaffold ^main`
Expected: a clean sequence of commits from Task 1 through Task 14, each with a
descriptive message.

If any commit message is unclear, do **not** rebase or amend published commits.
For commits that have not been pushed yet, `git commit --amend` on the most
recent commit only is acceptable if truly needed, but prefer leaving the
history as-is.

- [ ] **Step 2: Verify end state one more time**

Run: `just ci && prek run --all-files`
Expected: all green.

- [ ] **Step 3: Push the branch**

Run: `git push -u origin feat/sprint-0-scaffold`
Expected: branch published. CI will start automatically.

- [ ] **Step 4: Wait for CI and verify**

Run: `gh run watch` or monitor the Actions tab.
Expected: all six jobs (`fmt`, `clippy`, `test`, `msrv`, `deny`, `zizmor`) green.

If any CI job fails, fix the underlying issue in a new commit on the branch (do
not `--amend` after push). Common first-push failures: missing MSRV toolchain
install step (should be handled by `dtolnay/rust-toolchain@1.85.1`), SHA
resolution mismatch, unknown lint on 1.85.1.

- [ ] **Step 5: Open a pull request**

Run:
```bash
gh pr create --base main --title "Sprint 0: repo scaffolding and guardrails" --body "$(cat <<'EOF'
## Summary

- Cargo workspace with seven empty member crates (`rimap-core`, `rimap-config`, `rimap-imap`, `rimap-content`, `rimap-audit`, `rimap-authz`, `rimap-server`).
- MSRV pinned at 1.85.1; dev toolchain pinned at 1.94.0 via `rust-toolchain.toml`; MSRV verified independently in CI.
- Workspace-level clippy lint set per global standards (pedantic, `unwrap_used = deny`, `panic = deny`, etc.).
- `cargo-deny` policy covering advisories, licenses, bans, and source allowlist.
- `justfile` as the developer entry point; `just ci` is the local equivalent of CI.
- `prek` pre-commit and pre-push hooks: fmt, clippy, branch-name guard, forbidden-macros guard, shellcheck, shfmt, actionlint, zizmor, typos.
- SHA-pinned GitHub Actions CI: `fmt`, `clippy`, `test` (stable), `msrv` (1.85.1), `deny`, `zizmor` self-check.
- Dependabot with 7-day cooldowns and grouped minor/patch updates for cargo and github-actions.
- Dual MIT/Apache-2.0 licensing.
- Design spec at `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`.

No functionality — this is the gate every future sprint passes through.

## Test plan

- [ ] CI all green on the PR
- [ ] `just ci` green locally
- [ ] `prek run --all-files` green locally
- [ ] Deliberate clippy warning, fmt violation, and `println!` in server source are all rejected at commit time
EOF
)"
```

Expected: PR URL printed.

- [ ] **Step 6: Sprint 0 done**

Sprint 0 is complete when:

1. The PR is open and CI is green.
2. `just ci` passes locally on a clean checkout.
3. Negative tests (Task 15 steps 3–5) confirm guardrails reject bad input.
4. Merging the PR is the next human action; **do not merge from the agent.**

After merge, the next sprint's plan (Sprint 1: config, postures, authz skeleton)
can be written with the spec's Sprint 1 section as input.

---

## Self-review checklist (implementing engineer: do not skip)

Before marking the PR ready:

- [ ] Every file listed in the "File Structure" section exists.
- [ ] `git grep -nE 'TBD|FIXME|XXX' -- ':!docs/superpowers/'` returns nothing inside code or config (docs reference spec-internal TBDs legitimately).
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` is silent.
- [ ] `cargo fmt --all -- --check` is silent.
- [ ] `cargo deny check` is silent.
- [ ] `cargo +1.85.1 check --workspace --all-targets --all-features --locked` is silent.
- [ ] `.github/workflows/ci.yml` has every action pinned to a full 40-character SHA, each with a version comment.
- [ ] The `branch-name` hook rejects a commit on `main` (manually verified via Task 9 Step 6).
- [ ] The `forbidden-macros` hook rejects `println!` in `crates/rimap-server/src/main.rs` (Task 10 Step 6 or Task 15 Step 5).
- [ ] CI on the pushed branch has run and is green.

---

## Dependencies and scope guardrails for the implementing engineer

- **Do not** add `async-imap`, `rmcp`, `mail-parser`, `ammonia`, `keyring`, `governor`, `fs2`, or any other runtime dependency during Sprint 0. Those belong to later sprints and their addition is gated on the sprint plan that introduces them.
- **Do not** add any `src/` code beyond the empty placeholders described in Task 3. No types, no functions (except the empty `main` in `rimap-server`), no modules.
- **Do not** create any `tests/` files in this sprint. The testing strategy from Section 11 of the spec is implemented sprint-by-sprint starting in Sprint 1.
- **Do not** skip hooks with `--no-verify`. If a hook fails, fix the underlying issue.
- **Do not** commit on `main`. All work is on `feat/sprint-0-scaffold`.
- **Do not** force-push or amend commits that have already been pushed to `origin`.
