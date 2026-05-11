# Release Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a semver-compliant release workflow where tagged builds identify as `X.Y.Z` and untagged builds identify as `X.Y.Z-dev+g<sha>[.dirty]`, with the version computed once in `rimap-core` and flowing to the CLI, MCP server_info, and audit-log records. Drop the workspace version from the aspirational `1.0.0` to `0.1.0`.

**Architecture:** A new `crates/rimap-core/build.rs` shells out to `git` to compute the version at compile time and emits `RIMAP_VERSION` / `RIMAP_COMMIT` / `RIMAP_RELEASE` via `cargo:rustc-env`. A new `rimap_core::version::{version, commit, is_release}` API exposes those values. Three runtime sites (clap, MCP `server_info`, audit `process_start`) switch from `env!("CARGO_PKG_VERSION")` to the new helpers. The release workflow gains a `verify-tag` job that hard-fails on tag/Cargo.toml drift, plus a local mirror script `scripts/check-release-version.sh` invoked through a `just release-check` recipe.

**Tech Stack:** Rust 1.88.0 MSRV (edition 2024), Cargo workspace, clap 4.5, GitHub Actions, bash (`set -euo pipefail`), `just`, `prek` pre-commit hooks.

**Spec:** [`docs/superpowers/specs/2026-05-11-release-versioning-design.md`](../specs/2026-05-11-release-versioning-design.md)

---

## File Map

**Create:**
- `crates/rimap-core/build.rs` — git-describe-based version string composer
- `crates/rimap-core/src/version.rs` — public `version()` / `commit()` / `is_release()` helpers
- `crates/rimap-core/tests/version.rs` — unit tests for the helpers
- `scripts/check-release-version.sh` — local tag/Cargo.toml comparison
- `.github/workflows/release.yml` (modify) — `verify-tag` job + `workflow_dispatch` trigger

**Modify:**
- `Cargo.toml` — workspace version `1.0.0` → `0.1.0`
- `crates/rimap-core/Cargo.toml` — add `build = "build.rs"` line, declare `version` module
- `crates/rimap-core/src/lib.rs` — add `pub mod version;` and re-exports
- `crates/rimap-content/Cargo.toml` — two `1.0.0` literals (lines 19, 61)
- `crates/rimap-audit/Cargo.toml` — one literal (line 18)
- `crates/rimap-config/Cargo.toml` — one literal (line 20)
- `crates/rimap-authz/Cargo.toml` — two literals (lines 15, 16)
- `crates/rimap-smtp/Cargo.toml` — two literals (lines 18, 19)
- `crates/rimap-imap/Cargo.toml` — three literals (lines 27, 56, 57)
- `crates/rimap-server/Cargo.toml` — eleven literals (lines 30-36, 60-62, 66)
- `crates/rimap-server/src/cli/mod.rs:24` — `version` → `version = rimap_core::version::version()`
- `crates/rimap-server/src/mcp/server.rs:228` — `env!("CARGO_PKG_VERSION")` → `rimap_core::version::version()`
- `crates/rimap-server/src/boot/audit_init.rs:66-67` — populate `version` and `git_commit` from helpers
- `crates/rimap-server/tests/cli_smoke.rs` (create or extend) — assert `--version` output shape
- `CHANGELOG.md` — relabel `[1.0.0]` → `[0.1.0]`, fold `[Unreleased]` content, remove duplicate trailing heading, add reference-link footer
- `justfile` — add `release-check` recipe

---

## Task 1: Bump workspace version to 0.1.0 and update path-dep literals

**Files:**
- Modify: `Cargo.toml:16`
- Modify: `crates/rimap-content/Cargo.toml:19,61`
- Modify: `crates/rimap-audit/Cargo.toml:18`
- Modify: `crates/rimap-config/Cargo.toml:20`
- Modify: `crates/rimap-authz/Cargo.toml:15-16`
- Modify: `crates/rimap-smtp/Cargo.toml:18-19`
- Modify: `crates/rimap-imap/Cargo.toml:27,56-57`
- Modify: `crates/rimap-server/Cargo.toml:30-36,60-62,66`

- [ ] **Step 1: Change the workspace version**

In `Cargo.toml`, change line 16 from:

```toml
version = "1.0.0"
```

to:

```toml
version = "0.1.0"
```

- [ ] **Step 2: Update all 22 path-dep version literals**

Use a single targeted replacement across the seven crate manifests. Run from the repo root:

```bash
sed -i.bak -E 's/(path = "\.\.\/rimap-[a-z]+", version = )"1\.0\.0"/\1"0.1.0"/g' crates/*/Cargo.toml
sed -i.bak -E 's/^version = "1\.0\.0"$/version = "0.1.0"/g' crates/*/Cargo.toml
sed -i.bak -E 's/(path = "\.", version = )"1\.0\.0"/\1"0.1.0"/g' crates/*/Cargo.toml
rm crates/*/Cargo.toml.bak
```

On macOS, GNU sed is not present by default — the `-i.bak` form works on both BSD and GNU sed.

- [ ] **Step 3: Verify no `1.0.0` literals remain in the workspace**

Run:

```bash
grep -rn 'version = "1\.0\.0"' Cargo.toml crates/*/Cargo.toml
```

Expected: no output. If any remain, inspect and update by hand.

- [ ] **Step 4: Verify the workspace still resolves and compiles**

Run:

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean compile. Cargo.lock will be regenerated with the new version everywhere.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/*/Cargo.toml
git commit -m "chore: drop workspace version to 0.1.0

The project is pre-release; the aspirational 1.0.0 was never tagged or
published. Reset to 0.1.0 so the first cut release matches reality.
Path-dep version literals updated in lockstep."
```

---

## Task 2: Add build.rs to rimap-core

**Files:**
- Create: `crates/rimap-core/build.rs`
- Modify: `crates/rimap-core/Cargo.toml`

- [ ] **Step 1: Wire the build script into `rimap-core/Cargo.toml`**

Edit `crates/rimap-core/Cargo.toml`. Add `build = "build.rs"` to the `[package]` section directly below the existing `description` line. The result should look like:

```toml
[package]
name = "rimap-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Shared core types for rusty-imap-mcp: Message, Folder, Posture, audit records."
build = "build.rs"
```

- [ ] **Step 2: Write the build script**

Create `crates/rimap-core/build.rs` with the following exact contents:

```rust
//! Compile-time version composer for rusty-imap-mcp.
//!
//! Emits three `cargo:rustc-env` variables consumed by `src/version.rs`:
//!
//! - `RIMAP_VERSION` — the user-facing version string. Bare `CARGO_PKG_VERSION`
//!   when HEAD is exactly the tag `v<CARGO_PKG_VERSION>`; otherwise
//!   `<CARGO_PKG_VERSION>-dev+g<short-sha>[.dirty]`.
//! - `RIMAP_COMMIT` — the short SHA (or `unknown` outside a git checkout).
//! - `RIMAP_RELEASE` — `"true"` or `"false"` depending on the release/dev path.
//!
//! Every git failure path falls back to `RIMAP_VERSION =
//! <CARGO_PKG_VERSION>-dev+gunknown`, so vendored or `cargo package` builds
//! still compile without surprise breakage.

use std::process::Command;

fn main() {
    let base = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let expected_tag = format!("v{base}");

    let exact_tag = run_git(&["describe", "--tags", "--exact-match", "HEAD"]);
    let short_sha = run_git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = run_git(&["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false);

    let is_release = exact_tag.as_deref() == Some(expected_tag.as_str());
    let (version, commit) = if is_release {
        (base.clone(), short_sha.clone())
    } else {
        let suffix = if dirty { format!("+g{short_sha}.dirty") } else { format!("+g{short_sha}") };
        let commit = if dirty { format!("{short_sha}-dirty") } else { short_sha.clone() };
        (format!("{base}-dev{suffix}"), commit)
    };

    println!("cargo:rustc-env=RIMAP_VERSION={version}");
    println!("cargo:rustc-env=RIMAP_COMMIT={commit}");
    println!("cargo:rustc-env=RIMAP_RELEASE={}", if is_release { "true" } else { "false" });
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
```

- [ ] **Step 3: Verify the build script runs and emits the env vars**

Run:

```bash
cargo build -p rimap-core --locked 2>&1 | head -40
```

Then, on a clean local worktree:

```bash
cargo clean -p rimap-core
RUSTFLAGS='--cfg unused_for_now' cargo build -p rimap-core --locked -vv 2>&1 | grep -E 'RIMAP_VERSION|RIMAP_COMMIT|RIMAP_RELEASE' | head -5
```

Expected: lines of the form

```
[rimap-core 0.1.0] cargo:rustc-env=RIMAP_VERSION=0.1.0-dev+g<7hex>
[rimap-core 0.1.0] cargo:rustc-env=RIMAP_COMMIT=<7hex>
[rimap-core 0.1.0] cargo:rustc-env=RIMAP_RELEASE=false
```

(The `RUSTFLAGS` trick forces a full rebuild so the `-vv` output shows the cargo directives.)

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-core/Cargo.toml crates/rimap-core/build.rs
git commit -m "feat(rimap-core): add build.rs to compose version string

Shells out to git describe/rev-parse/status at compile time and emits
RIMAP_VERSION, RIMAP_COMMIT, RIMAP_RELEASE as cargo:rustc-env variables.
Tag-exact builds get bare CARGO_PKG_VERSION; all others get a -dev+gSHA
suffix with .dirty when the worktree has uncommitted changes.

Acknowledged under SC-PROC-01: this is a new build script, but it runs
git with constant argv via std::process::Command (no sh -c), and never
fails the build — every error path falls through to a gunknown
fallback. Worst-case behavior on a malicious git on \$PATH is identical
to the rest of cargo build."
```

---

## Task 3: Add the public version helpers

**Files:**
- Create: `crates/rimap-core/src/version.rs`
- Modify: `crates/rimap-core/src/lib.rs`
- Create: `crates/rimap-core/tests/version.rs`

- [ ] **Step 1: Write the helpers**

Create `crates/rimap-core/src/version.rs` with:

```rust
//! Build-injected version metadata.
//!
//! Values are produced by `build.rs` and embedded via `env!`. They are
//! string slices with `'static` lifetime, suitable for direct use in
//! `clap`'s `version = ...` attribute and any other place that wants a
//! `&'static str`.

/// The user-facing version string.
///
/// `X.Y.Z` for release builds (HEAD is exactly the tag `v<X.Y.Z>`);
/// `X.Y.Z-dev+g<short-sha>[.dirty]` otherwise. Outside a git checkout
/// the suffix is `-dev+gunknown`.
#[must_use]
pub fn version() -> &'static str {
    env!("RIMAP_VERSION")
}

/// Short git SHA of the build (`abc1234`), `abc1234-dirty` for dirty
/// worktrees, or `unknown` when no git information is available.
#[must_use]
pub fn commit() -> &'static str {
    env!("RIMAP_COMMIT")
}

/// `true` when this build was produced from a `vX.Y.Z` git tag whose
/// version matches the workspace `Cargo.toml`.
#[must_use]
pub fn is_release() -> bool {
    matches!(env!("RIMAP_RELEASE"), "true")
}
```

- [ ] **Step 2: Re-export from the crate root**

Edit `crates/rimap-core/src/lib.rs`. Add `pub mod version;` to the module list (alphabetically just before `pub mod warning;`), and add a re-export line so callers can write `rimap_core::version()` directly. The relevant region should look like:

```rust
pub mod tls;
pub mod tool;
pub mod uid_selector;
pub mod version;
pub mod warning;
```

No `pub use crate::version::*;` — keeping the helpers namespaced under `rimap_core::version` avoids polluting the crate root with three generic identifiers. Call sites use `rimap_core::version::version()`.

- [ ] **Step 3: Write the unit tests**

Create `crates/rimap-core/tests/version.rs`:

```rust
//! Smoke tests for the build-injected version metadata.

use rimap_core::version::{commit, is_release, version};

#[test]
fn version_is_non_empty() {
    let v = version();
    assert!(!v.is_empty(), "version() must not be empty");
}

#[test]
fn version_starts_with_workspace_base() {
    let v = version();
    assert!(
        v.starts_with(env!("CARGO_PKG_VERSION")),
        "version() = {v:?} should start with CARGO_PKG_VERSION = {:?}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn commit_matches_expected_shape() {
    let c = commit();
    // Either the sentinel `unknown` or a 7-hex SHA with an optional `-dirty` suffix.
    let body = c.strip_suffix("-dirty").unwrap_or(c);
    let valid = body == "unknown" || (body.len() == 7 && body.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(valid, "commit() = {c:?} should be `unknown`, `<7hex>`, or `<7hex>-dirty`");
}

#[test]
fn release_flag_agrees_with_version_shape() {
    let v = version();
    let has_dev = v.contains("-dev");
    assert_eq!(
        is_release(),
        !has_dev,
        "is_release() must be true exactly when version() lacks a -dev suffix"
    );
}
```

- [ ] **Step 4: Run the new tests**

```bash
cargo test -p rimap-core --test version --locked
```

Expected: all four tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/version.rs crates/rimap-core/src/lib.rs crates/rimap-core/tests/version.rs
git commit -m "feat(rimap-core): public version()/commit()/is_release() helpers

Expose the build-injected metadata via a small module. Three runtime
sites (clap, MCP server_info, audit process_start) will switch to these
in the next task. Smoke tests assert non-empty version, base-version
prefix, valid commit shape, and consistency between is_release() and
the -dev suffix."
```

---

## Task 4: Wire the helpers into the three runtime surfaces

**Files:**
- Modify: `crates/rimap-server/src/cli/mod.rs` (remove the `version` attribute)
- Modify: `crates/rimap-server/src/main.rs:31-34` (switch to builder-pattern parse with dynamic version)
- Modify: `crates/rimap-server/src/mcp/server.rs:225-230`
- Modify: `crates/rimap-server/src/boot/audit_init.rs:65-67`

**Why the clap setup is two edits:** clap 4's derive macro accepts `#[command(version = "literal")]` or a path to a `const`, but not a function-call expression. And `cargo:rustc-env=RIMAP_VERSION=...` emitted by `rimap-core/build.rs` is only visible inside `rimap-core`'s compilation — `env!("RIMAP_VERSION")` from `rimap-server` would fail to resolve. The cleanest fix is to drop the static `version` attribute and override the version dynamically at parse time via clap's builder API.

- [ ] **Step 1: Drop the static `version` attribute from `Cli`**

Edit `crates/rimap-server/src/cli/mod.rs`. The `#[command(...)]` block currently reads:

```rust
#[command(
    name = "rusty-imap-mcp",
    version,
    about = "Security-first MCP server for IMAP email access"
)]
```

Change to:

```rust
#[command(
    name = "rusty-imap-mcp",
    about = "Security-first MCP server for IMAP email access"
)]
```

The `version` attribute is removed entirely so the builder pattern in `main.rs` (Step 2) can set it dynamically without conflict.

- [ ] **Step 2: Switch `main.rs` to the builder-pattern parse**

Edit `crates/rimap-server/src/main.rs`. Add `use clap::{CommandFactory, FromArgMatches};` near the top with the other `use` lines (just above `use crate::cli::{AuditAction, Cli, Command};`), then change the body of `fn main()` from:

```rust
fn main() -> ExitCode {
    logging::init();
    let cli = Cli::parse();
    match run(cli) {
```

to:

```rust
fn main() -> ExitCode {
    logging::init();
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(e) => {
            e.exit();
        }
    };
    match run(cli) {
```

And add a new free function above `fn main()`:

```rust
fn parse_cli() -> Result<Cli, clap::Error> {
    let matches = Cli::command()
        .version(rimap_core::version::version())
        .get_matches();
    Cli::from_arg_matches(&matches)
}
```

The existing in-crate `Cli::try_parse_from([...])` calls in `cli/mod.rs:122,134,159,186,193` are unit-test helpers that exercise the derive macro directly — they keep working because `try_parse_from` does not invoke the `version` flag. No test changes needed for them.

- [ ] **Step 3: Switch the MCP `server_info`**

Edit `crates/rimap-server/src/mcp/server.rs` around line 228. Change:

```rust
ServerInfo::default().with_server_info(Implementation::new(
    "rusty-imap-mcp",
    env!("CARGO_PKG_VERSION"),
))
```

to:

```rust
ServerInfo::default().with_server_info(Implementation::new(
    "rusty-imap-mcp",
    rimap_core::version::version(),
))
```

- [ ] **Step 4: Switch the audit-record fields**

Edit `crates/rimap-server/src/boot/audit_init.rs` lines 65-67. Change:

```rust
writer.log_process_start(ProcessStartInputs {
    version: env!("CARGO_PKG_VERSION").to_string(),
    git_commit: String::new(),
```

to:

```rust
writer.log_process_start(ProcessStartInputs {
    version: rimap_core::version::version().to_string(),
    git_commit: rimap_core::version::commit().to_string(),
```

The `git_commit` field was previously stubbed as `String::new()`; this populates it with the same short-SHA that the version string carries, so a captured audit record uniquely identifies the build.

- [ ] **Step 5: Verify the workspace compiles**

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean.

- [ ] **Step 6: Smoke-test the CLI**

```bash
cargo run --quiet -p rimap-server --bin rusty-imap-mcp -- --version
```

Expected output (worktree is currently on `feat/release-versioning`, dirty or clean depending on intermediate state):

```
rusty-imap-mcp 0.1.0-dev+g<7hex>
```

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/cli/mod.rs crates/rimap-server/src/main.rs crates/rimap-server/src/mcp/server.rs crates/rimap-server/src/boot/audit_init.rs
git commit -m "feat(rimap-server): consume rimap_core::version at runtime surfaces

clap --version (set via CommandFactory builder override in main.rs),
MCP server_info, and the audit-log process_start record all switch
from env!(\"CARGO_PKG_VERSION\") to rimap_core::version::*. The audit
record's previously-stubbed git_commit field is now populated with the
short SHA, so a captured audit log uniquely identifies the exact build
it came from.

The derive-time \`version\` attribute is dropped because clap 4 does not
accept a function-call expression there, and \`cargo:rustc-env\`
RIMAP_VERSION emitted by rimap-core's build.rs is not visible to
rimap-server's compilation. The builder override is the standard clap
pattern for this case."
```

---

## Task 5: CLI smoke test

**Files:**
- Create: `crates/rimap-server/tests/cli_smoke.rs` (or extend if it exists)
- Modify: `crates/rimap-server/Cargo.toml` (if the dev-deps aren't wired yet)

The richer `long_version` (commit + target triple + release flag) is intentionally out of scope: clap 4 derive does not accept a function-call expression for `long_version` either, and rimap-server cannot see `RIMAP_VERSION` directly. Wiring `long_version` through the same builder pattern as `version` would require a runtime `format!`, which means `Cli::command().long_version(...)` would build a `String` per parse — fine, but adds a `Box::leak` or `'static` workaround. Defer this until a real user asks for it.

- [ ] **Step 1: Check whether `cli_smoke.rs` already exists**

```bash
ls crates/rimap-server/tests/ 2>/dev/null
```

If `cli_smoke.rs` exists, append to it instead of creating a new file.

- [ ] **Step 2: Write the smoke test**

Create `crates/rimap-server/tests/cli_smoke.rs` (or append the test to the existing file):

```rust
//! Smoke tests for the user-visible `--version` output.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_flag_prints_expected_shape() {
    Command::cargo_bin("rusty-imap-mcp")
        .expect("binary exists")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("rusty-imap-mcp "))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}
```

`assert_cmd` and `predicates` are already declared in `[workspace.dependencies]`. Verify the dev-dependency wiring on `rimap-server`:

```bash
grep -nE 'assert_cmd|predicates' crates/rimap-server/Cargo.toml
```

If neither appears under `[dev-dependencies]`, add them:

```toml
[dev-dependencies]
assert_cmd = { workspace = true }
predicates = { workspace = true }
```

- [ ] **Step 3: Run the smoke test**

```bash
cargo test -p rimap-server --test cli_smoke --locked
```

Expected: PASS. The test asserts the output starts with `rusty-imap-mcp ` and contains the base `CARGO_PKG_VERSION` (`0.1.0`).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/cli_smoke.rs crates/rimap-server/Cargo.toml
git commit -m "test(rimap-server): smoke test --version output shape

Asserts that \`rusty-imap-mcp --version\` succeeds, starts with the
binary name, and contains the workspace base version. Catches accidental
regressions in either the clap wiring or rimap_core::version::version()."
```

---

## Task 6: Local release-version mirror script

**Files:**
- Create: `scripts/check-release-version.sh`
- Modify: `justfile`

- [ ] **Step 1: Write the script**

Create `scripts/check-release-version.sh` with the following exact contents:

```bash
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
```

- [ ] **Step 2: Make the script executable**

```bash
chmod +x scripts/check-release-version.sh
```

- [ ] **Step 3: Run shellcheck and shfmt**

```bash
shellcheck scripts/check-release-version.sh
shfmt -d scripts/check-release-version.sh
```

Expected: shellcheck reports no issues; shfmt produces no diff. If shfmt reports a diff, run `shfmt -w scripts/check-release-version.sh` and re-run the diff check.

- [ ] **Step 4: Manually exercise the script**

Positive case:

```bash
./scripts/check-release-version.sh v0.1.0
```

Expected: `ok: tag 'v0.1.0' matches Cargo.toml workspace version '0.1.0'` (exit 0).

Negative cases — confirm each fails:

```bash
./scripts/check-release-version.sh v9.9.9        # expect exit 68
./scripts/check-release-version.sh v0.1          # expect exit 65
./scripts/check-release-version.sh v0.1.0-rc1    # expect exit 65
./scripts/check-release-version.sh               # expect exit 64
```

- [ ] **Step 5: Add the `release-check` recipe to `justfile`**

Append to `justfile` (just after the existing `hooks:` recipe):

```just
# Verify a candidate tag against the Cargo.toml workspace version.
# Run this before pushing a `vX.Y.Z` tag.
#   just release-check v0.1.0
release-check TAG:
    ./scripts/check-release-version.sh {{TAG}}
```

- [ ] **Step 6: Verify the recipe**

```bash
just release-check v0.1.0
```

Expected: same `ok:` line as Step 4.

- [ ] **Step 7: Commit**

```bash
git add scripts/check-release-version.sh justfile
git commit -m "build: scripts/check-release-version.sh + just release-check

Local-side mirror of the verify-tag CI job (added in the next commit):
parses the workspace version from Cargo.toml, compares to a vX.Y.Z
argument, and exits non-zero on any mismatch, malformed tag, or
\`-dev\` literal in the manifest. Pure bash, shellcheck-clean."
```

---

## Task 7: Release-workflow verify-tag job

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Add a `workflow_dispatch` trigger with a `dry_run` input**

Edit `.github/workflows/release.yml`. Replace the existing `on:` block at the top:

```yaml
on:
  push:
    tags: ["v*"]
```

with:

```yaml
on:
  push:
    tags: ["v*"]
  workflow_dispatch:
    inputs:
      dry_run:
        description: "Run verify-tag only; skip build and release jobs."
        type: boolean
        default: true
      tag:
        description: "Tag to validate (e.g. v0.1.0). Used only on workflow_dispatch."
        type: string
        required: true
```

- [ ] **Step 2: Add the `verify-tag` job**

Immediately under the `jobs:` line (so it runs before any of the build jobs), insert:

```yaml
  verify-tag:
    name: Verify tag matches Cargo.toml
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    outputs:
      version: ${{ steps.verify.outputs.version }}
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - name: Verify tag
        id: verify
        env:
          TAG_REF: ${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}
        run: |
          ./scripts/check-release-version.sh "$TAG_REF"
          echo "version=${TAG_REF#v}" >> "$GITHUB_OUTPUT"
```

- [ ] **Step 3: Gate every existing build job on `verify-tag`**

For each of the five build jobs (`build-linux-x86_64`, `build-linux-aarch64`, `build-macos-aarch64`, `build-linux-ppc64le`, `build-linux-s390x`) and the `release` job, add a `needs:` directive. For the five build jobs, the directive is `needs: verify-tag`. For the existing `release` job, **prepend** `verify-tag` to its existing `needs:` list. After the change, the `release` job's `needs:` should read:

```yaml
    needs:
      - verify-tag
      - build-linux-x86_64
      - build-linux-aarch64
      - build-macos-aarch64
      - build-linux-ppc64le
      - build-linux-s390x
```

- [ ] **Step 4: Make build and release jobs skip on dry-run**

For each of the five build jobs and the `release` job, add an `if:` directive at the job level that skips when `workflow_dispatch` set `dry_run` to true:

```yaml
    if: github.event_name != 'workflow_dispatch' || inputs.dry_run != true
```

- [ ] **Step 5: Lint the workflow**

```bash
actionlint .github/workflows/release.yml
zizmor .github/workflows/release.yml
```

Expected: both clean. If zizmor flags anything new, address it (or add a targeted `# zizmor: ignore[...]` comment with justification, matching the pattern already in the file).

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): verify-tag guard + workflow_dispatch dry-run trigger

verify-tag runs scripts/check-release-version.sh against the pushed tag
(or the manually-supplied tag input under workflow_dispatch) and gates
every build/release job via 'needs'. workflow_dispatch with dry_run=true
runs the guard alone, allowing the check logic to be exercised without
cutting a real tag. Hard-fails on tag/Cargo.toml drift, malformed tag
formats, or a -dev literal in the manifest."
```

---

## Task 8: CHANGELOG migration

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Re-read the current CHANGELOG**

```bash
wc -l CHANGELOG.md
grep -n '^## ' CHANGELOG.md
```

Expected: heading list shows `[Unreleased]` (line 8), `[1.0.0] - 2026-04-13` (line 39), and a duplicate `[Unreleased]` (line 244).

- [ ] **Step 2: Rewrite the file**

In a single edit pass:

1. Delete the duplicate `## [Unreleased]` at line 244 (the last line of the file as observed during exploration). If there is any content under it, fold it into the main `[Unreleased]` section before deleting the heading.
2. Take the content currently under the top `## [Unreleased]` heading (the multi-account credential-namespacing entries, lines 8–37) and merge it into the existing `## [1.0.0]` section. Place the new entries under appropriate Keep-a-Changelog subheadings (`### Changed`, `### Added`) within `[1.0.0]`, deduplicating if any topic overlaps.
3. Rename the merged section's heading from `## [1.0.0] - 2026-04-13` to `## [0.1.0] - Unreleased`.
4. Leave a fresh, empty `## [Unreleased]` heading at the top of the file (immediately under the introduction paragraph) for future post-0.1.0 work.
5. At the bottom of the file, add or update the reference-link footer:

```markdown
[Unreleased]: https://github.com/randomparity/rusty-imap-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/randomparity/rusty-imap-mcp/releases/tag/v0.1.0
```

- [ ] **Step 3: Verify the changelog now contains only the expected headings**

```bash
grep -n '^## ' CHANGELOG.md
```

Expected output (exact line numbers will vary):

```
8:## [Unreleased]
12:## [0.1.0] - Unreleased
```

No `[1.0.0]` heading anywhere. No duplicate `[Unreleased]`.

- [ ] **Step 4: Verify the per-tag extraction still works**

The release workflow extracts release notes via:

```bash
awk "/^## \\[0.1.0\\]/,/^## \\[[^\\]]+\\]/" CHANGELOG.md | head -n -1 | head -40
```

Expected: shows the full `[0.1.0]` section, stopping before the next `## [` heading. The `Unreleased` heading sits above `[0.1.0]` in the file, so the awk pattern (which starts at `[0.1.0]` and stops at the next bracketed heading) is unaffected by it.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): relabel [1.0.0] to [0.1.0]; fold [Unreleased]

The 1.0.0 heading was aspirational — no tag, no release. Renaming the
section to 0.1.0 and folding the in-flight credential-namespacing
entries into it gives the first real release a coherent changelog
entry. Duplicate trailing [Unreleased] heading removed. Reference-link
footer added at the bottom in Keep-a-Changelog style."
```

---

## Task 9: Full local CI pass and dry-run workflow

**Files:** none

- [ ] **Step 1: Run the local-CI equivalent**

```bash
just ci
```

Expected: `fmt-check`, `lint`, `test`, `test-msrv`, `deny`, and `typos` all pass. If `cargo-deny` flags anything (license, advisory, ban, source), address before proceeding.

- [ ] **Step 2: Run the pre-commit hooks across all files**

```bash
just hooks
```

Expected: all hooks pass on the full tree.

- [ ] **Step 3: Verify final version output**

```bash
cargo run --quiet -p rimap-server --bin rusty-imap-mcp -- --version
```

Expected (worktree clean):

```
rusty-imap-mcp 0.1.0-dev+g<7hex>
```

Expected (worktree dirty): the same with a trailing `.dirty`.

- [ ] **Step 4: Run the workflow dry-run from the PR branch**

After pushing the branch and opening the PR (Task 10), use `gh` to dispatch the workflow against the branch:

```bash
gh workflow run release.yml --ref feat/release-versioning -f tag=v0.1.0 -f dry_run=true
gh run watch
```

Expected: the `verify-tag` job runs and passes; the build/release jobs are skipped (visible as "Skipped" in the run summary). Negative variant:

```bash
gh workflow run release.yml --ref feat/release-versioning -f tag=v9.9.9 -f dry_run=true
gh run watch
```

Expected: `verify-tag` fails with exit 68; downstream jobs skip.

- [ ] **Step 5: Commit any incidental fixes**

If `just ci` or `just hooks` produced fixes (formatting, typos, etc.), commit them as a follow-on:

```bash
git add -A
git commit -m "chore: incidental fixes surfaced by local-CI pass"
```

If nothing changed, skip this step.

---

## Task 10: Open the pull request

**Files:** none

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feat/release-versioning
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat: release versioning with -dev+gSHA suffix" --body "$(cat <<'EOF'
## Summary

- Workspace version drops from the aspirational `1.0.0` to `0.1.0`. Every
  `version = "1.0.0"` literal on the 22 cross-crate path-deps follows.
- New `rimap-core/build.rs` shells out to `git describe --tags
  --exact-match HEAD`, `rev-parse --short=7`, and `status --porcelain` to
  compute a semver-compliant version string at compile time:
  `X.Y.Z` for tag-exact builds, `X.Y.Z-dev+g<sha>[.dirty]` otherwise.
- The CLI `--version`, MCP `server_info.version`, and audit-log
  `process_start.version` / `.git_commit` fields all consume the new
  `rimap_core::version` helpers, so a captured audit log identifies the
  exact commit a dev build came from.
- `.github/workflows/release.yml` gains a `verify-tag` job that
  hard-fails before any build job runs if the pushed tag does not match
  the workspace version, and a `workflow_dispatch` trigger with
  `dry_run: true` that exercises the guard without cutting a real tag.
- `scripts/check-release-version.sh` mirrors the CI guard locally via
  `just release-check vX.Y.Z`.
- `CHANGELOG.md` relabels `[1.0.0]` → `[0.1.0]`, folds the in-flight
  `[Unreleased]` entries into it, and adds reference-link footers.

Spec: `docs/superpowers/specs/2026-05-11-release-versioning-design.md`.

## Test plan

- [x] `just ci` passes locally (fmt, lint, test, test-msrv, deny, typos)
- [x] `just hooks` passes across the whole tree
- [x] `cargo test -p rimap-core --test version` passes
- [x] `cargo test -p rimap-server --test cli_smoke` passes
- [x] `rusty-imap-mcp --version` prints `rusty-imap-mcp 0.1.0-dev+g<sha>`
- [x] `./scripts/check-release-version.sh v0.1.0` exits 0
- [x] `./scripts/check-release-version.sh v9.9.9` exits 68
- [x] `./scripts/check-release-version.sh v0.1.0-rc1` exits 65
- [x] `gh workflow run release.yml -f tag=v0.1.0 -f dry_run=true` -> verify-tag passes
- [x] `gh workflow run release.yml -f tag=v9.9.9 -f dry_run=true` -> verify-tag fails

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Confirm CI is green**

```bash
gh pr checks
```

Expected: all CI jobs report success. Address any failures before requesting review.

---

## Verification checklist

After all tasks complete and CI is green:

- [ ] `grep -rn 'version = "1\.0\.0"' Cargo.toml crates/*/Cargo.toml` returns no output.
- [ ] `cargo run -p rimap-server --bin rusty-imap-mcp -- --version` prints `rusty-imap-mcp 0.1.0-dev+g<7hex>` on a clean worktree.
- [ ] `cargo run -p rimap-server --bin rusty-imap-mcp -- --version` prints `…dirty` when the worktree is dirty.
- [ ] The audit log written by a smoke `--dry-run` run contains `"version": "0.1.0-dev+g<sha>"` and a non-empty `"git_commit"`.
- [ ] A `workflow_dispatch` of `release.yml` with `dry_run=true` and a matching tag passes `verify-tag` and skips the rest.
- [ ] A `workflow_dispatch` of `release.yml` with `dry_run=true` and a non-matching tag fails `verify-tag`.
- [ ] `CHANGELOG.md` has exactly one `[Unreleased]` heading (the new empty one at the top) and one `[0.1.0]` heading.

---

## Out of scope (do not touch in this PR)

- Pre-release identifiers other than `-dev` (no `-rc.N`, `-beta.N`, `-alpha`).
- Automatic version-bump tooling (`cargo-release`, `cargo-edit`).
- crates.io publish flow.
- Reproducible-build flags beyond honoring `SOURCE_DATE_EPOCH` as a rerun trigger.
- Richer clap `long_version` output (commit + target triple + release flag).
