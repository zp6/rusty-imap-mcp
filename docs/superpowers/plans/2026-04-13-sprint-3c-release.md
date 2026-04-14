# Sprint 3c: v1.0.0 Release Preparation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare and ship v1.0.0: version bump, CHANGELOG, documentation, cross-platform release workflow with pre-built binaries for five targets.

**Architecture:** A GitHub Actions release workflow triggered on `v*` tags builds binaries in parallel across five platform targets. Linux x86_64 and macOS aarch64 use native builds, Linux aarch64 uses `cross`, and Linux ppc64le and s390x use QEMU user-mode emulation for native builds inside platform containers.

**Tech Stack:** GitHub Actions, `cross`, QEMU/binfmt_misc, Docker, `cargo build --release`

**Depends on:** Sprint 3a (labels) and Sprint 3b (multi-account) merged to the feature branch.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `Cargo.toml` | Version bump to 1.0.0 |
| Modify | `CHANGELOG.md` | Full v1.0.0 release entry |
| Modify | `README.md` | Rewrite for v1.0 |
| Create | `docs/configuration.md` | Full config reference |
| Create | `docs/multi-account.md` | Multi-account guide |
| Create | `docs/security-model.md` | Posture matrix, threat model |
| Create | `docs/proton-bridge-setup.md` | Setup walkthrough |
| Create | `.github/workflows/release.yml` | Release build + publish workflow |
| Modify | `AGENTS.md` | Update repo status, tool counts, sprint references |

---

## Task 1: Version bump

**Files:**
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Update workspace version**

In the root `Cargo.toml`, update `[workspace.package]`:

```toml
[workspace.package]
version = "1.0.0"
```

- [ ] **Step 2: Run `cargo check --workspace`**

Run: `cargo check --workspace`
Expected: compiles with new version.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "chore: bump workspace version to 1.0.0"
```

---

## Task 2: Write CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write the v1.0.0 entry**

Replace the `## [Unreleased]` section with a full release entry. Organize by capability, not sprint. Cover the entire feature surface from sprints 0 through 3:

```markdown
## [1.0.0] — 2026-04-XX

### Features

- **Multi-account support:** Configure multiple IMAP/SMTP accounts in a
  single process. Accounts are discoverable via MCP resources
  (`rimap://accounts/<name>`) and selectable per-session (`use_account`)
  or per-call (`account` parameter). Existing single-account configs
  work unchanged.

- **22 MCP tools** across four security postures:
  - **Read:** `list_folders`, `search`, `fetch_message`, `list_attachments`,
    `download_attachment`, `list_labels`
  - **Organize:** `mark_read`, `mark_unread`, `flag`, `unflag`,
    `add_label`, `remove_label`, `move_message`, `create_draft`
  - **Write:** `send_email`, `delete_message`, `create_folder`,
    `rename_folder`
  - **Destructive:** `expunge`, `delete_folder`
  - **Infrastructure:** `use_account`, `list_accounts`

- **Security postures:** `readonly`, `draft-safe` (default), `full`,
  `destructive`. Per-account posture configuration with per-tool
  allow/deny overrides. Tools denied by posture are not advertised.

- **SMTP sending** via `lettre` with TLS (STARTTLS or implicit),
  rate-limited (`sends_per_minute`), with Sent folder copy.

- **Content pipeline:** MIME parsing, Unicode normalization (NFKC),
  HTML-to-text conversion, look-alike detection (mixed-script, TR39
  confusables, IDN, bidi tricks), structured security warnings.

- **Audit log:** Append-only JSONL with exclusive file locking,
  per-record timestamps, process IDs, sequence numbers, provenance
  tracking, and argument redaction. `audit merge` subcommand with
  time/tool/account/process filters.

- **Folder safety:** Protected folders list (default: INBOX, Sent,
  Drafts, Trash) prevents deletion and rename. Expunge folder
  allowlist (default: deny all) gates permanent message removal.
  INBOX is always protected regardless of configuration.

- **Rate limiting and circuit breaker:** Per-account token bucket
  rate limiter and sliding-window circuit breaker. Separate rate
  limits for general commands, drafts, and sends.

- **TLS fingerprint pinning:** SHA-256 certificate fingerprint
  verification for Proton Bridge and other self-signed setups.
  Constant-time comparison, redacted in debug output.

- **IMAP keyword labels:** `add_label`, `remove_label`, `list_labels`
  tools for managing custom IMAP keyword flags.

### Platform Support

Pre-built binaries for:
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `powerpc64le-unknown-linux-gnu`
- `s390x-unknown-linux-gnu`
- `aarch64-apple-darwin`

### Development

- Rust 1.88.0 MSRV, Edition 2024
- `just ci` runs full local CI equivalent
- `prek` pre-commit hooks
- `cargo deny` for supply chain auditing
- `zizmor` for GitHub Actions security scanning
```

Adjust the date when the release is cut.

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: write CHANGELOG for v1.0.0 release"
```

---

## Task 3: Write documentation

**Files:**
- Modify: `README.md`
- Create: `docs/configuration.md`
- Create: `docs/multi-account.md`
- Create: `docs/security-model.md`
- Create: `docs/proton-bridge-setup.md`

- [ ] **Step 1: Rewrite README.md**

Rewrite for v1.0: what the project is, quick-start with a minimal config, multi-account example, posture overview, link to docs, build instructions, license.

Key sections:
- What is this (one paragraph)
- Quick start (install binary, create config, run)
- Configuration overview (link to docs/configuration.md)
- Security postures (table with the four postures)
- Multi-account (brief example, link to docs/multi-account.md)
- Building from source
- License (MIT/Apache-2.0)

- [ ] **Step 2: Write docs/configuration.md**

Full config reference covering:
- Legacy single-account format (all fields, defaults, types)
- Multi-account format (`[defaults]`, `[[accounts]]`, `[audit]`, `[attachments]`)
- Credential resolution (keyring, environment variable)
- SMTP configuration
- Security settings (postures, tool overrides, protected folders, expunge folders)
- Limits (rate limiting, circuit breaker, size caps)
- Audit settings
- Validation rules and error messages

Include complete example configs for both formats.

- [ ] **Step 3: Write docs/multi-account.md**

Guide covering:
- Account discovery via MCP resources (`rimap://accounts/<name>`)
- `use_account` tool for session-scoped default
- Per-call `account` parameter override
- Single-account backward compatibility
- Example agent workflow (discover → select → operate)

- [ ] **Step 4: Write docs/security-model.md**

Document covering:
- Threat model (email as adversarial input, prompt injection, autonomous send risk, data destruction)
- Posture matrix (full 22-tool × 4-posture table)
- Per-account isolation (separate rate limiters, circuit breakers, postures)
- Content pipeline defenses (sanitization, look-alike detection, structured warnings)
- Audit log (what's logged, redaction, provenance)
- Folder safety (protected folders, expunge allowlist)
- TLS fingerprint pinning

- [ ] **Step 5: Write docs/proton-bridge-setup.md**

Walkthrough covering:
- Installing Proton Bridge
- Capturing the TLS fingerprint (`openssl s_client` command)
- Creating the config file for Bridge (localhost IMAP + SMTP)
- Running `rusty-imap-mcp login` to store credentials
- Verifying with `--dry-run`
- Setting up SMTP for `send_email`

- [ ] **Step 6: Commit**

```bash
git add README.md docs/
git commit -m "docs: write v1.0.0 documentation (config, multi-account, security, proton bridge)"
```

---

## Task 4: Create release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write the release workflow**

Create `.github/workflows/release.yml`. Look up current SHA pins for all actions before writing. The workflow:

1. Triggers on `v*` tags
2. Five parallel build jobs
3. Artifact collection and checksum generation
4. GitHub release creation

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

env:
  CARGO_TERM_COLOR: always
  BINARY_NAME: rusty-imap-mcp

jobs:
  build-linux-x86_64:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # stable
        with:
          toolchain: stable
      - run: cargo build --release --locked
      - run: |
          mv target/release/${{ env.BINARY_NAME }} \
             ${{ env.BINARY_NAME }}-x86_64-unknown-linux-gnu
      - uses: actions/upload-artifact@<SHA>  # v4.x.x
        with:
          name: binary-linux-x86_64
          path: ${{ env.BINARY_NAME }}-x86_64-unknown-linux-gnu

  build-linux-aarch64:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # stable
        with:
          toolchain: stable
          targets: aarch64-unknown-linux-gnu
      - run: cargo install cross --locked
      - run: cross build --release --locked --target aarch64-unknown-linux-gnu
      - run: |
          mv target/aarch64-unknown-linux-gnu/release/${{ env.BINARY_NAME }} \
             ${{ env.BINARY_NAME }}-aarch64-unknown-linux-gnu
      - uses: actions/upload-artifact@<SHA>  # v4.x.x
        with:
          name: binary-linux-aarch64
          path: ${{ env.BINARY_NAME }}-aarch64-unknown-linux-gnu

  build-linux-ppc64le:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: docker/setup-qemu-action@<SHA>  # v3.x.x
        with:
          platforms: ppc64le
      - run: |
          docker run --rm --platform linux/ppc64le \
            -v "${{ github.workspace }}:/src" \
            -w /src \
            rust:latest \
            cargo build --release --locked
      - run: |
          mv target/release/${{ env.BINARY_NAME }} \
             ${{ env.BINARY_NAME }}-powerpc64le-unknown-linux-gnu
      - uses: actions/upload-artifact@<SHA>  # v4.x.x
        with:
          name: binary-linux-ppc64le
          path: ${{ env.BINARY_NAME }}-powerpc64le-unknown-linux-gnu

  build-linux-s390x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: docker/setup-qemu-action@<SHA>  # v3.x.x
        with:
          platforms: s390x
      - run: |
          docker run --rm --platform linux/s390x \
            -v "${{ github.workspace }}:/src" \
            -w /src \
            rust:latest \
            cargo build --release --locked
      - run: |
          mv target/release/${{ env.BINARY_NAME }} \
             ${{ env.BINARY_NAME }}-s390x-unknown-linux-gnu
      - uses: actions/upload-artifact@<SHA>  # v4.x.x
        with:
          name: binary-linux-s390x
          path: ${{ env.BINARY_NAME }}-s390x-unknown-linux-gnu

  build-macos-aarch64:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<SHA>  # stable
        with:
          toolchain: stable
      - run: cargo build --release --locked
      - run: |
          mv target/release/${{ env.BINARY_NAME }} \
             ${{ env.BINARY_NAME }}-aarch64-apple-darwin
      - uses: actions/upload-artifact@<SHA>  # v4.x.x
        with:
          name: binary-macos-aarch64
          path: ${{ env.BINARY_NAME }}-aarch64-apple-darwin

  release:
    needs:
      - build-linux-x86_64
      - build-linux-aarch64
      - build-linux-ppc64le
      - build-linux-s390x
      - build-macos-aarch64
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>  # v4.x.x
        with:
          persist-credentials: false
      - uses: actions/download-artifact@<SHA>  # v4.x.x
        with:
          path: artifacts
          merge-multiple: true
      - name: Generate checksums
        run: |
          cd artifacts
          sha256sum ${{ env.BINARY_NAME }}-* > SHA256SUMS
      - name: Create GitHub Release
        uses: softprops/action-gh-release@<SHA>  # v2.x.x
        with:
          files: |
            artifacts/${{ env.BINARY_NAME }}-*
            artifacts/SHA256SUMS
          generate_release_notes: false
          body_path: RELEASE_NOTES.md
          draft: true
```

All `<SHA>` placeholders MUST be replaced with full 40-character SHA hashes with version comments during implementation. Look up the current stable versions of each action.

Note: the QEMU builds output to `target/release/` (not a target-specific directory) because they run inside a platform container where the native architecture matches.

- [ ] **Step 2: Run `actionlint` and `zizmor`**

Run: `actionlint .github/workflows/release.yml && zizmor .github/workflows/release.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow for 5-target binary builds"
```

---

## Task 5: Update AGENTS.md

**Files:**
- Modify: `AGENTS.md`

- [ ] **Step 1: Update repository status**

Change the "Repository status" section from:

> The repo is under active pre-v1 development.

To reflect the current state: multi-account, 22 tools + 2 infrastructure tools, v1.0.0.

Update tool counts, sprint references, and any stale information.

- [ ] **Step 2: Run `just ci`**

Run: `just ci`
Expected: all checks pass on the complete sprint 3 branch.

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md
git commit -m "docs: update AGENTS.md for v1.0.0 release"
```

---

## Task 6: Final release validation

- [ ] **Step 1: Run full CI locally**

Run: `just ci`
Expected: clean pass.

- [ ] **Step 2: Verify `--dry-run` with multi-account config**

Create a test config with two accounts and verify `--dry-run` output shows both accounts with their effective matrices.

- [ ] **Step 3: Verify `--dry-run` with legacy config**

Verify an existing single-account config still works with `--dry-run`.

- [ ] **Step 4: Review the diff against main**

Run: `git diff main...HEAD --stat`
Review the full changeset for anything that shouldn't be in the release.

- [ ] **Step 5: Open PR against main**

Push the branch and create a PR. CI must pass all status checks before merge.
