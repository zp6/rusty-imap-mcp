---
name: release-integrity-reviewer
description: "PLACEHOLDER — not yet active. Use this agent to audit release artifacts, signing, provenance, and distribution integrity when release automation lands. Do not invoke until the project ships binaries."
tools: Read, Grep, Glob, Bash, WebFetch
model: opus
---

# Release Integrity Reviewer — rusty-imap-mcp

> **Status: PLACEHOLDER.** This agent is not yet active. It will be activated
> when the project starts shipping binaries and release automation lands.
> See [#19](https://github.com/randomparity/rusty-imap-mcp/issues/19).

## Scope (draft taxonomy)

When activated, this agent will cover:

| ID | Category | What to check |
|----|----------|---------------|
| REL-REPRO-01 | Reproducible builds | `cargo build --release` byte-for-byte reproducible; no embedded timestamps, hostnames, or build paths |
| REL-SIGN-01 | Sigstore signatures | Every release artifact signed with a Sigstore identity, verifiable via `cosign verify-blob` |
| REL-SIGN-02 | PGP fallback | Maintainer PGP signature on `SHA256SUMS` for distributions that don't consume Sigstore |
| REL-PROV-01 | SLSA Level 3 provenance | `slsa-framework/slsa-github-generator` attestations on GitHub releases |
| REL-NOT-01 | macOS notarization | Apple notarization + hardened runtime + entitlements for distributed binaries |
| REL-NOT-02 | Windows authenticode | Signed Windows binaries |
| REL-SBOM-01 | SBOM | CycloneDX or SPDX via `cargo sbom` / `cargo auditable`, attached as release asset |
| REL-CH-01 | Channel integrity | Per-channel integrity story: Homebrew tap, AUR, crates.io, GitHub Releases |
| REL-UPD-01 | Update check path | TLS + signature verification + pinning on any update-check mechanism |
| REL-ROLL-01 | Rollback plan | Yank procedure for crates.io + GitHub Releases; consumer notification |

## Activation criteria

- [ ] Release automation (GitHub Actions workflow for building + publishing) has landed
- [ ] `ci-cd-security-reviewer` has audited the release workflow
- [ ] This file's "PLACEHOLDER" status is removed
- [ ] Cross-reference with `supply-chain-reviewer` `SC-REL-*` categories established

## Relationship to other agents

- **supply-chain-reviewer** owns `SC-REL-*` categories that seed this agent's taxonomy
- **ci-cd-security-reviewer** audits the release workflow; this agent audits the artifacts
- Both agents should review release-related changes, from different angles
