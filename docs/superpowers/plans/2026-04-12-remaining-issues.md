# Remaining Open Issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the four remaining open GitHub issues: #32 (pre-flight size check for fetch_body), #14 (threat-model-reviewer agent), #18 (SECURITY.md hygiene reviewer), and #19 (release integrity reviewer placeholder agent).

**Architecture:** Three issue groups — one code change (#32 adds a `FETCH RFC822.SIZE` probe before `FETCH BODY.PEEK[]` to reject oversize messages without buffering them) and two agent/doc groups (#14/#18 create new security-review agents, #19 creates a placeholder agent file). All changes land on a single branch.

**Tech Stack:** Rust (async-imap, tokio), Markdown (agent definitions)

---

## File Structure

### Group A: Pre-flight size check (#32)

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-imap/src/ops/fetch.rs` | Add `preflight_size_check` function |
| Modify | `crates/rimap-imap/src/connection.rs` | Wire pre-flight check into `Connection::fetch_body` |
| Modify | `crates/rimap-imap/src/error.rs` | No changes needed — `Error::SizeLimit` already exists |

### Group B: Security reviewer agents (#14, #18, #19)

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `.claude/agents/threat-model-reviewer.md` | STRIDE-based spec/plan reviewer (#14) |
| Modify | `SECURITY.md` | Add CVE process, supported versions, PGP/Sigstore, disclosure timeline (#18) |
| Create | `.claude/agents/security-docs-reviewer.md` | SECURITY.md currency checker (#18) |
| Create | `.claude/agents/release-integrity-reviewer.md` | Placeholder for post-v1 release signing (#19) |

---

## Task 1: Pre-flight RFC822.SIZE probe in fetch_body (#32)

**Files:**
- Modify: `crates/rimap-imap/src/ops/fetch.rs:154-190`
- Modify: `crates/rimap-imap/src/connection.rs:539-574`

### Approach

Issue #32's Option 3: before issuing `FETCH BODY.PEEK[]`, issue `UID FETCH <uid> (RFC822.SIZE)` and reject if the server-reported size exceeds `max_fetch_body_bytes`. This adds one IMAP round-trip but prevents async-imap from buffering the entire oversize body into memory.

The existing post-parse size check stays as defense-in-depth (servers can lie about `RFC822.SIZE`), but the pre-flight probe catches the honest-server case cheaply.

- [ ] **Step 1: Write failing test for `preflight_size_check`**

Add to `crates/rimap-imap/src/ops/fetch.rs` in the `#[cfg(test)] mod tests` block:

```rust
#[test]
#[expect(clippy::panic, reason = "test failure path")]
fn preflight_size_check_rejects_oversize() {
    // Server reports 10 MB, limit is 5 MB → SizeLimit error
    let result = preflight_size_check(Some(10_485_760), 5_242_880);
    match result {
        Err(Error::SizeLimit { limit }) => {
            assert_eq!(limit, 5_242_880);
        }
        other => panic!("expected SizeLimit, got {other:?}"),
    }
}

#[test]
fn preflight_size_check_accepts_within_limit() {
    // Server reports 1 MB, limit is 5 MB → Ok
    assert!(preflight_size_check(Some(1_048_576), 5_242_880).is_ok());
}

#[test]
fn preflight_size_check_accepts_at_exact_limit() {
    // Server reports exactly the limit → Ok (consistent with project_size)
    assert!(preflight_size_check(Some(5_242_880), 5_242_880).is_ok());
}

#[test]
fn preflight_size_check_passes_when_server_omits_size() {
    // Server returns no RFC822.SIZE → Ok (fall through to post-parse check)
    assert!(preflight_size_check(None, 5_242_880).is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-imap preflight_size_check -- --nocapture`
Expected: compilation error — `preflight_size_check` does not exist yet.

- [ ] **Step 3: Implement `preflight_size_check` in `ops/fetch.rs`**

Add above the existing `project_size` function (around line 192):

```rust
/// Pre-flight size gate: if the server reported `RFC822.SIZE` and it
/// exceeds `limit`, return `Error::SizeLimit` immediately — before
/// issuing `FETCH BODY.PEEK[]`. When the server omits the size (or
/// returns `None`), this function passes and we fall through to the
/// existing post-parse `project_size` check.
///
/// This is defense-in-depth: servers can lie about `RFC822.SIZE`, so
/// the post-parse check remains the final gate.
fn preflight_size_check(
    server_size: Option<u32>,
    limit: u64,
) -> Result<(), Error> {
    if let Some(size) = server_size {
        if u64::from(size) > limit {
            return Err(Error::SizeLimit { limit });
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rimap-imap preflight_size_check -- --nocapture`
Expected: all 4 tests pass.

- [ ] **Step 5: Add `preflight_fetch_size` async function**

Add a new async function in `ops/fetch.rs` that issues the `UID FETCH <uid> (RFC822.SIZE)` probe:

```rust
/// Issue `UID FETCH <uid> (RFC822.SIZE)` and return the server-reported
/// size if present. Used as a pre-flight check before `fetch_body` to
/// avoid buffering oversize messages.
pub(crate) async fn preflight_fetch_size(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
) -> Result<Option<u32>, Error> {
    session
        .examine(folder)
        .await
        .map_err(super::folders::map_err)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "(UID RFC822.SIZE)")
        .await
        .map_err(super::folders::map_err)?;

    let mut size = None;
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        if msg.uid == Some(uid.get()) {
            size = msg.size;
        }
    }
    Ok(size)
}
```

- [ ] **Step 6: Wire pre-flight check into `Connection::fetch_body`**

In `crates/rimap-imap/src/connection.rs`, modify the `fetch_body` method. The key change: inside the timeout block, call `preflight_fetch_size` first, run `preflight_size_check`, then proceed to the existing `fetch_body` call.

Replace the body of the timeout closure in `Connection::fetch_body` (lines ~542-548):

```rust
pub async fn fetch_body(
    &self,
    folder: &str,
    uid: crate::types::Uid,
) -> Result<Vec<u8>, Error> {
    let dur = self.inner.cfg.command_timeout;
    let limit = self.inner.cfg.max_fetch_body_bytes;
    let result = crate::time::with_timeout("fetch_body", dur, async {
        let mut guard = self.session().await?;
        let session = guard
            .as_mut()
            .unwrap_or_else(|| unreachable!("session() ensures Some"));

        // Pre-flight: ask the server for RFC822.SIZE before fetching
        // the full body. Rejects oversize messages without buffering
        // them. The folder is already EXAMINEd by preflight_fetch_size,
        // so fetch_body's EXAMINE is a no-op (same selected state).
        let server_size =
            crate::ops::fetch::preflight_fetch_size(
                session, folder, uid,
            )
            .await?;
        crate::ops::fetch::preflight_size_check(server_size, limit)?;

        crate::ops::fetch::fetch_body(session, folder, uid, limit)
            .await
    })
    .await;
    // ... existing invalidation logic unchanged ...
```

Note: `preflight_size_check` must be made `pub(crate)` for `connection.rs` to call it.

- [ ] **Step 7: Update `preflight_size_check` visibility**

Change `fn preflight_size_check` to `pub(crate) fn preflight_size_check` in `ops/fetch.rs`.

- [ ] **Step 8: Update the `Connection::fetch_body` docstring**

Remove the paragraph about callers needing `cgroups`/`RLIMIT_AS` and the link to issue #32, replacing with:

```rust
/// # Pre-flight size check
///
/// Before fetching the body, issues `UID FETCH <uid> (RFC822.SIZE)` to
/// get the server-reported message size. If it exceeds
/// `max_fetch_body_bytes`, returns `Error::SizeLimit` without issuing
/// the body fetch — avoiding the intermediate allocation inside
/// async-imap. The post-parse `project_size` check remains as
/// defense-in-depth (servers can misreport `RFC822.SIZE`).
```

- [ ] **Step 9: Run full test suite and lint**

Run: `cargo test -p rimap-imap && cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: all tests pass, no warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/rimap-imap/src/ops/fetch.rs crates/rimap-imap/src/connection.rs
git commit -m "fix(imap): add pre-flight RFC822.SIZE check before fetch_body (#32)

Issue UID FETCH RFC822.SIZE before FETCH BODY.PEEK[] so oversize
messages are rejected without buffering the full body in async-imap.
The post-parse project_size check remains as defense-in-depth."
```

---

## Task 2: Threat-model-reviewer agent (#14)

**Files:**
- Create: `.claude/agents/threat-model-reviewer.md`

This agent reviews specs and plans (not code) for threat-model completeness. It runs STRIDE against new components, checks asset enumeration, trust boundary mapping, attacker model clarity, and deferral discipline.

- [ ] **Step 1: Create the agent file**

Create `.claude/agents/threat-model-reviewer.md` with the following content:

```markdown
---
name: threat-model-reviewer
description: Use this agent to review rusty-imap-mcp specs and plans for threat-model completeness. Invoke on changes to docs/superpowers/specs/ or docs/superpowers/plans/, especially when new components, trust boundaries, or attacker surfaces are introduced. Operates on design documents, not code.
tools: Read, Grep, Glob, Bash, WebFetch
model: opus
---

# Threat Model Reviewer — rusty-imap-mcp

You are a threat-model reviewer for design documents. You review specs (`docs/superpowers/specs/`) and plans (`docs/superpowers/plans/`), not code. Your job is to ensure every new component has an explicit threat analysis before implementation begins.

## Project threat model (ground truth)

`rusty-imap-mcp` is a security-first MCP server for IMAP email. The design spec lives at `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`. Read it before every review — it is the canonical threat model.

**Primary adversary:** Crafted email attempting prompt injection to induce an LLM agent to exfiltrate data, send mail, modify mailbox state, or pivot to other tools.

**Secondary adversaries:**
- Hostile IMAP server (MITM, malformed IMAP responses, oversized literals)
- Local malware with the user's file-system UID

**Trusted:** Config file, keychain entries, audit log, TLS identity (within fingerprint-pinning limits).

**Untrusted:** Email bodies, headers, sender addresses, display names, attachment filenames, link targets, all server-provided content.

## Review checklist

For each spec or plan under review, check every item. A missing item is a finding.

### 1. Asset enumeration

- What secrets does this component handle? (credentials, tokens, keys)
- What data does it process? (email content, metadata, user input)
- What capabilities does it grant? (network access, filesystem write, mailbox mutation)
- Are assets classified by sensitivity? (public metadata vs. credential vs. PII)

### 2. Trust boundary mapping

- Where do untrusted inputs enter this component?
- What sanitizer or validator sits at each entry point?
- Does the spec name the specific crate/module responsible for validation?
- Are there any paths where untrusted data bypasses sanitization?

### 3. STRIDE analysis

For each new component or interface, produce a table:

| Threat | Applies? | Mitigation | Spec section |
|--------|----------|------------|--------------|
| **S**poofing | Does the component authenticate its inputs/peers? | | |
| **T**ampering | Can an attacker modify data in transit or at rest? | | |
| **R**epudiation | Is the action auditable? Is the audit tamper-evident? | | |
| **I**nformation disclosure | Can secrets or PII leak through errors, logs, timing? | | |
| **D**enial of service | Are there unbounded allocations, recursion, or fan-out? | | |
| **E**levation of privilege | Can the component be used to bypass posture/authz? | | |

### 4. Attacker model clarity

- Every defense must cite the attacker class it defends against
- Valid attacker classes: `malicious-email`, `hostile-imap-server`, `mitm`, `local-user`, `stolen-laptop`, `compromised-mcp-client`
- A defense without a named attacker is a finding

### 5. Deferral discipline

- Any threat acknowledged but not mitigated in this sprint must have a GitHub issue
- The issue must cite the spec section, name the threat, and state acceptance criteria
- "Deferred to Sprint N" in prose without an issue link is a finding
- Check: `gh issue list --state open` for existing tracking

### 6. Cross-reference with existing taxonomies

Link each identified threat to the most relevant taxonomy id from the six code-level reviewers:

| Reviewer | Prefix | Scope |
|----------|--------|-------|
| mcp-security-reviewer | `MCP-*` | Prompt injection, tool poisoning, auth, transport |
| email-imap-security-reviewer | `MAIL-*` | IMAP protocol, MIME, TLS, header parsing |
| local-security-reviewer | `LOCAL-*` | Secrets, disk, permissions, TOCTOU |
| rust-safety-reviewer | `RUST-*` | Unsafe, panics, async, integer overflow |
| supply-chain-reviewer | `SC-*` | Dependencies, build, SBOM |
| ci-cd-security-reviewer | `CI-*` | Actions, tokens, branch protection |

A new threat that doesn't map to any existing category suggests the taxonomy needs extending — flag this.

## Review process

1. **Read the spec/plan end-to-end.** Understand what it claims to build.
2. **Run the checklist** (sections 1-6 above) against each new component.
3. **Compare against the canonical threat model** in the design spec. Flag any divergence.
4. **Check prior sprint plans** for accumulated deferrals that this sprint should address.
5. **Verify GitHub issues exist** for all deferred threats.

## Reporting format

Produce findings as a prioritized list. Each finding must have:

1. **Severity** — `critical` / `high` / `medium` / `low` / `info`
2. **Checklist item** — which section above was violated (e.g., "STRIDE-D", "Deferral discipline")
3. **Location** — spec file and section heading
4. **What** — one sentence describing the gap
5. **Recommendation** — what to add to the spec or what issue to file

End with a STRIDE summary table for the reviewed component(s) and a list of any new GitHub issues needed.

## What NOT to do

- Do not review code. This agent reviews design documents only.
- Do not invent threats that require attacker capabilities outside the project's threat model.
- Do not recommend features beyond what the spec proposes.
- Do not mark a spec "safe" without running every checklist item.
```

- [ ] **Step 2: Verify the agent file parses correctly**

Run: `head -5 .claude/agents/threat-model-reviewer.md`
Expected: frontmatter with `name`, `description`, `tools`, `model` fields.

- [ ] **Step 3: Commit**

```bash
git add .claude/agents/threat-model-reviewer.md
git commit -m "feat: add threat-model-reviewer agent for specs and plans (#14)"
```

---

## Task 3: SECURITY.md hygiene and security-docs-reviewer agent (#18)

**Files:**
- Modify: `SECURITY.md`
- Create: `.claude/agents/security-docs-reviewer.md`

### Part A: Enhance SECURITY.md

- [ ] **Step 1: Update SECURITY.md with disclosure process details**

Add the following sections to `SECURITY.md` after the existing content:

- **Disclosure timeline:** Initial response within 7 days, fix target within 90 days, coordinated disclosure preferred.
- **CVE process:** Security advisories filed via GitHub Security Advisories (GHSA). CVEs requested through GitHub's CNA integration.
- **Security contact identity:** No PGP key pre-v1; Sigstore identity will be established when release signing lands (tracked in #19).
- **Supported versions policy:** Pre-v1: latest `main` only. Post-v1: current major release receives security fixes for 12 months; previous major receives critical fixes for 6 months.

The exact content is specified in Step 2 below.

- [ ] **Step 2: Write the updated SECURITY.md**

Replace the "Supported versions" section (lines 35-38) and append after it:

```markdown
## Supported versions

During pre-v1 development, only the latest commit on `main` is supported. Once
v1.0.0 ships, this policy applies:

| Version | Security fixes | End of support |
|---------|---------------|----------------|
| Current major (e.g., 1.x) | All severity levels | 12 months after next major |
| Previous major (e.g., 0.x) | Critical only | 6 months after next major |

## Disclosure timeline

- **Initial response:** within 7 calendar days of report
- **Fix target:** within 90 calendar days of confirmed vulnerability
- **Coordinated disclosure:** preferred; we will work with the reporter on timing
- **Public disclosure:** after the fix ships, or after 90 days, whichever comes first

## CVE process

Security vulnerabilities are tracked via
[GitHub Security Advisories](https://github.com/randomparity/rusty-imap-mcp/security/advisories).
CVEs are requested through GitHub's CNA (CVE Numbering Authority) integration
when the advisory is published. We do not self-assign CVE IDs.

## Security contact identity

Pre-v1, the security contact is the repository owner via GitHub Security
Advisories (no direct email). A Sigstore signing identity and release
attestations will be established when release automation lands (tracked in
[#19](https://github.com/randomparity/rusty-imap-mcp/issues/19)).
```

- [ ] **Step 3: Verify SECURITY.md renders correctly**

Run: `cat SECURITY.md | head -80`
Expected: well-formed Markdown with all new sections.

### Part B: Create security-docs-reviewer agent

- [ ] **Step 4: Create `.claude/agents/security-docs-reviewer.md`**

```markdown
---
name: security-docs-reviewer
description: Use this agent to audit SECURITY.md for currency against the project's threat model, CVE disclosure readiness, and supported-versions accuracy. Invoke on changes to SECURITY.md, docs/superpowers/specs/, release tag workflows, or version bumps.
tools: Read, Grep, Glob, Bash, WebFetch
model: sonnet
---

# Security Documentation Reviewer — rusty-imap-mcp

You review `SECURITY.md` and related security documentation for currency and completeness. You do not review code.

## Checklist

Run every item on each review. A gap is a finding.

### 1. Threat model currency

- Does `SECURITY.md`'s threat model summary match the canonical threat model in `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md` sections 1, 6, 7, 8, 9, 10?
- Are all adversary classes listed? (crafted email, hostile IMAP server, local malware)
- Are trust/untrust boundaries accurate?
- Has a new sprint introduced components not reflected in the summary?

### 2. Vulnerability reporting process

- Is the reporting channel documented? (GitHub Security Advisories)
- Is the response timeline stated? (7 days initial, 90 days fix target)
- Is coordinated disclosure mentioned?
- Is there a fallback contact if GitHub is unavailable?

### 3. CVE process

- Is the CVE numbering authority identified? (GitHub CNA)
- Is the advisory-to-CVE workflow described?
- Are known-affected-version communication steps documented?

### 4. Supported versions

- Does the supported-versions table match the actual release cadence?
- Is the MSRV commitment reflected? (currently 1.88.0, in `[workspace.package]`)
- Post-v1: does the table list specific version ranges?

### 5. Security contact identity

- Is a signing identity documented? (PGP key, Sigstore identity, or "not yet established")
- If not yet established, is the tracking issue linked?
- Post-v1: are release signatures verifiable?

### 6. Spec alignment

- Read the latest sprint spec under `docs/superpowers/specs/`
- Check if any new trust boundaries, attacker classes, or defense layers are missing from `SECURITY.md`
- Flag any divergence as a finding

## Reporting format

Findings as a prioritized list:

1. **Severity** — `high` (stale threat model) / `medium` (missing process detail) / `low` (minor wording) / `info`
2. **Checklist item** — section number above
3. **Location** — file and line/section
4. **What** — one sentence
5. **Fix** — specific text to add or change

## When to invoke

- Changes to `SECURITY.md`
- Changes to `docs/superpowers/specs/` (new threat surfaces)
- Release tag workflows (verify disclosure channel reachability)
- Version bumps in `Cargo.toml` (supported-versions table currency)
```

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md .claude/agents/security-docs-reviewer.md
git commit -m "feat: enhance SECURITY.md and add security-docs-reviewer agent (#18)

Add disclosure timeline, CVE process, supported-versions policy, and
security contact identity sections to SECURITY.md. Create a reviewer
agent to keep the document current against the threat model."
```

---

## Task 4: Release integrity reviewer placeholder (#19)

**Files:**
- Create: `.claude/agents/release-integrity-reviewer.md`

This is a placeholder agent. Issue #19 explicitly says "create this agent when release automation lands, not before." We create the file with a clear "not yet active" header and the full taxonomy from the issue so it's ready to activate.

- [ ] **Step 1: Create `.claude/agents/release-integrity-reviewer.md`**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/release-integrity-reviewer.md
git commit -m "feat: add placeholder release-integrity-reviewer agent (#19)

Placeholder agent with full taxonomy from #19. Not yet active — will
be activated when release automation lands post-v1."
```

---

## Task 5: Final verification

- [ ] **Step 1: Run full CI locally**

Run: `just ci`
Expected: all checks pass (fmt, clippy, test, deny).

- [ ] **Step 2: Verify all new agent files have correct frontmatter**

Run: `head -6 .claude/agents/threat-model-reviewer.md .claude/agents/security-docs-reviewer.md .claude/agents/release-integrity-reviewer.md`
Expected: each file has `---` delimited frontmatter with `name`, `description`, `tools`, `model`.

- [ ] **Step 3: Verify issue references are correct**

Run: `gh issue view 32 --json title,state && gh issue view 14 --json title,state && gh issue view 18 --json title,state && gh issue view 19 --json title,state`
Expected: all four issues are open.
