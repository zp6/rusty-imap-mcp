# Dovecot 2.4 Multi-Arch Test Fixture

**Date:** 2026-05-13
**Status:** Spec (pending implementation plan)
**Tracking:** GitHub issue #273

## Problem

The integration-test Dovecot fixture is pinned to `docker.io/dovecot/dovecot:2.3.21`, which is published only for `linux/amd64`. Two test harnesses (`crates/rimap-server/tests/support/dovecot/harness.rs` and `crates/rimap-imap/tests/integration/support/container.rs`) silently skip on `std::env::consts::ARCH != "x86_64"` because the 2.3.21 image crashes under Rosetta on arm64 macOS (`rosetta error: unable to mmap ExecutableHeap: 12` — `ENOMEM` in dovecot worker processes). Consequence: every integration test for `rimap-imap` and `rimap-server` silently skips for any developer working on Apple Silicon, and only CI exercises that surface.

## Goal

Run the Dovecot-backed integration suites on both `linux/amd64` (CI) and `arm64 macOS` (local Apple-Silicon dev hosts) using the same fixture, same harness, same assertions. Close issue #273.

## Non-Goals

- Deduplicating the two harnesses that both call into the same compose tree.
- Switching from `docker compose` to a Rust container library.
- Supporting a non-container fallback.
- Pinning the Docker image by SHA digest (separate Dependabot/supply-chain decision).

## Approach

Single-step replacement: bump the fixture to `dovecot/dovecot:2.4.4`, rewrite `dovecot.conf` to 2.4 syntax, and delete the arch gate from both harnesses. No 2.3 fallback, no runtime config translation, no dual-image branching — consistent with the project's "replace, don't deprecate" rule.

## Components Touched

### 1. Image bump
- File: `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`
- Change: `image: docker.io/dovecot/dovecot:2.3.21` → `image: docker.io/dovecot/dovecot:2.4.4`
- Drop the multi-line comment that explained the amd64-only constraint; the new image is multi-arch.

`2.4.4` was published 2026-05-12 and ships both `linux/amd64` and `linux/arm64` manifests. The plan stage will confirm the tag is still the latest stable at implementation time and bump if a newer 2.4.x has shipped.

### 2. Config rewrite

File: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`. Rewritten from scratch in 2.4 syntax. Final text is verified at implementation time against `doveconf -n` inside the running 2.4.4 container; the table below records intent.

| 2.3 (current) | 2.4 target | Notes |
|---|---|---|
| (none) | `dovecot_config_version = 2.4.4` | new required first line in 2.4 |
| (none) | `dovecot_storage_version = 2.4.4` | new required setting in 2.4 |
| `protocols = imap` | unchanged | |
| `ssl = required` | unchanged | tightened semantics: login_trusted_networks also requires TLS; our list is empty so test path is unaffected |
| `ssl_cert = </etc/dovecot/cert.pem` | unchanged | |
| `ssl_key = </etc/dovecot/key.pem` | unchanged | |
| `ssl_min_protocol = TLSv1.2` | unchanged | `SSLv3` removed in 2.4; we don't use it |
| `disable_plaintext_auth = yes` | unchanged | |
| `login_trusted_networks =` | unchanged | empty list preserved |
| `mail_location = maildir:~/Maildir` | `mail_path = ~/Maildir` + `mail_driver = maildir` | per 2.4 rename; exact split verified via `doveconf -n` in the new image |
| `passdb { driver = passwd-file; args = scheme=PLAIN /etc/dovecot/users }` | `passdb passwd-file { passwd_file_path = /etc/dovecot/users; default_password_scheme = PLAIN }` | sections require names in 2.4; `args =` removed in favour of named settings |
| `userdb { driver = static; args = uid=1000 gid=1000 home=/var/mail/%u }` | `userdb static { fields = uid=1000 gid=1000 home=/var/mail/%u }` | named section; `args` → `fields` |
| `namespace inbox { … mailbox Drafts/Junk/Sent/Trash { special_use=…; auto=subscribe } }` | structurally unchanged | already named `inbox`; mailbox blocks already named |
| `service imap-login { inet_listener imap { port=143 } inet_listener imaps { port=993; ssl=yes } }` | structurally unchanged | already-named sections satisfy 2.4 rule |
| `log_path = /dev/stderr` / `info_log_path = /dev/stderr` / `debug_log_path = /dev/stderr` | unchanged | `auth_debug`/`mail_debug` removed but we don't use them |

**Implementation-time follow-up:** if the upstream image's baked-in `/etc/dovecot/conf.d/*.conf` overrides our settings, explicitly disable the conf.d include (drop the `!include conf.d/*.conf` line if our config inherits it, or rely on `dovecot -c /etc/dovecot/dovecot.conf` mounting our file directly, which is already the layout).

### 3. Harness arch gate removal

**`crates/rimap-server/tests/support/dovecot/harness.rs`** (lines 48–73). `check_prerequisites` collapses to:

```rust
fn check_prerequisites() -> Result<(), HarnessError> {
    let require_runtime = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();
    if !runtime_available() {
        return if require_runtime {
            Err(HarnessError::ComposeFailed(
                "neither docker nor podman found but RIMAP_REQUIRE_DOCKER=1".into(),
            ))
        } else {
            Err(HarnessError::DockerUnavailable)
        };
    }
    Ok(())
}
```

Module `//!` doc comment (lines 1–6) loses the "silently skips on non-x86_64" sentence.

**`crates/rimap-imap/tests/integration/support/container.rs`** — equivalent change at lines 259–276 plus rustdoc at lines 86–95.

### 4. Caller-side doc comment sweep

- `crates/rimap-server/tests/e2e.rs:5`
- `crates/rimap-server/tests/e2e_wire.rs:9`
- `crates/rimap-imap/tests/integration/dovecot.rs:2`

Each currently mentions the arch skip; each gets a one-line update reflecting the new "container runtime required on any arch" reality.

### 5. AGENTS.md

Lines 72–108 currently encode the Rosetta failure mode and arch-gate rationale. Replace with a shorter section: container runtime is required on any host; `RIMAP_REQUIRE_DOCKER=1` flips silent-skip to a hard error when the runtime is missing; no arch caveats.

### 6. Memory cleanup

Delete `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_dovecot_rosetta_gate.md` and remove its line from `MEMORY.md`. The memo exists specifically to discourage removing the arch gate; once the gate is gone the memo is actively misleading.

## Out of Scope

- Deduplicating the two harnesses (`rimap-server` and `rimap-imap` both have a near-identical `runtime_available` + prerequisite-check stack).
- Replacing `docker compose` with a Rust container library.
- Image digest pinning.
- Adding a non-container fallback for environments without Docker/Podman.

## Verification

The migration is complete only when verification passes on **both** `linux/amd64` and `arm64 macOS`. Asymmetric verification is the known failure mode.

### Bring-up (manual, both arches)

1. `docker pull docker.io/dovecot/dovecot:2.4.4`; confirm host-native manifest with `docker image inspect | jq '.[].Architecture'`.
2. `RIMAP_DOVECOT_HOST_PORT=9993 RIMAP_DOVECOT_HOST_PORT_STARTTLS=1143 docker compose -p smoke up -d`
3. `docker compose -p smoke logs dovecot` — no `dovecot_config_version` upgrade-required error, no unknown-setting errors, `[entrypoint] ready` line emitted.
4. `openssl s_client -connect 127.0.0.1:9993 -servername localhost` returns the self-signed cert.
5. `docker exec <name> doveadm mailbox list -u rimap-test` returns INBOX and the seeded sub-folders without `Disconnected unexpectedly`.
6. `docker compose -p smoke down -v --remove-orphans` cleans up.

### Automated (CI on amd64, local on arm64 macOS)

7. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap --test dovecot --locked`
8. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e --locked`
9. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked`

Each suite must pass on both arches. Silent-skip on arm64 = failure of this migration's central goal.

### Specific risks

- **`case_11` force-recreate flow** (rimap-imap). Relies on the shared volume persisting `cert.pem` / `key.pem` across `docker compose up --force-recreate` so the pinned TLS fingerprint stays stable. 2.4 doesn't touch volume semantics, but this test exercises a real TCP/TLS race and is the most likely regression site.
- **`doveadm -u rimap-test`**. 2.4 tightened `doveadm` USER-env-var semantics, but our calls already pass `-u`, so should be unaffected.
- **Entrypoint wait-for-LISTEN ordering**. The current `entrypoint.sh` parses `/proc/net/tcp{,6}` to wait for port 993 before publishing readiness markers; 2.4's child-process startup order may differ. Step 4 of bring-up + step 9 of automated verification jointly cover this.

### No-silent-skip regression guard

Run `cargo nextest run -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe` *without* `RIMAP_REQUIRE_DOCKER=1` on a host with Docker available; the test must execute and pass, not return "0 tests executed". If silent-skip re-appears, the harness has regressed.

## Implementation Order

The plan derived from this spec should sequence work so that intermediate states are testable:

1. Bring up the new image with an exploratory config on arm64 macOS (offline, not committed).
2. Extract `doveconf -n` output as the source of truth for the rewritten `dovecot.conf`.
3. Commit the new compose tree (image bump + config) on a branch.
4. Remove the arch gates from both harnesses on the same branch — there's no env-var bypass today, so a local patch and a gate removal are the same edit. Run the suites on arm64 macOS at this point.
5. Update AGENTS.md and caller-side doc comments to reflect the new "container runtime required on any arch" rule.
6. Verify on CI (linux/amd64) before merging.
7. Delete the obsolete memory note (`project_dovecot_rosetta_gate.md`) and its `MEMORY.md` index line.

## Open Questions for the Plan Stage

1. **Exact image tag.** Plan-time check: is `2.4.4` still latest stable, or has `2.4.5+` shipped? Pin to whatever is current.
2. **`mail_location` replacement form.** `mail_path` + `mail_driver` is the most likely split per the 2.4 docs; `doveconf -n` from the running image is authoritative.
3. **`userdb static.args` → `fields` rename.** Same — confirm via `doveconf -n`.
4. **Inherited `/etc/dovecot/conf.d/*.conf`.** Does the upstream image ship them? If yes, do they interfere? The current 2.3 mount uses a single `dovecot.conf` that does not include `conf.d/` — verify same behaviour on 2.4.4.
