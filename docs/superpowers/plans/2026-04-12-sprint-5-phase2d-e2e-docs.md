# Sprint 5 Phase 2d — End-to-End Tests, Documentation, Cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate the full MCP server with a scripted Dovecot smoke test, publish v0.1.0 documentation, clean up deferred items (epvme_runner tests, mutants rerun), and tag `v0.1.0`.

**Architecture:** The e2e test starts the MCP server in-process against the Dovecot container, sends MCP tool requests, and validates responses including audit log assertions. Documentation describes existing behavior from code and specs.

**Spec:** [`../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md`](../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md) §5

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/rimap-server/tests/e2e_dovecot.rs` | Full-session MCP smoke test |
| `docs/configuration.md` | Config file format, all fields, defaults |
| `docs/postures.md` | Three postures, tool matrix, overrides |
| `docs/security-model.md` | Threat model, sanitization, audit, $PendingReview |
| `docs/proton-bridge-setup.md` | Bridge install, fingerprint capture, config |
| `docs/audit-log.md` | JSONL schema, record types, rotation, merge |
| `crates/rimap-content/tests/epvme_integration.rs` | epvme_runner integration tests |

---

### Task 1: End-to-end smoke test

Write a Dovecot-backed integration test that exercises the full MCP tool chain. Gated behind `RIMAP_REQUIRE_DOCKER=1`.

### Task 2: Documentation — configuration.md

Config file format, all fields with defaults, env var overrides, credential resolution.

### Task 3: Documentation — postures.md

Three postures, the tool matrix, per-tool overrides, list_tools behavior.

### Task 4: Documentation — security-model.md

Threat model summary, sanitization pipeline, lookalike detection, audit log, $PendingReview.

### Task 5: Documentation — proton-bridge-setup.md

Bridge install, TLS fingerprint capture, config example, known quirks.

### Task 6: Documentation — audit-log.md

JSONL schema, record types, rotation, `audit merge`, operator notes.

### Task 7: epvme_runner integration tests

Tests for `collect_eml_files` and `run_dataset` over fixture directory.

### Task 8: Mutants rerun

Run `cargo mutants --package rimap-content --timeout 120`, update docs.

### Task 9: Final CI verification and v0.1.0 readiness

Run `just ci`, verify all exit criteria, prepare for tag.
