# Audit Cancellation Drop-Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three audit-durability issues as one sweep — guarantee every `tool_start` record is paired with a `tool_end` even when the MCP handler future is dropped mid-call (#71, #99), and pin `fail_open = true` write-failure propagation with a test (#72).

**Architecture:** Introduce a `CancelledToolEndSender` primitive in `rimap-audit` (bounded async channel) and a dedicated drainer task that consumes it via `spawn_blocking` calls into the existing `AuditWriter`. `run_with_audit_envelope` in `rimap-server/src/mcp/audit_envelope.rs` wraps its body in an `AuditEnvelopeGuard`. On normal completion the guard is disarmed before `emit_tool_end` fires. If the outer future is dropped between `emit_tool_start` and the disarm call, the guard's `Drop` impl synthesizes a `ToolEnd { status: Cancelled, error_code: ERR_CANCELLED, duration_ms: elapsed }` record and enqueues it via the channel. The drainer task drains remaining records on shutdown.

**Tech Stack:** Rust (stable), `tokio` (`task::spawn_blocking`, `JoinHandle`), `async_channel` (bounded), existing `rimap-audit::AuditWriter`.

---

## Prior-Art Context

`crates/rimap-server/src/mcp/audit_envelope.rs` currently implements `run_with_audit_envelope`. It calls `emit_tool_start` (returns a `Seq`), awaits `body`, then calls `emit_tool_end`. Both `emit_tool_start` / `emit_tool_end` offload to `spawn_blocking` and surface audit-write failures (the former as `ErrorData::internal_error`, the latter as `tracing::error!`). There is currently no drop-guard — a dropped outer future leaves an orphan `tool_start`.

Issues #71 and #99 reference the same logical call site at different review cycles. #71's line references (`server.rs:265-315`) predate the refactor that moved the pair into `mcp/audit_envelope.rs`; both are addressed by one guard.

`AuditWriter` (`crates/rimap-audit/src/writer/mod.rs`) already has `fail_open: bool` and a `suppressed_failures: Arc<AtomicU64>` counter. On `fail_open = true`, write errors log via `tracing::error!` and increment the counter; the writer returns `Ok(())` to callers. This is what #72 wants to pin with a test.

---

## File Structure

### New files

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `crates/rimap-audit/src/cancellation.rs` | `CancelledToolEndSender` / `CancelledToolEndReceiver` wrapper types + drainer task helper. |

### Modified files

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-core/src/error.rs` | Add `ErrorCode::Cancelled` → `"ERR_CANCELLED"`. Update `as_str`, `from_str`, and the `round_trip_pairs` list. |
| Modify | `crates/rimap-audit/src/record/mod.rs` | Add `ToolStatus::Cancelled` variant (snake_case serde). Round-trip test. |
| Modify | `crates/rimap-audit/src/lib.rs` | Register `cancellation` module; re-export the public types. |
| Modify | `crates/rimap-audit/src/writer/mod.rs` | Add a `#[cfg(test)]` failure-injection hook (`force_next_write_failure`) used only by #72's test. |
| Modify | `crates/rimap-server/src/mcp/audit_envelope.rs` | `AuditEnvelopeGuard` struct + `Drop` impl + wiring into `run_with_audit_envelope`. |
| Modify | `crates/rimap-server/src/mcp/server.rs` | `ImapMcpServer` holds the `CancelledToolEndSender`; construction accepts it. |
| Modify | `crates/rimap-server/src/main.rs` | Construct sender + drainer at boot, await drainer handle on shutdown. |
| Create | `crates/rimap-server/tests/audit_cancellation.rs` | Integration test for the drop-induced cancellation. |
| Create | `crates/rimap-server/tests/audit_fail_open.rs` | Integration test for #72 (fail_open=true + write failure). |

---

## Task 1: Add `ErrorCode::Cancelled` variant

**Issue:** prerequisite for the cancellation record's `error_code` field.

**Files:**
- Modify: `crates/rimap-core/src/error.rs`

### Approach

Add a new variant `Cancelled` that serializes to `"ERR_CANCELLED"`. Keep the existing pattern: `as_str` match arm, `from_str` parse arm, and an entry in the `round_trip_pairs` list used by the tests.

- [ ] **Step 1: Write failing test**

Add to `crates/rimap-core/src/error.rs` tests:

```rust
    #[test]
    fn cancelled_round_trips() {
        assert_eq!(ErrorCode::Cancelled.as_str(), "ERR_CANCELLED");
        assert_eq!("ERR_CANCELLED".parse::<ErrorCode>().unwrap(), ErrorCode::Cancelled);
    }
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test -p rimap-core --lib error::tests::cancelled_round_trips`
Expected: FAIL — variant undefined.

- [ ] **Step 3: Add the variant**

In `crates/rimap-core/src/error.rs`, add `Cancelled` to the `ErrorCode` enum:

```rust
    /// Operation cancelled before completion (e.g. client disconnect, runtime
    /// shutdown). Emitted in `tool_end` records synthesized by the cancellation
    /// drop-guard (#99).
    Cancelled,
```

Add the `as_str` match arm:

```rust
            Self::Cancelled => "ERR_CANCELLED",
```

Add the `from_str` parse arm. Find the existing `match s { "ERR_X" => Ok(Self::X), ... }` block and add `"ERR_CANCELLED" => Ok(Self::Cancelled),`.

Add the entry to the `round_trip_pairs` list (or equivalent) used by the existing `every_code_round_trips` test:

```rust
            (ErrorCode::Cancelled, "ERR_CANCELLED"),
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test -p rimap-core --lib error::tests`
Expected: PASS including the new `cancelled_round_trips` and the existing `every_code_round_trips`.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/error.rs
git commit -m "core: add ErrorCode::Cancelled (#99 prep)

New variant for the cancellation drop-guard: resolves to
\"ERR_CANCELLED\". Used by the synthesized tool_end record when the
MCP dispatch future is dropped mid-call."
```

---

## Task 2: Add `ToolStatus::Cancelled` variant

**Issue:** prerequisite for the cancellation record's `status` field.

**Files:**
- Modify: `crates/rimap-audit/src/record/mod.rs`

### Approach

Add `Cancelled` to `ToolStatus` with snake_case serde.

- [ ] **Step 1: Write failing test**

In `crates/rimap-audit/src/record/mod.rs`:

```rust
    #[test]
    fn tool_status_cancelled_serializes_as_snake_case() {
        let j = serde_json::to_string(&ToolStatus::Cancelled).unwrap();
        assert_eq!(j, "\"cancelled\"");
        let back: ToolStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ToolStatus::Cancelled);
    }
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test -p rimap-audit --lib record::tests::tool_status_cancelled_serializes_as_snake_case`
Expected: FAIL.

- [ ] **Step 3: Add the variant**

In `crates/rimap-audit/src/record/mod.rs`, find the `ToolStatus` enum and add:

```rust
pub enum ToolStatus {
    /// Tool call succeeded.
    Ok,
    /// Tool call failed.
    Error,
    /// Tool call was cancelled (e.g. client disconnect, runtime shutdown).
    /// Written by the cancellation drop-guard on future drop; see #99.
    Cancelled,
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test -p rimap-audit --lib record::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/record/mod.rs
git commit -m "audit: add ToolStatus::Cancelled variant (#99 prep)

Serializes as \"cancelled\". Used by the tool_end record the
cancellation drop-guard synthesizes when the MCP dispatch future is
dropped mid-call."
```

---

## Task 3: Cancellation channel primitive + drainer task

**Issue:** #71, #99 — the shared mechanism both layers consume.

**Files:**
- Create: `crates/rimap-audit/src/cancellation.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

### Approach

Wrap `async_channel::bounded::<ToolEndInputs>(1024)` in a pair of newtypes — `CancelledToolEndSender` (`Clone`, used from sync `Drop`) and `CancelledToolEndReceiver` (used once by the drainer). Provide a `spawn_drainer` helper that returns the tokio `JoinHandle` so `main.rs` can await it at shutdown.

Verify `async_channel` is already a workspace dep (used in `rimap-imap/connection.rs`). If `rimap-audit/Cargo.toml` lacks it, add `async_channel = { workspace = true }`.

- [ ] **Step 1: Write failing unit test**

Create `crates/rimap-audit/src/cancellation.rs`:

```rust
//! Cancellation drop-guard plumbing: a bounded channel of `ToolEndInputs`
//! submitted from `Drop` (sync) and consumed by a dedicated tokio task that
//! routes each record through the existing `AuditWriter::log_tool_end` path.
//!
//! Used by `rimap-server/src/mcp/audit_envelope.rs::AuditEnvelopeGuard` to
//! close out the `tool_start` / `tool_end` pair when the MCP dispatch future
//! is dropped mid-call (#71, #99).

use crate::ToolEndInputs;
use crate::writer::AuditWriter;

/// Channel capacity. 1024 outstanding cancellations is a lot — drops here
/// only happen on client disconnect / shutdown, not steady-state.
const CHANNEL_CAPACITY: usize = 1024;

/// Clone-cheap handle used by `Drop` implementations to enqueue a
/// cancellation `ToolEnd`. `try_send` is non-blocking; on `Full` or `Closed`
/// the caller logs a warning and discards the record.
#[derive(Clone, Debug)]
pub struct CancelledToolEndSender {
    inner: async_channel::Sender<ToolEndInputs>,
}

impl CancelledToolEndSender {
    /// Try to enqueue a cancellation record without blocking. Returns an
    /// error if the channel is full or all receivers have dropped.
    ///
    /// # Errors
    /// Returns `async_channel::TrySendError` on `Full` or `Closed`.
    pub fn try_send(
        &self,
        inputs: ToolEndInputs,
    ) -> Result<(), async_channel::TrySendError<ToolEndInputs>> {
        self.inner.try_send(inputs)
    }
}

/// Receiver half. Created once at startup; moved into the drainer task.
pub struct CancelledToolEndReceiver {
    inner: async_channel::Receiver<ToolEndInputs>,
}

/// Build a paired `(sender, receiver)` for cancellation records.
#[must_use]
pub fn cancellation_channel() -> (CancelledToolEndSender, CancelledToolEndReceiver) {
    let (tx, rx) = async_channel::bounded(CHANNEL_CAPACITY);
    (
        CancelledToolEndSender { inner: tx },
        CancelledToolEndReceiver { inner: rx },
    )
}

/// Spawn a dedicated tokio task that drains `receiver` and writes each
/// record via `AuditWriter::log_tool_end` on a `spawn_blocking` thread.
/// The task exits when all senders are dropped and the channel drains.
///
/// The returned `JoinHandle` should be `await`ed on shutdown so the drainer
/// finishes any remaining queued records before the runtime exits.
#[must_use]
pub fn spawn_drainer(
    receiver: CancelledToolEndReceiver,
    writer: AuditWriter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(inputs) = receiver.inner.recv().await {
            let writer = writer.clone();
            let join =
                tokio::task::spawn_blocking(move || writer.log_tool_end(inputs)).await;
            match join {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::error!(
                        error = %e,
                        "cancellation tool_end write failed",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "cancellation drainer spawn_blocking panic",
                    );
                }
            }
        }
        tracing::debug!("cancellation drainer exiting — all senders dropped");
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::cancellation_channel;
    use crate::record::{Provenance, ResultSummary, ToolStatus};
    use crate::{AuditWriter, Seq, ToolEndInputs};
    use rimap_core::ErrorCode;
    use rimap_core::tool::ToolName;
    use tempfile::tempdir;

    fn dummy_inputs(account: &str) -> ToolEndInputs {
        ToolEndInputs {
            start_seq: Seq::FIRST,
            tool: ToolName::Search,
            account: Some(account.to_string()),
            status: ToolStatus::Cancelled,
            error_code: Some(ErrorCode::Cancelled),
            duration_ms: 42,
            result_summary: ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
        }
    }

    #[test]
    fn try_send_and_receive_round_trip() {
        let (tx, rx) = cancellation_channel();
        tx.try_send(dummy_inputs("a")).unwrap();
        tx.try_send(dummy_inputs("b")).unwrap();
        drop(tx);
        let received: Vec<_> = futures::executor::block_on(async {
            let mut out = Vec::new();
            while let Ok(inputs) = rx.inner.recv().await {
                out.push(inputs);
            }
            out
        });
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].account.as_deref(), Some("a"));
        assert_eq!(received[1].account.as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn drainer_writes_records_to_audit_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::new(crate::writer::AuditWriterOpts {
            path: path.clone(),
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            provenance_window_seconds: 60,
            fail_open: false,
        })
        .unwrap();

        // Prime an earlier tool_start so the tool_end has a plausible start_seq.
        let start_seq = writer
            .log_tool_start(
                ToolName::Search,
                Some("a"),
                rimap_audit::record::PostureEffective::DraftSafe,
                serde_json::Value::Object(serde_json::Map::new()),
                "0".repeat(64),
            )
            .unwrap();

        let (tx, rx) = cancellation_channel();
        let handle = super::spawn_drainer(rx, writer.clone());

        let mut inputs = dummy_inputs("a");
        inputs.start_seq = start_seq;
        tx.try_send(inputs).unwrap();
        drop(tx); // Signals drainer to exit once drained.
        handle.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        // Two JSONL records: the tool_start we primed + the cancellation tool_end.
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 records, got: {contents}");
        assert!(
            lines[1].contains(r#""status":"cancelled""#),
            "last line should be cancellation tool_end: {}",
            lines[1]
        );
    }
}
```

`rimap-audit/Cargo.toml` needs `async_channel = { workspace = true }` if not already present, plus `futures = { workspace = true }` under `[dev-dependencies]` for `futures::executor::block_on`. Check existing `Cargo.toml` before adding.

- [ ] **Step 2: Register the module**

In `crates/rimap-audit/src/lib.rs`, add:

```rust
pub mod cancellation;
pub use cancellation::{cancellation_channel, CancelledToolEndSender, CancelledToolEndReceiver, spawn_drainer};
```

- [ ] **Step 3: Run tests — expect PASS**

Run: `cargo test -p rimap-audit --lib cancellation::tests`
Expected: PASS — both tests.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/cancellation.rs crates/rimap-audit/src/lib.rs \
        crates/rimap-audit/Cargo.toml
git commit -m "audit: add cancellation channel + drainer task (#71, #99 prep)

Bounded async channel carries ToolEndInputs synthesized by
Drop-invoked cancellation guards in rimap-server. A dedicated tokio
task drains the channel and routes each record through
AuditWriter::log_tool_end via spawn_blocking. Returning the
JoinHandle lets main.rs await the drainer on shutdown so queued
records are not lost."
```

---

## Task 4: `AuditEnvelopeGuard` + `run_with_audit_envelope` integration

**Issue:** #71, #99 — the drop-guard plumbed into the dispatch path.

**Files:**
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs`

### Approach

Build `AuditEnvelopeGuard` as a local struct inside the `audit_envelope` module. The guard owns `Option<GuardInner>` so that `disarm()` swaps the inner to `None` without touching `Drop`. `Drop` checks `take()` — if `Some`, it builds the cancellation `ToolEndInputs` and calls `sender.try_send`.

`run_with_audit_envelope` constructs the guard AFTER `emit_tool_start` returns the `start_seq`. On normal completion (before or after `emit_tool_end`), call `guard.disarm()` so the Drop is a no-op.

One subtlety: `run_with_audit_envelope` currently calls `emit_tool_end` via `.await` — that path may itself be cancelled. The normal-completion code path should therefore be:

1. Construct guard.
2. Await `body` → `result`.
3. Construct the `tool_end` inputs on the stack (do NOT call `emit_tool_end` yet).
4. `guard.disarm()` — we've already committed to emitting a real `tool_end`; the guard's work is done.
5. Call `emit_tool_end` (await). If cancelled here, the real `tool_end` may be lost — but the cancellation channel will NOT emit (guard already disarmed). That's acceptable: a cancellation during the final audit write leaves a dangling `tool_start`, but the window is now sub-millisecond (a `spawn_blocking` schedule) instead of the full `body` duration.

A more ambitious fix would keep the guard armed past `emit_tool_end` submission, but that risks double-emission if `spawn_blocking` has already sent the normal `tool_end`. Keeping the guard armed only during `body` is the right scope for this PR.

- [ ] **Step 1: Read the current `run_with_audit_envelope`**

Reference: `crates/rimap-server/src/mcp/audit_envelope.rs:24-69`. Note the existing structure:

```rust
let start_seq = self.emit_tool_start(...).await?;
let start_time = Instant::now();
let result = body.await;
let duration_ms = ...;
let (status, error_code) = ...;
self.emit_tool_end(start_seq, tool, audit_account, status, error_code, duration_ms).await;
match result { ... }
```

The guard wraps the `body.await` step.

- [ ] **Step 2: Define `AuditEnvelopeGuard`**

Append to `crates/rimap-server/src/mcp/audit_envelope.rs`:

```rust
use rimap_audit::record::Provenance;
use rimap_audit::{CancelledToolEndSender, ToolEndInputs};

/// RAII guard that emits a cancellation `tool_end` record if dropped
/// undisarmed. Used inside `run_with_audit_envelope` to pair every
/// `tool_start` with a `tool_end`, even when the outer MCP dispatch
/// future is dropped mid-call (#71, #99).
struct AuditEnvelopeGuard {
    inner: Option<GuardInner>,
}

struct GuardInner {
    start_seq: rimap_audit::Seq,
    tool: ToolName,
    account: Option<String>,
    start_time: std::time::Instant,
    sender: CancelledToolEndSender,
}

impl AuditEnvelopeGuard {
    fn new(
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        start_time: std::time::Instant,
        sender: CancelledToolEndSender,
    ) -> Self {
        Self {
            inner: Some(GuardInner {
                start_seq,
                tool,
                account,
                start_time,
                sender,
            }),
        }
    }

    /// Mark the guard as completed normally. Drop becomes a no-op.
    fn disarm(&mut self) {
        self.inner = None;
    }
}

impl Drop for AuditEnvelopeGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let duration_ms = inner
            .start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        // `ToolName` is `Copy`; capture it for the warning log before
        // `try_send` consumes the payload.
        let tool = inner.tool;
        let cancellation = ToolEndInputs {
            start_seq: inner.start_seq,
            tool,
            account: inner.account,
            status: rimap_audit::record::ToolStatus::Cancelled,
            error_code: Some(rimap_core::ErrorCode::Cancelled),
            duration_ms,
            result_summary: rimap_audit::record::ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
        };
        if let Err(e) = inner.sender.try_send(cancellation) {
            tracing::warn!(
                error = %e,
                tool = tool.as_str(),
                "cancellation tool_end drop: failed to enqueue (channel full or closed)",
            );
        }
    }
}
```

- [ ] **Step 3: Wire the guard into `run_with_audit_envelope`**

Update the body of `run_with_audit_envelope` (`crates/rimap-server/src/mcp/audit_envelope.rs:24-69`):

```rust
    pub(super) async fn run_with_audit_envelope<F>(
        &self,
        tool: ToolName,
        audit_account: Option<String>,
        posture: PostureContext,
        args: &serde_json::Map<String, serde_json::Value>,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = self.redact_tool_args(tool, &args_value);
        let hash = hash_arguments(&args_value);

        let start_seq = self
            .emit_tool_start(tool, audit_account.clone(), posture, redacted, hash)
            .await?;
        let start_time = std::time::Instant::now();

        let mut guard = AuditEnvelopeGuard::new(
            start_seq,
            tool,
            audit_account.clone(),
            start_time,
            self.cancellation_sender.clone(),
        );

        let result = body.await;

        // Body completed normally. Disarm the guard before any further await
        // points so a drop of THIS future between here and emit_tool_end does
        // not cause double emission.
        guard.disarm();

        let duration_ms = start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let (status, error_code) = match &result {
            Ok(_) => (ToolStatus::Ok, None),
            Err(e) => (ToolStatus::Error, Some(e.code())),
        };
        self.emit_tool_end(
            start_seq,
            tool,
            audit_account,
            status,
            error_code,
            duration_ms,
        )
        .await;

        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
        }
    }
```

Note: this references `self.cancellation_sender` — that field is added in Task 5.

- [ ] **Step 4: Temporarily stub the field access**

Task 4 cannot compile standalone because Task 5 adds the field. Commit Tasks 4 and 5 TOGETHER (see Task 5's commit step). For now, proceed to Task 5 before running any build commands against this task's changes.

- [ ] **Step 5: No separate commit — fold into Task 5's commit**

---

## Task 5: Wire `CancelledToolEndSender` through `ImapMcpServer` and boot

**Issue:** #71, #99 — the end-to-end plumbing.

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs`
- Modify: `crates/rimap-server/src/main.rs`

### Approach

`ImapMcpServer` gains `pub(crate) cancellation_sender: CancelledToolEndSender`. `ImapMcpServer::new` takes it as an argument. `main.rs` constructs the `(sender, receiver)` pair at boot, spawns the drainer task with a clone of the `AuditWriter`, keeps the drainer's `JoinHandle` for shutdown, and passes the sender into `ImapMcpServer::new`.

On shutdown after the MCP loop exits, `drop(server)` releases the sender, the drainer's `recv().await` returns `Err`, the drainer task exits. We `await` the drainer handle so the runtime doesn't exit until the drainer finishes.

- [ ] **Step 1: Add the field to `ImapMcpServer`**

In `crates/rimap-server/src/mcp/server.rs`:

```rust
use rimap_audit::CancelledToolEndSender;

pub struct ImapMcpServer {
    /// Account registry holding per-account state.
    #[doc(hidden)]
    pub registry: AccountRegistry,
    /// Append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Channel used by `AuditEnvelopeGuard::drop` to emit synthetic
    /// cancellation `tool_end` records when the MCP dispatch future is
    /// dropped mid-call (#71, #99).
    pub(crate) cancellation_sender: CancelledToolEndSender,
    /// Per-process salt used when applying `Redactor` to tool arguments.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
    /// Redaction schemas keyed by tool name.
    pub(crate) redaction_schemas: Arc<HashMap<ToolName, RedactionSchema>>,
}

impl ImapMcpServer {
    #[must_use]
    pub fn new(
        registry: AccountRegistry,
        audit: AuditWriter,
        cancellation_sender: CancelledToolEndSender,
    ) -> Self {
        let schema_map: HashMap<ToolName, RedactionSchema> =
            schemas().into_iter().map(|s| (s.tool, s)).collect();
        Self {
            registry,
            audit,
            cancellation_sender,
            redaction_salt: Arc::new(RedactionSalt::new_random()),
            redaction_schemas: Arc::new(schema_map),
        }
    }
}
```

- [ ] **Step 2: Wire boot in `main.rs`**

In `crates/rimap-server/src/main.rs`, update the `rt.block_on` block to construct the channel and drainer:

```rust
    let mcp_result: anyhow::Result<()> = rt.block_on(async {
        let registry = build_registry(&multi, &audit, &credentials, &download_dir)
            .await
            .context("building account registry")?;

        let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
        let drainer_handle = rimap_audit::spawn_drainer(cancellation_rx, audit.clone());

        let mcp_server = server::ImapMcpServer::new(registry, audit, cancellation_tx);
        let transport = rmcp::transport::io::stdio();
        let service = Box::pin(rmcp::serve_server(mcp_server, transport))
            .await
            .map_err(|e| anyhow::anyhow!("MCP server init: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

        // ImapMcpServer drops here, releasing the cancellation sender. Wait
        // for the drainer to flush remaining records before the runtime exits.
        drop(service);
        if let Err(e) = drainer_handle.await {
            tracing::error!(error = %e, "cancellation drainer join error");
        }
        Ok(())
    });
```

The existing `audit_for_shutdown.log_process_end(...)` call further down runs after this block, which is the right order — drainer exits, then `process_end` is written.

- [ ] **Step 3: Run full build — expect PASS**

Run: `cd /home/dave/src/rusty-imap-mcp-audit-cancel && cargo build --workspace`
Expected: PASS. Task 4's `audit_envelope.rs` reference to `self.cancellation_sender` now resolves.

If the build fails because of other `ImapMcpServer::new` call sites with the old 2-argument signature (tests, maybe), update them to pass a fresh sender (use `rimap_audit::cancellation_channel().0`) or accept `CancelledToolEndSender` via a test helper. Search: `grep -rn "ImapMcpServer::new(" crates/ tests/`.

- [ ] **Step 4: Run tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-audit-cancel && cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 5: Commit (Tasks 4 + 5 together)**

```bash
git add crates/rimap-server/src/mcp/audit_envelope.rs \
        crates/rimap-server/src/mcp/server.rs \
        crates/rimap-server/src/main.rs
# plus any test files updated for the new ImapMcpServer::new signature
git commit -m "server: guard tool_start with AuditEnvelopeGuard (#71, #99)

run_with_audit_envelope now wraps body.await in a drop-guard. Normal
completion disarms the guard before emit_tool_end; a dropped future
synthesizes a tool_end { status: cancelled, error_code:
ERR_CANCELLED, duration_ms: elapsed } and enqueues it via the
CancelledToolEndSender channel added in rimap-audit. main.rs spawns
the drainer task and awaits its JoinHandle on shutdown so queued
records flush before the runtime exits."
```

---

## Task 6: Test — drop-induced cancellation emits a paired `tool_end`

**Issue:** #71, #99 — pins the drop-guard behavior.

**Files:**
- Create: `crates/rimap-server/tests/audit_cancellation.rs`

### Approach

Spawn `run_with_audit_envelope` with a body that is `std::future::pending` (never completes). Drop the outer future. Assert the audit log contains a `tool_end` with `status: "cancelled"` paired to the earlier `tool_start`.

This requires enough of the MCP server to construct `ImapMcpServer`. Look for existing integration-test helpers in `rimap-server/tests/` (probably `e2e.rs` or `dry_run.rs`). Reuse the helpers if possible; otherwise build a minimal fixture.

If `run_with_audit_envelope` is `pub(super)`, the test will need to go through a public tool-dispatch path. Call `call_tool` via `ServerHandler::call_tool` with a mock account. The challenge: the test needs to drop the outer future deterministically, which means wrapping the call in a `tokio::time::timeout` and relying on timeout-drops, or in a pinned future we poll manually.

Simpler pattern:

```rust
let fut = server.handle_call_tool(...);
let mut fut = Box::pin(fut);
// Poll once to get past emit_tool_start.
let waker = futures::task::noop_waker();
let mut cx = std::task::Context::from_waker(&waker);
let _ = fut.as_mut().poll(&mut cx);
// Now drop the future before body completes.
drop(fut);
// Give the drainer task a moment to process.
tokio::time::sleep(Duration::from_millis(100)).await;
```

That relies on `handle_call_tool` having an await point inside `emit_tool_start` (it does — `spawn_blocking`). After polling once, the future is suspended awaiting `spawn_blocking`, so `emit_tool_start` will complete on a background thread. Dropping the future here cancels the body future, which triggers `AuditEnvelopeGuard::drop`.

Actually — after poll once, `emit_tool_start` may not have finished yet because `spawn_blocking` is async from the caller's perspective. A more reliable test uses a dispatch body that completes in phases, or uses `tokio::select!` with a cancellation signal. Consider this approach:

```rust
let start_signal = Arc::new(tokio::sync::Notify::new());
let start_signal_clone = start_signal.clone();

let inner_fut = server.call_dispatch_with_body(..., async move {
    start_signal_clone.notify_one();
    std::future::pending::<Result<_, _>>().await;
    unreachable!()
});

let outer = tokio::spawn(inner_fut);
start_signal.notified().await;  // Body future has started, emit_tool_start is done.
outer.abort();  // Cancels the outer task → drops the future → fires guard.
// Await the drainer.
...
```

Implementation details depend on what the dispatch path exposes. The implementer should feel free to shape the test mechanism to fit the codebase.

- [ ] **Step 1: Write the integration test scaffolding**

Create `crates/rimap-server/tests/audit_cancellation.rs`:

```rust
//! Pins the cancellation drop-guard behavior: when an MCP dispatch future is
//! dropped between emit_tool_start and emit_tool_end, a synthetic tool_end
//! record with status = "cancelled" is written to the audit log.
//!
//! Issue: #71 (server-layer drop-guard), #99 (audit-envelope drop-guard).

// Scaffolding: concrete setup depends on which test helpers already exist
// in `crates/rimap-server/tests/`. Look for `e2e.rs`, `dry_run.rs`, or a
// `common.rs` module with reusable fixtures. Reuse what exists; extend only
// if a new helper is unavoidable.

#[tokio::test]
async fn dropped_dispatch_future_emits_cancellation_tool_end() {
    // 1. Build an ImapMcpServer with a temporary audit file.
    // 2. Construct a dispatch future that is guaranteed to block past
    //    emit_tool_start but never returns (`std::future::pending`).
    // 3. Drop the future.
    // 4. Drop the server to release the cancellation sender; await the drainer.
    // 5. Parse the audit file; assert the last record has
    //    status == "cancelled" and error_code == "ERR_CANCELLED".
    //
    // Full implementation below — follow existing patterns in e2e.rs for
    // ImapMcpServer construction.

    todo!("expand using existing rimap-server test helpers");
}
```

- [ ] **Step 2: Expand the test with a concrete implementation**

The implementer should:

1. Locate existing test helpers (e.g. `rimap-server/tests/e2e.rs` constructs `ImapMcpServer` — see how it wires the registry and audit writer).
2. Construct a minimal `ImapMcpServer` with: one account (use `AccountId::default_account()`), a `tempfile::NamedTempFile` for the audit path with `fail_open = false`, the new `cancellation_channel`, and the drainer.
3. Invoke a dispatch path that goes through `run_with_audit_envelope`. The simplest way is to pick a read-only tool like `list_folders` but with an IMAP connection that never responds. Mock the IMAP connection to block on `std::future::pending`.
4. Use `tokio::spawn` to run the dispatch, then `handle.abort()` to drop the future.
5. Drop the server, await the drainer handle, then read the audit file.
6. Use `rimap-audit::reader` (check `crates/rimap-audit/src/reader/`) to parse records, or just read lines and deserialize as `Payload`.
7. Assert the last record matches `ToolEnd { status: Cancelled, error_code: Some(ErrorCode::Cancelled), .. }` with `start_seq` matching the earlier `ToolStart.seq`.

Given the complexity of mocking IMAP, an alternative is to test `run_with_audit_envelope` directly by making it `pub(crate)` (or adding a thin `#[cfg(test)]` wrapper) and calling it with a synthetic body future. Adjust visibility only if strictly necessary.

- [ ] **Step 3: Run the test**

Run: `cd /home/dave/src/rusty-imap-mcp-audit-cancel && cargo test -p rimap-server --test audit_cancellation`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/audit_cancellation.rs
# plus any visibility / helper changes needed
git commit -m "test: pin cancellation tool_end on dropped dispatch future (#71, #99)

Spawns a dispatch with a pending body, drops the outer future after
emit_tool_start completes, and asserts the audit log contains a
matching tool_end with status = \"cancelled\" / error_code =
ERR_CANCELLED. Exercises the AuditEnvelopeGuard → channel → drainer
→ AuditWriter::log_tool_end path end-to-end."
```

---

## Task 7: Test — `fail_open = true` propagation on write failure (#72)

**Issue:** #72 — pin the existing `fail_open = true` suppression behavior.

**Files:**
- Modify: `crates/rimap-audit/src/writer/mod.rs` (add `#[cfg(test)]` failure-injection hook)
- Create: `crates/rimap-server/tests/audit_fail_open.rs`

### Approach

Add a test-only failure-injection hook on `AuditWriter` that forces the next `write_record_inner` to return `AuditError::Write`. This lets the fail_open path exercise without filesystem tricks (chmod, deleted files) that are platform-sensitive.

- [ ] **Step 1: Add the failure-injection hook**

In `crates/rimap-audit/src/writer/mod.rs`, near the `AuditWriter` definition:

```rust
#[cfg(test)]
#[derive(Debug, Default)]
struct FailureInjection {
    /// When `true`, the next `write_record_inner` call returns
    /// `AuditError::Write` without touching the file.
    fail_next: std::sync::atomic::AtomicBool,
}

pub struct AuditWriter {
    // ... existing fields ...
    #[cfg(test)]
    failure_injection: Arc<FailureInjection>,
}
```

Initialize `failure_injection: Arc::new(FailureInjection::default())` in `AuditWriter::new`.

Add a test-only method:

```rust
impl AuditWriter {
    /// Test-only: cause the next `write_record_inner` call to fail.
    /// Used by #72's test to exercise the `fail_open = true` suppression
    /// path without filesystem tricks.
    #[cfg(test)]
    pub(crate) fn force_next_write_failure(&self) {
        self.failure_injection
            .fail_next
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
```

Modify the top of `write_record_inner` (around line 285):

```rust
fn write_record_inner(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
    #[cfg(test)]
    if self
        .failure_injection
        .fail_next
        .swap(false, std::sync::atomic::Ordering::Relaxed)
    {
        return Err(AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("injected failure (test)"),
        });
    }

    // existing body
    ...
}
```

Verify `AuditError::Write`'s structure (check `crates/rimap-audit/src/error.rs` or the module that defines it). Adjust the error construction to match the actual variant.

- [ ] **Step 2: Write the failing integration test**

Create `crates/rimap-server/tests/audit_fail_open.rs`:

```rust
//! Pin the fail_open = true propagation path: when an audit write fails and
//! the writer was configured with fail_open = true, the tool call succeeds
//! (no ERR_INTERNAL to the caller) and the writer's suppressed_failures
//! counter increments.
//!
//! Issue: #72.

// Scaffolding. Follow the same pattern as audit_cancellation.rs for server
// construction, but:
// 1. Create the AuditWriter with fail_open = true.
// 2. Call force_next_write_failure() before invoking the dispatch.
// 3. Run a successful tool call (the body completes normally).
// 4. Assert the tool result is Ok (not ERR_INTERNAL).
// 5. Assert `audit.suppressed_failures() == 1`.

#[tokio::test]
async fn fail_open_suppresses_write_failure_and_increments_counter() {
    // ... full implementation here ...
}
```

The implementer expands this to a concrete test. Visibility: `force_next_write_failure` is `pub(crate)` in `rimap-audit`, so cross-crate tests in `rimap-server/tests/` cannot call it directly. Options:

- (a) Make it `#[cfg(test)] pub` — but `#[cfg(test)]` only applies within the defining crate, not dependent crates. Use `#[cfg(any(test, feature = "test-injection"))]` with a non-default feature, and enable the feature in `rimap-server`'s `[dev-dependencies]` entry for `rimap-audit`.
- (b) Put the test entirely inside `rimap-audit`'s own `tests/` directory, exercising the writer in isolation without going through `rimap-server`.

Option (a) keeps the test at the integration boundary (where #72 is about end-to-end fail_open behavior). Option (b) is simpler but verifies less.

Recommend (a). In `crates/rimap-audit/Cargo.toml`:

```toml
[features]
test-injection = []
```

Then gate the hook:

```rust
#[cfg(any(test, feature = "test-injection"))]
```

And in `crates/rimap-server/Cargo.toml`:

```toml
[dev-dependencies]
rimap-audit = { path = "../rimap-audit", features = ["test-injection"] }
```

- [ ] **Step 3: Run the test — expect PASS**

Run: `cd /home/dave/src/rusty-imap-mcp-audit-cancel && cargo test -p rimap-server --test audit_fail_open`
Expected: PASS. Tool result is Ok, `suppressed_failures == 1`.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/writer/mod.rs crates/rimap-audit/Cargo.toml \
        crates/rimap-server/tests/audit_fail_open.rs \
        crates/rimap-server/Cargo.toml
git commit -m "test: pin fail_open=true write-failure suppression (#72)

Adds a test-injection hook on AuditWriter (gated by the
test-injection feature of rimap-audit) that forces the next
write_record_inner to fail. The new integration test constructs a
writer with fail_open = true, injects a failure, runs a tool
dispatch, and asserts that (1) the tool call returns Ok (not
ERR_INTERNAL) and (2) suppressed_failures increments by 1."
```

---

## Task 8: Final verification + PR

- [ ] **Step 1: Run the full verification pipeline**

```bash
cd /home/dave/src/rusty-imap-mcp-audit-cancel
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check advisories bans licenses sources
typos
```

All five must pass.

- [ ] **Step 2: Open the PR**

Branch: `feat/audit-cancellation-guard`. Target: `main`. PR body references `Closes #71`, `Closes #72`, `Closes #99`.

- [ ] **Step 3: After merge, update the roadmap spec**

Mark sub-group 3 as closed in `docs/superpowers/specs/2026-04-19-open-issues-roadmap-design.md` (or leave to a roadmap-refresh sweep).
