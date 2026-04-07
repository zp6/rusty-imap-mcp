//! Audit record skeleton.
//!
//! This module defines the *shape* of the audit log — the variants that every
//! sprint produces — but carries no serialization, no writer, and no I/O.
//! Sprint 2 fills in the variant payloads and adds a file-backed writer in
//! `rimap-audit`; Sprint 5 wires tool dispatch into the writer.
//!
//! Keeping the enum in `rimap-core` guarantees that `rimap-authz` can reference
//! audit variant *names* (e.g. for tracing spans) without taking a dependency
//! on the audit crate.

/// Per-process startup and shutdown events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessEvent {
    /// Process started; first audit entry in a new or rotated file.
    Start,
    /// Process exiting cleanly.
    End,
}

/// Authentication outcome reported by the IMAP session wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Credential was resolved and server accepted it.
    Success,
    /// Credential was resolved but server rejected it.
    Failure,
}

/// Top-level audit record. Variants are placeholder shells — Sprint 2 adds
/// the field payloads (sequence number, timestamps, redacted args, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    /// Process lifecycle event.
    Process(ProcessEvent),
    /// Authentication attempt result.
    Auth(AuthOutcome),
    /// A tool call has entered the dispatch chain.
    ToolStart,
    /// A tool call has exited the dispatch chain.
    ToolEnd,
}

#[cfg(test)]
mod tests {
    use crate::audit::{AuditRecord, AuthOutcome, ProcessEvent};

    #[test]
    fn variants_are_constructible() {
        let _ = AuditRecord::Process(ProcessEvent::Start);
        let _ = AuditRecord::Process(ProcessEvent::End);
        let _ = AuditRecord::Auth(AuthOutcome::Success);
        let _ = AuditRecord::Auth(AuthOutcome::Failure);
        let _ = AuditRecord::ToolStart;
        let _ = AuditRecord::ToolEnd;
    }

    #[test]
    fn process_event_equality() {
        assert_eq!(ProcessEvent::Start, ProcessEvent::Start);
        assert_ne!(ProcessEvent::Start, ProcessEvent::End);
    }
}
