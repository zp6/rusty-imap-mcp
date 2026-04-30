//! Asserts that a tool failure inside `run_with_audit_envelope`'s body
//! still emits a paired `tool_start` + `tool_end(status=error,
//! error_code=Some(_))`. Drives `fetch_message` against a non-existent
//! folder so EXAMINE returns NO and the handler maps it to
//! `ErrorCode::ImapProtocol` after `tool_start` has fired.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use serde_json::Value;

use common::dovecot_daemon_harness::DovecotDaemon;
use common::shim_jsonrpc::{
    READ_TIMEOUT, make_runtime_dir, recv_frame, resolved_socket_path, send_frame,
    spawn_shim_and_initialize,
};

#[tokio::test]
async fn tool_failure_inside_envelope_emits_paired_start_end_error() {
    let runtime_dir = make_runtime_dir();
    let socket_path = resolved_socket_path(runtime_dir.path());

    let Some(daemon) = DovecotDaemon::try_spawn_at(64, socket_path).await else {
        return;
    };

    let (mut shim, mut stdin, mut reader) =
        spawn_shim_and_initialize(runtime_dir.path(), "rimap-tool-failure-audit-test").await;

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "fetch_message",
            "arguments": {
                "folder": "DefinitelyNotAFolder-rimap174",
                "uid": 1
            }
        }
    });
    send_frame(&mut stdin, &call, "tools/call").await;
    // Drain so the shim settles before EOF; the audit log is the contract.
    let _ = recv_frame(&mut reader, "tools/call").await;

    drop(stdin);
    let _ = tokio::time::timeout(READ_TIMEOUT, shim.wait()).await;

    let result = daemon.shutdown().await;

    let mut start: Option<Value> = None;
    let mut end: Option<Value> = None;
    let mut start_count = 0usize;
    let mut end_count = 0usize;
    for line in result.log.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v["tool"] != "fetch_message" {
            continue;
        }
        match v["kind"].as_str() {
            Some("tool_start") => {
                start_count += 1;
                start.get_or_insert(v);
            }
            Some("tool_end") => {
                end_count += 1;
                end.get_or_insert(v);
            }
            _ => {}
        }
    }

    assert_eq!(
        start_count, 1,
        "expected exactly one tool_start for fetch_message; got {start_count}\nlog:\n{}",
        result.log,
    );
    assert_eq!(
        end_count, 1,
        "expected exactly one tool_end for fetch_message; got {end_count}\nlog:\n{}",
        result.log,
    );

    let start = start.expect("tool_start present");
    let end = end.expect("tool_end present");
    assert_eq!(
        end["start_seq"], start["seq"],
        "tool_end.start_seq must reference the paired tool_start.seq;\nstart={start}\nend={end}",
    );
    assert_eq!(
        end["status"], "error",
        "tool_end must record status=error for an in-envelope failure; got {end}",
    );
    assert!(
        end["error_code"].is_string(),
        "tool_end must carry a non-null error_code string; got {end}",
    );
}
