#!/usr/bin/env bash
# Speak MCP directly to rusty-imap-mcp's stdio transport and report what
# `tools/list` returns. Use when an MCP client (Claude Desktop, Claude Code,
# IBM Bob, etc.) reports "no tools exposed" — this isolates whether the gap is
# server-side (server returns 0 tools) or client-side (server returns tools,
# client doesn't display them).
#
# Usage: scripts/mcp-probe-tools.sh [path/to/config.toml]
#
# With no argument the script uses /tmp/rimap-probe.toml — and auto-generates
# it from your main config (RUSTY_IMAP_MCP_CONFIG or the platform default) if
# it doesn't exist. The probe config gets a different [audit].path so it
# doesn't fight a running MCP client's audit lock.
set -euo pipefail

CONFIG="${1:-}"
BIN="$(command -v rusty-imap-mcp || true)"

if [ -z "$BIN" ]; then
    echo "rusty-imap-mcp not on PATH" >&2
    echo "install with: cargo install --path crates/rimap-server --locked" >&2
    exit 1
fi

if ! command -v jq >/dev/null; then
    echo "jq is required" >&2
    exit 1
fi

# Resolve probe config. Priority:
#   1. Explicit argument
#   2. Existing /tmp/rimap-probe.toml
#   3. Auto-generate /tmp/rimap-probe.toml from the main config
if [ -z "$CONFIG" ] && [ -f "/tmp/rimap-probe.toml" ]; then
    CONFIG="/tmp/rimap-probe.toml"
fi
if [ -z "$CONFIG" ]; then
    # Locate the main config to derive from.
    MAIN_CONFIG="${RUSTY_IMAP_MCP_CONFIG:-}"
    if [ -z "$MAIN_CONFIG" ]; then
        for candidate in \
            "$HOME/Library/Application Support/rusty-imap-mcp/config.toml" \
            "$HOME/.config/rusty-imap-mcp/config.toml"; do
            if [ -f "$candidate" ]; then
                MAIN_CONFIG="$candidate"
                break
            fi
        done
    fi
    if [ -z "$MAIN_CONFIG" ] || [ ! -f "$MAIN_CONFIG" ]; then
        echo "no main config found (set RUSTY_IMAP_MCP_CONFIG or place a config" >&2
        echo "at the platform default), and no probe config path was provided." >&2
        exit 1
    fi

    # Extract the main audit.path so the probe audit can live next to it
    # (under the same allowed_base_dir) with a distinct filename.
    MAIN_AUDIT="$(awk '
		BEGIN { in_audit = 0 }
		/^\[audit\]/ { in_audit = 1; next }
		/^\[/ && in_audit { exit }
		in_audit && /^[[:space:]]*path[[:space:]]*=/ {
			match($0, /"[^"]*"/)
			if (RSTART > 0) {
				print substr($0, RSTART + 1, RLENGTH - 2)
				exit
			}
		}
	' "$MAIN_CONFIG")"
    if [ -z "$MAIN_AUDIT" ]; then
        echo "could not extract [audit].path from $MAIN_CONFIG" >&2
        exit 1
    fi
    PROBE_AUDIT="$(dirname "$MAIN_AUDIT")/audit-probe.jsonl"
    CONFIG="/tmp/rimap-probe.toml"

    awk -v new_path="$PROBE_AUDIT" '
		BEGIN { in_audit = 0 }
		/^\[audit\]/ { in_audit = 1; print; next }
		/^\[/ && in_audit { in_audit = 0 }
		in_audit && /^[[:space:]]*path[[:space:]]*=/ {
			print "path = \"" new_path "\""
			next
		}
		{ print }
	' "$MAIN_CONFIG" >"$CONFIG"

    echo "generated probe config: $CONFIG"
    echo "  - source:      $MAIN_CONFIG"
    echo "  - audit.path:  $PROBE_AUDIT"
    echo
fi

if [ ! -f "$CONFIG" ]; then
    echo "config not found: $CONFIG" >&2
    exit 1
fi

WORKDIR="$(mktemp -d -t rimap-probe.XXXXXX)"
ENVELOPE="$WORKDIR/probe.jsonl"
STDOUT_LOG="$WORKDIR/stdout.log"
STDERR_LOG="$WORKDIR/stderr.log"

# Build the JSON-RPC envelopes via jq -nc. Each call emits one compact line, so
# there's no risk of terminal width wrapping a JSON object across two lines.
{
    jq -nc '{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"probe",version:"1.0"}}}'
    jq -nc '{jsonrpc:"2.0",method:"notifications/initialized"}'
    jq -nc '{jsonrpc:"2.0",id:2,method:"tools/list",params:{}}'
} >"$ENVELOPE"

printf 'config:   %s\n' "$CONFIG"
printf 'binary:   %s\n' "$BIN"
printf 'workdir:  %s\n' "$WORKDIR"
echo

set +e
RUSTY_IMAP_MCP_CONFIG="$CONFIG" "$BIN" <"$ENVELOPE" >"$STDOUT_LOG" 2>"$STDERR_LOG"
EXIT_CODE=$?
set -e

echo "=== stdout (JSON-RPC responses) ==="
if [ -s "$STDOUT_LOG" ]; then
    jq -c '.' <"$STDOUT_LOG" 2>/dev/null || cat "$STDOUT_LOG"
else
    echo "(empty — server wrote nothing to stdout before exiting)"
fi
echo

echo "=== tools/list summary ==="
TOOL_COUNT="$(jq -s '[.[] | select(.id == 2) | .result.tools] | first | length // 0' "$STDOUT_LOG" 2>/dev/null || echo "?")"
echo "tool count: $TOOL_COUNT"
if [ "$TOOL_COUNT" != "0" ] && [ "$TOOL_COUNT" != "?" ]; then
    echo "tool names:"
    jq -r -s '.[] | select(.id == 2) | .result.tools[].name' "$STDOUT_LOG" 2>/dev/null | sed 's/^/  /'
fi
echo

echo "=== stderr (server logs) ==="
if [ -s "$STDERR_LOG" ]; then
    cat "$STDERR_LOG"
else
    echo "(empty)"
fi

if [ "$EXIT_CODE" -ne 0 ]; then
    echo
    echo "server exited with code $EXIT_CODE"
fi
