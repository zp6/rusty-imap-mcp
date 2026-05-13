import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { mkdtemp, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface, type Interface } from "node:readline";

import { buildConfigToml } from "./config.js";

const REQUEST_TIMEOUT_MS = 2_000;
const SHUTDOWN_TIMEOUT_MS = 5_000;

export interface JsonRpcSuccess {
  jsonrpc: "2.0";
  id: number;
  result: Record<string, unknown>;
  error?: undefined;
}

export interface JsonRpcError {
  jsonrpc: "2.0";
  id: number;
  result?: undefined;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcError;

/**
 * Validates a parsed JSON-RPC envelope received over stdio.
 * Mirrors Phase 1's `assert_envelope_valid` (Rust:
 * `crates/rimap-server/tests/mcp_wire_conformance.rs`). Phase 2's
 * regression net for negative-path wire tests depends on this:
 * without it, `request()` could happily return a malformed payload
 * and the only thing the unknown-method test would catch is `code`
 * and `message`, missing structural drift (missing `jsonrpc`,
 * simultaneous `result`+`error`, non-numeric `error.code`, etc).
 *
 * Throws a descriptive `Error` on any structural violation.
 */
export function assertEnvelopeValid(
  response: JsonRpcResponse,
  expectedId: number,
): void {
  const env = response as unknown as Record<string, unknown>;

  if (env["jsonrpc"] !== "2.0") {
    throw new Error(
      `envelope must declare jsonrpc="2.0"; got ${JSON.stringify(env["jsonrpc"])}`,
    );
  }

  if (env["id"] !== expectedId) {
    throw new Error(
      `response id ${JSON.stringify(env["id"])} did not match request id ${expectedId}`,
    );
  }

  const hasResult = Object.prototype.hasOwnProperty.call(env, "result");
  const hasError = Object.prototype.hasOwnProperty.call(env, "error");

  if (hasResult === hasError) {
    throw new Error(
      `envelope must contain exactly one of \`result\` or \`error\`; got result=${hasResult} error=${hasError}`,
    );
  }

  if (hasResult) {
    const result = env["result"];
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
      throw new Error(
        `envelope.result must be an object; got ${JSON.stringify(result)}`,
      );
    }
  } else {
    const error = env["error"];
    if (error === null || typeof error !== "object" || Array.isArray(error)) {
      throw new Error(
        `envelope.error must be an object; got ${JSON.stringify(error)}`,
      );
    }
    const errObj = error as Record<string, unknown>;
    if (typeof errObj["code"] !== "number") {
      throw new Error(
        `envelope.error.code must be a number; got ${JSON.stringify(errObj["code"])}`,
      );
    }
    if (typeof errObj["message"] !== "string") {
      throw new Error(
        `envelope.error.message must be a string; got ${JSON.stringify(errObj["message"])}`,
      );
    }
  }
}

export interface RawHandles {
  request(method: string, params: unknown): Promise<JsonRpcResponse>;
  notify(method: string, params: unknown): Promise<void>;
  assertNoResponseWithin(ms: number): Promise<void>;
  shutdownAndWait(): Promise<number>;
  close(): Promise<void>;
  readonly tempdir: string;
}

class HarnessTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`timeout waiting for stdout line after ${timeoutMs} ms`);
    this.name = "HarnessTimeoutError";
  }
}

async function resolveBinaryPath(): Promise<string> {
  const envPath = process.env["RUSTY_IMAP_MCP_BIN"];
  if (envPath !== undefined && envPath !== "") {
    await access(envPath);
    return envPath;
  }
  // tests/mcp-conformance/src/raw-harness.ts → ../../../target/debug/rusty-imap-mcp
  const here = dirname(fileURLToPath(import.meta.url));
  const fallback = resolve(here, "..", "..", "..", "target", "debug", "rusty-imap-mcp");
  await access(fallback);
  return fallback;
}

export async function spawnRaw(): Promise<RawHandles> {
  const binPath = await resolveBinaryPath();
  const tempdir = await mkdtemp(join(tmpdir(), "rusty-imap-mcp-raw-"));
  const configPath = join(tempdir, "config.toml");
  await writeFile(configPath, buildConfigToml(tempdir), "utf8");

  const child: ChildProcessWithoutNullStreams = spawn(
    binPath,
    ["--config", configPath, "--allow-empty-accounts"],
    { stdio: ["pipe", "pipe", "ignore"] },
  ) as unknown as ChildProcessWithoutNullStreams;

  try {
    const reader: Interface = createInterface({ input: child.stdout, crlfDelay: Infinity });

    const lineQueue: string[] = [];
    const waiters: ((line: string | null) => void)[] = [];
    let stdoutClosed = false;

    reader.on("line", (line) => {
      const waiter = waiters.shift();
      if (waiter) {
        waiter(line);
      } else {
        lineQueue.push(line);
      }
    });
    reader.on("close", () => {
      stdoutClosed = true;
      while (waiters.length > 0) {
        const waiter = waiters.shift();
        if (waiter) {
          waiter(null);
        }
      }
    });

    function nextLine(timeoutMs: number): Promise<string | null> {
      const queued = lineQueue.shift();
      if (queued !== undefined) {
        return Promise.resolve(queued);
      }
      if (stdoutClosed) {
        return Promise.resolve(null);
      }
      return new Promise<string | null>((resolveLine, rejectLine) => {
        const timer = setTimeout(() => {
          const idx = waiters.indexOf(onLine);
          if (idx >= 0) {
            waiters.splice(idx, 1);
          }
          rejectLine(new HarnessTimeoutError(timeoutMs));
        }, timeoutMs);
        const onLine = (line: string | null): void => {
          clearTimeout(timer);
          resolveLine(line);
        };
        waiters.push(onLine);
      });
    }

    let nextId = 0;

    async function write(line: string): Promise<void> {
      await new Promise<void>((resolveWrite, rejectWrite) => {
        child.stdin.write(line, (err) => {
          if (err) {
            rejectWrite(err);
          } else {
            resolveWrite();
          }
        });
      });
    }

    async function request(method: string, params: unknown): Promise<JsonRpcResponse> {
      nextId += 1;
      const id = nextId;
      const envelope = { jsonrpc: "2.0", id, method, params };
      await write(`${JSON.stringify(envelope)}\n`);
      const line = await nextLine(REQUEST_TIMEOUT_MS);
      if (line === null) {
        throw new Error(`stdout closed before responding to ${method}`);
      }
      const parsed = JSON.parse(line) as JsonRpcResponse;
      // Full envelope validation — matches Phase 1's `assert_envelope_valid`.
      // Without this, negative-path tests (unknown method, unknown tool)
      // could pass against a malformed error envelope.
      assertEnvelopeValid(parsed, id);
      return parsed;
    }

    async function notify(method: string, params: unknown): Promise<void> {
      const envelope = { jsonrpc: "2.0", method, params };
      await write(`${JSON.stringify(envelope)}\n`);
    }

    async function assertNoResponseWithin(ms: number): Promise<void> {
      try {
        const line = await nextLine(ms);
        if (line === null) {
          throw new Error("stdout closed unexpectedly");
        }
        throw new Error(`expected no response within ${ms} ms, got: ${line}`);
      } catch (err) {
        if (err instanceof HarnessTimeoutError) {
          return; // expected: no response, as desired
        }
        throw err;
      }
    }

    async function shutdownAndWait(): Promise<number> {
      child.stdin.end();
      return await new Promise<number>((resolveExit, rejectExit) => {
        const timer = setTimeout(() => {
          rejectExit(new Error(`process did not exit within ${SHUTDOWN_TIMEOUT_MS} ms`));
        }, SHUTDOWN_TIMEOUT_MS);
        child.once("exit", (code) => {
          clearTimeout(timer);
          if (code === null) {
            rejectExit(new Error("process exited via signal"));
          } else {
            resolveExit(code);
          }
        });
      });
    }

    async function close(): Promise<void> {
      if (!child.killed && child.exitCode === null) {
        child.kill("SIGKILL");
      }
      await rm(tempdir, { recursive: true, force: true });
    }

    return { request, notify, assertNoResponseWithin, shutdownAndWait, close, tempdir };
  } catch (err) {
    if (!child.killed && child.exitCode === null) {
      child.kill("SIGKILL");
    }
    await rm(tempdir, { recursive: true, force: true });
    throw err;
  }
}
