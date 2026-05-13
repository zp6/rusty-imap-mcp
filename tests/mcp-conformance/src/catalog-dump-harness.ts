import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

async function resolveBinaryPath(): Promise<string> {
  const envPath = process.env["RUSTY_IMAP_MCP_BIN"];
  if (envPath !== undefined && envPath !== "") {
    await access(envPath);
    return envPath;
  }
  const here = dirname(fileURLToPath(import.meta.url));
  const fallback = resolve(here, "..", "..", "..", "target", "debug", "rusty-imap-mcp");
  await access(fallback);
  return fallback;
}

/**
 * Invokes `rusty-imap-mcp dump-tool-catalog` and returns the parsed
 * line-delimited JSON tool definitions.
 *
 * The binary must have been built with `--features test-support`;
 * a non-test-support build does not have the subcommand and clap
 * exits non-zero before producing output.
 */
export async function dumpToolCatalog(): Promise<unknown[]> {
  const binPath = await resolveBinaryPath();
  return await new Promise<unknown[]>((resolveResult, rejectResult) => {
    const child = spawn(binPath, ["dump-tool-catalog"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errChunks.push(chunk));
    child.on("error", (err) => rejectResult(err));
    child.on("exit", (code) => {
      if (code !== 0) {
        rejectResult(
          new Error(
            `dump-tool-catalog exited ${code}; stderr: ${Buffer.concat(errChunks).toString("utf8")}`,
          ),
        );
        return;
      }
      try {
        const stdout = Buffer.concat(chunks).toString("utf8");
        const lines = stdout.split("\n").filter((l) => l.length > 0);
        const parsed = lines.map((l) => JSON.parse(l) as unknown);
        resolveResult(parsed);
      } catch (err) {
        rejectResult(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}
