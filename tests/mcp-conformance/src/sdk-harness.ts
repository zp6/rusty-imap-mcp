import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { mkdtemp, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildConfigToml } from "./config.js";

export interface SdkHandles {
  readonly client: Client;
  readonly transport: StdioClientTransport;
  readonly tempdir: string;
  close(): Promise<void>;
}

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

export async function spawnSdk(): Promise<SdkHandles> {
  const binPath = await resolveBinaryPath();
  const tempdir = await mkdtemp(join(tmpdir(), "rusty-imap-mcp-sdk-"));
  try {
    const configPath = join(tempdir, "config.toml");
    await writeFile(configPath, buildConfigToml(tempdir), "utf8");

    const transport = new StdioClientTransport({
      command: binPath,
      args: ["--config", configPath, "--allow-empty-accounts"],
      stderr: "ignore",
    });

    const client = new Client(
      { name: "rusty-imap-mcp-conformance-harness-node", version: "0.1.0" },
      { capabilities: {} },
    );

    try {
      await client.connect(transport);
    } catch (err) {
      // connect() failed; ensure the spawned child is reaped by closing
      // the transport (which kills the process) before we rethrow.
      await transport.close().catch(() => undefined);
      throw err;
    }

    return {
      client,
      transport,
      tempdir,
      close: async (): Promise<void> => {
        await client.close();
        await rm(tempdir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    await rm(tempdir, { recursive: true, force: true });
    throw err;
  }
}
