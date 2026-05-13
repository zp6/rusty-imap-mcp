import { afterEach, describe, expect, it } from "vitest";

import { spawnSdk, type SdkHandles } from "./sdk-harness.js";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
// Consumed by T9 — see plan task 9
const PINNED_PROTOCOL_VERSION = "2025-11-25";

describe("wire conformance (SDK harness)", () => {
  let harness: SdkHandles | undefined;

  afterEach(async () => {
    if (harness) {
      try {
        await harness.close();
      } finally {
        harness = undefined;
      }
    }
  });

  it("wire_smoke_initialize_returns_valid_envelope (SDK)", async () => {
    // Phase 1 parity: a successful connect() validates InitializeResult
    // through the SDK's Zod schema. If serverInfo or capabilities
    // were malformed, Zod would throw inside connect().
    harness = await spawnSdk();
    const info = harness.client.getServerVersion();
    expect(info?.name).toBeDefined();
    expect(info?.version).toBeDefined();
  });

  it("wire_initialize_advertises_tools_capability (SDK) — regression net for #261", async () => {
    harness = await spawnSdk();
    const caps = harness.client.getServerCapabilities();
    expect(caps, "capabilities must be present after initialize").toBeDefined();
    expect(
      caps?.tools,
      "capabilities.tools must be advertised — regression net for #261",
    ).toBeDefined();
  });

  it("wire_tools_list_returns_object_schemas (SDK) — regression net for fix/tool-input-schema-object-type", async () => {
    harness = await spawnSdk();
    const result = await harness.client.listTools();

    // Zod will have thrown inside listTools() if any tool's
    // inputSchema fails the SDK's Tool definition. Explicit asserts
    // below are belt-and-suspenders for if Zod ever relaxes.
    expect(result.tools.length, "tools/list must return at least the infrastructure tools").toBeGreaterThan(0);

    const names = result.tools.map((t) => t.name);
    expect(names, "list_accounts must be advertised").toContain("list_accounts");
    expect(names, "use_account must be advertised").toContain("use_account");

    for (const tool of result.tools) {
      const schema = tool.inputSchema as Record<string, unknown> | undefined;
      expect(schema, `tool ${tool.name}: inputSchema must be an object`).toBeDefined();
      expect(
        schema?.["type"],
        `tool ${tool.name}: inputSchema.type must be "object" (regression net)`,
      ).toBe("object");
    }
  });

  it("wire_resources_list_is_empty_for_no_accounts (SDK)", async () => {
    harness = await spawnSdk();
    const result = await harness.client.listResources();
    expect(result.resources, "zero accounts must produce zero resources").toHaveLength(0);
  });

  it("wire_tools_call_unknown_tool_returns_error_envelope (SDK)", async () => {
    harness = await spawnSdk();
    try {
      await harness.client.callTool({
        name: "this_tool_does_not_exist",
        arguments: {},
      });
      throw new Error("expected callTool to throw");
    } catch (err) {
      // rmcp 1.5 maps unknown tool names to INVALID_PARAMS (-32602)
      // with message "tool not found"; see Phase 1's
      // wire_tools_call_unknown_tool_returns_error_envelope test.
      // The SDK throws an McpError whose .code field is the JSON-RPC
      // error code.
      const error = err as { code?: number; message?: string };
      expect(error.code, "expected JSON-RPC error code -32602").toBe(-32602);
      expect(typeof error.message, "error.message must be a string").toBe("string");
    }
  });
});

// PINNED_PROTOCOL_VERSION is consumed by Task 9's raw-harness block,
// which appends to this same file. Keep it as a module-scoped const.
