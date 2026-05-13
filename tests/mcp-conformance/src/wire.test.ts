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
});

// PINNED_PROTOCOL_VERSION is consumed by Task 9's raw-harness block,
// which appends to this same file. Keep it as a module-scoped const.
