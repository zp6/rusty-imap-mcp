import { afterEach, describe, expect, it } from "vitest";
import { spawnSdk, type SdkHandles } from "./sdk-harness.js";

describe("sdk-harness", () => {
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

  it("connects and reports the server's negotiated capabilities", async () => {
    harness = await spawnSdk();
    const caps = harness.client.getServerCapabilities();
    expect(caps).toBeDefined();
    expect(caps?.tools).toBeDefined();
  });
});
