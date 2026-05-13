import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    hookTimeout: 15_000,
    testTimeout: 15_000,
    pool: "threads",
    isolate: true,
    reporters: ["default"],
  },
});
