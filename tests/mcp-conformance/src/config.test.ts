import { describe, expect, it } from "vitest";
import { buildConfigToml } from "./config.js";

describe("buildConfigToml", () => {
  it("produces TOML with accounts=[] and audit paths inside the given tempdir", () => {
    const tempdir = "/tmp/rusty-imap-mcp-test-12345";
    const toml = buildConfigToml(tempdir);

    expect(toml).toMatch(/^accounts\s*=\s*\[\s*\]$/m);
    expect(toml).toContain(`path = "${tempdir}/audit.jsonl"`);
    expect(toml).toContain(`allowed_base_dir = "${tempdir}"`);
    expect(toml).toContain("[audit]");
  });

  it("escapes a tempdir path containing a backslash safely", () => {
    // Defensive: Node's os.tmpdir() on macOS/Linux never returns backslashes,
    // but the helper should not produce malformed TOML if it ever did.
    const tempdir = "/tmp/with\\backslash";
    const toml = buildConfigToml(tempdir);
    expect(toml).not.toContain("\\backslash"); // raw backslash would be invalid in basic TOML strings
  });
});
