/**
 * Builds the inline `config.toml` content for a zero-account
 * conformance test. The structure mirrors Phase 1's Rust harness
 * (`crates/rimap-server/tests/mcp_wire_conformance.rs`, ~line 75):
 * zero accounts plus an `[audit]` section pointing at the given
 * tempdir.
 *
 * @param tempdir Absolute path to an existing directory the server
 *   may write to. Must not contain characters that would break a
 *   basic TOML quoted string; the helper escapes backslashes.
 * @returns The TOML config as a UTF-8 string.
 */
export function buildConfigToml(tempdir: string): string {
  const escaped = tempdir.replaceAll("\\", "/");
  return [
    "accounts = []",
    "",
    "[audit]",
    `path = "${escaped}/audit.jsonl"`,
    `allowed_base_dir = "${escaped}"`,
    "",
  ].join("\n");
}
