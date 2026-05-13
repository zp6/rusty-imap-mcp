## Lint/format tooling

- oxlint 1.64.0 — works on TS (probe: `node_modules/.bin/oxlint /tmp/probe.ts` → exit 0, "Found 0 warnings and 0 errors.")
- oxfmt 0.49.0 — works on TS (probe: `node_modules/.bin/oxfmt --check /tmp/probe.ts` → exit 1 due to formatting diff vs defaults; `oxfmt /tmp/probe.ts` reformatted the file successfully)
- Outcome: kept both. `lint` chains `tsc --noEmit && oxlint src/`; `format:check` runs `oxfmt --check src/`.
