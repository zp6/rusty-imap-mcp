# EPVME Dataset Testing

This document describes how to run the external EPVME malicious-email corpus
against `rimap-content` and records the first full-run results captured on
April 8, 2026.

## Purpose

The repo already contains a curated adversarial fixture corpus under
`tests/injection-corpus/`. That corpus is the source of truth for exact
security assertions.

The EPVME runner is complementary:

- it bulk-runs a large external corpus of malicious `.eml` samples
- it fails on parser regressions, panics, read errors, and hard parse errors
- it does **not** require every malicious sample to emit a specific warning

This keeps the curated corpus precise while adding broad real-world regression
coverage.

## Entry Points

Run the existing curated corpus:

```bash
just test-injection
```

Run the EPVME bulk runner:

```bash
just test-epvme --dataset-dir /path/to/extracted-epvme
```

Or let the wrapper use/download zip archives and extract them into a cache dir:

```bash
just test-epvme --download --cache-dir /path/to/EPVME-Dataset
```

The wrapper accepts either layout:

- zip files directly under `--cache-dir`
- zip files under `--cache-dir/zips`

Optional controls:

```bash
just test-epvme --download --cache-dir /path/to/EPVME-Dataset --limit 100
just test-epvme --download --cache-dir /path/to/EPVME-Dataset --json-out /tmp/epvme-report.json
```

Direct binary invocation:

```bash
cargo run -p rimap-content --locked --bin epvme_runner -- /path/to/extracted-epvme --json-out /tmp/epvme-report.json
```

## Exit Behavior

- exit `0`: every processed sample parsed successfully
- exit `1`: at least one read error, parse error, or panic occurred
- exit `2`: invocation or environment error in the shell wrapper

The runner prints:

- discovered file count
- processed file count
- successful parse count
- parse error counts by `ContentError` kind
- warning counts by `WarningCode`
- up to 50 recorded failing sample paths

## Recorded Results

Run date: **April 8, 2026**

Command:

```bash
./scripts/test-epvme.sh \
  --download \
  --cache-dir /Users/dave/src/EPVME-Dataset \
  --json-out /Users/dave/src/EPVME-Dataset/epvme-report.json
```

Dataset outcome:

- discovered `.eml` files: `49,136`
- processed files: `49,136`
- parsed successfully: `49,135`
- parse errors: `1`
- read failures: `0`
- panics: `0`

Warning counts:

- `html_body_unsanitized`: `21,039`
- `unicode_c0_c1_stripped`: `1,564`
- `parse_mime_type_mismatch`: `261`
- `parse_attachment_filename_rewritten`: `83`
- `parse_header_smuggling_blocked`: `3`
- `unicode_zero_width_stripped`: `4`

Observed hard failure:

- sample:
  `/Users/dave/src/EPVME-Dataset/extracted/3/36bf3f9ec993096c6584c6b841571c65.eml`
- error: `content limit exceeded: header_count (limit=256)`

Follow-up inspection showed that sample contained `389` headers, including
`369` repeated `X-FOPE-CONNECTOR` headers. That indicates the failure was a
deliberate hard-limit rejection, not a parser panic or general parsing defect.

## Interpretation

Current assessment from the April 8, 2026 run:

- the bulk-runner path is working correctly
- `rimap-content` remained stable across the corpus
- the only failing sample exceeded the current `MAX_HEADER_COUNT` policy

That makes the result acceptable for the current security posture. Any future
decision to raise `MAX_HEADER_COUNT` should be treated as a product and threat
model change, not as a required bug fix from this run.
