---
name: download-js-map-files
description: Use when working in the download-js-map-files repository, especially the Python CLI, raw HTTP request parsing, JavaScript/source-map discovery, static endpoint and secret analysis, pipx packaging, tests, coverage, and security-recon output contracts.
---

# Download JS Map Files

## Repository Workflow

1. Inspect the local tree before editing and preserve unrelated user changes.
2. Keep production code in `src/download_js_map_files/`; avoid adding behavior to legacy root scripts.
3. Keep the CLI installable with pipx through the `download_js_map_files` console script.
4. Prefer small modules with one clear responsibility: CLI parsing, raw request parsing, HTTP session setup, source-map handling, static analysis, file IO, reporting, and scan orchestration.
5. Avoid new runtime dependencies unless the standard library and current dependencies are insufficient.
6. Update README, unit tests, and e2e tests when CLI flags, output files, or scan behavior changes.

## Project Contracts

- `-u/--url` scans a target URL directly.
- `-r/--request` scans from a raw HTTP request file; preserve method, host, headers, and body.
- `-o/--output` controls all generated output.
- `-p/--proxy` enables proxying and defaults to `http://127.0.0.1:8080` when passed without a value.
- `--no-proxy` disables proxying, even if `--proxy` is also supplied.
- Source-map extraction must never write outside the selected output directory.
- Static analysis should keep separate outputs for inline scripts, compiled fallback files, source-map sources, findings, discovered endpoints, and clean RPC names.

## Validation

- Focused unit gate:
  `make test`
- pipx e2e gate:
  `make test-e2e`
- Full local gate:
  `make all`

Unit tests must enforce at least 95 percent coverage for `download_js_map_files`.
