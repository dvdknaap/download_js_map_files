# JavaScript Source Map Downloader TODO

Status: candidate external helper for Zone A JavaScript/source-map reconnaissance.

The tool is useful for Claudor because it can collect external JavaScript, extract source maps, beautify fallback bundles,
save inline scripts, and surface possible secrets. Do not add it as a fully approved hunter helper until the items below are
closed.

## Current Local CLI

The installed command is available as `download_js_map_files`, but the local help does not match the pasted README:

```text
usage: download_js_map_files [-h] -r REQUEST [-o OUTPUT] [--proxy [PROXY]]
                             [--no-proxy]

Advanced JS Recon v3.0

options:
  -h, --help            show this help message and exit
  -r, --request REQUEST
                        Path to raw HTTP request file
  -o, --output OUTPUT   Output directory
  --proxy [PROXY]       Proxy URL (Default: http://127.0.0.1:8080)
  --no-proxy            Disable the default proxy
```

## Required Fixes

1. Synchronize README and CLI behavior.
   - Either document the real `-r, --request` workflow, or implement the documented `-u, --url` workflow as an additional
     mode.
   - The Claudor guide should prefer raw request mode because it preserves cookies, headers, virtual hosts, and session
     context.

2. Make proxy behavior safe and explicit.
   - README says proxy is disabled unless `-p/--proxy` is used, while local help exposes `--no-proxy`.
   - For hunter automation, the tool should not require Burp/Caido to be running by default.
   - Recommended behavior: no proxy by default, explicit `--proxy [URL]` only when needed.

3. Require project-local output in all examples.
   - Claudor runs should write below paths like:
     `projects/<target>/hunting/zone-a/commands/js-map/`
   - Avoid defaults that write into the repo root, `$HOME`, or `/tmp` during automated runs.

4. Add machine-readable output for automation.
   - Keep `urls.txt` and `findings.txt` for humans.
   - Add `summary.json` or `findings.jsonl` with discovered script URLs, source-map status, files written, secret findings,
     path, line number, pattern, and confidence.
   - Add an endpoint export that can be handed to `claudor-endpoints` or the existing endpoint normalization workflow.

5. Add scope controls.
   - Default to same-origin or explicitly in-scope hosts from the request target.
   - Skip or separately list third-party CDN/vendor scripts unless `--include-third-party` is provided.
   - Record skipped third-party URLs so the operator can review them without accidentally expanding scope.

6. Document raw request preservation.
   - Confirm and document that cookies, authorization headers, custom headers, method, scheme, and Host header are preserved.
   - Include examples for authenticated single-page applications and virtual-host labs.

7. Stabilize exit and status semantics.
   - Exit `0` when JavaScript was processed successfully even if no source maps were found.
   - Use non-zero exit only for usage errors or fatal target/output errors.
   - Emit a clear final status such as `sourcemaps_found`, `beautified_only`, or `no_scripts_found`.

8. Add bounded network behavior.
   - Add or document timeout, retries, delay, and maximum file size limits.
   - This keeps VitaMedix-style production-availability constraints safe and makes failed downloads reproducible.

9. Add regression tests.
   - Local fixture with an HTML page, external JS, inline script, and valid `.js.map`.
   - Source-map path traversal attempt that must stay inside the output directory.
   - No-source-map fallback that writes beautified JS.
   - Secret pattern in inline and external scripts.
   - Third-party script skipped by default.

## Claudor Integration After Fixes

1. Add `knowledge/custom_tools/download_js_map_files/README.md`.
2. Add `knowledge/tool_guides/download_js_map_files/README.md` with hunter-safe commands and failure handling.
3. Update `knowledge/custom_tools/README.md` to list it as the preferred JS/source-map helper for Zone A.
4. Update `tools/README.md` under JavaScript and source-map checks to reference this helper.
5. Keep version numbers out of hunter guidance; use capability-based wording instead.
