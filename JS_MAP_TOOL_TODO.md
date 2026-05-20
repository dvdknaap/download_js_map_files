# JavaScript Source Map Downloader TODO

Status: public JavaScript/source-map reconnaissance helper.

## Completed Foundation Work

1. README and CLI behavior are synchronized.
   - Direct URL mode is available with `-u, --url`.
   - Raw HTTP request mode remains available with `-r, --request`.
   - Source-map discovery includes automatic bounded sibling fallback probing when no explicit hint is present.

2. Proxy behavior is explicit.
   - No proxy is used by default.
   - `-p, --proxy` enables a proxy and can accept a custom URL.
   - `--no-proxy` disables proxying even if a proxy flag is supplied.

3. Output is explicit.
   - `-o, --output` is required.
   - Examples use caller-selected output directories.

4. Machine-readable output is available.
   - `summary.json` records scan status, scope, limits, scripts, generated files, and secret findings.
   - `endpoints.jsonl` records endpoint findings for automation.
   - Human-readable `urls.txt`, `findings.txt`, and endpoint text reports remain available.

5. Scope controls are available.
   - Third-party scripts are skipped by default.
   - Skipped third-party script URLs are written for review.
   - `--include-third-party` opts in to processing third-party scripts.
   - `--scope-host`, `--scope-host-file`, `--exclude-host`, and `--exclude-host-file` provide explicit allow/deny scope controls.

6. Raw request preservation is documented.
   - Method, scheme, Host header, cookies, authorization headers, custom headers, and body content are preserved.
   - URL mode supports repeatable `--header` and `--cookie` values for simpler authenticated scans.

7. Exit and status semantics are stabilized.
   - Successful scans exit `0`, including scans with no source maps.
   - Fatal target/output errors use a non-zero exit.
   - Final statuses include `sourcemaps_found`, `beautified_only`, `no_scripts_found`, and `target_fetch_failed`.

8. Bounded network behavior is configurable.
   - CLI options exist for timeout, retries, delay, and maximum response size.

9. Regression coverage exists.
   - Unit tests enforce at least 95 percent package coverage.
   - E2E tests install the local package through pipx and exercise the console script.

## Future Public Improvements

1. Add optional structured logging levels, for example `--quiet` and `--verbose`.
2. Add an optional JSONL secret-finding stream if integrations need append-only output.
3. Add richer endpoint normalization without tying the tool to any one downstream workflow.
4. Add fixtures for more source-map variants, including indexed source maps and missing `sourcesContent`.
5. Add a richer scope report that explains why each skipped script was skipped.

## Downstream Integration

Downstream project integration docs and repository-specific folder conventions should live outside this public tool.
