# JavaScript Source Map Downloader & Recon Tool

A pipx-friendly CLI for security reconnaissance against JavaScript-heavy web applications. It discovers inline and external scripts, downloads source maps when available, extracts original sources, falls back to beautified compiled JavaScript, and writes endpoint and secret findings to disk.

## Features

* Source-map discovery through `SourceMap`/`X-SourceMap` headers, `sourceMappingURL` comments, and bounded automatic sibling fallback probing.
* Safe source-map extraction that prevents path traversal outside the output directory.
* Inline and external JavaScript processing.
* Beautified fallback output for compiled or minified scripts without usable source maps.
* Static scanning for common secret patterns, API paths, AJAX/fetch calls, full URLs, and RPC-like method definitions.
* Raw HTTP request parsing with preserved method, headers, host, and body.
* URL scans can add repeatable headers and cookies without requiring a raw request file.
* Optional proxy support for Burp Suite, Caido, or similar tools.
* Host allowlists and denylists with repeatable CLI flags or newline-based host files.

## Installation

Requires Python 3.10+.

```bash
pipx install git+https://github.com/dvdknaap/download_js_map_files.git
```

For local development:

```bash
make init
```

## Usage

Show help. Running the command without arguments prints the same grouped help:

```bash
download_js_map_files
download_js_map_files --help
```

Scan a URL directly:

```bash
download_js_map_files -u https://example.com -o ./scan-output/example --no-proxy
```

Scan from a raw HTTP request file:

```bash
download_js_map_files -r request.txt --scheme https -o ./scan-output/example
```

Scan a URL with additional headers and cookies:

```bash
download_js_map_files -u https://example.com/app -o ./scan-output/example \
  --header "Authorization: Bearer <token>" \
  --header "X-Requested-With: XMLHttpRequest" \
  --cookie "session=abc123" \
  --cookie "theme=dark"
```

Route traffic through the default local proxy:

```bash
download_js_map_files -u https://example.com -p
```

Use a custom proxy:

```bash
download_js_map_files -u https://example.com --proxy http://127.0.0.1:8081
```

Disable proxying even when a proxy flag is supplied:

```bash
download_js_map_files -u https://example.com --proxy http://127.0.0.1:8081 --no-proxy
```

Process third-party scripts as well as same-site scripts:

```bash
download_js_map_files -u https://example.com -o ./scan-output/example --include-third-party
```

Process only selected additional hosts and skip known unwanted hosts:

```bash
download_js_map_files -u https://example.com -o ./scan-output/example \
  --scope-host cdn.example.com \
  --scope-host-file ./scope-hosts.txt \
  --exclude-host analytics.example.com \
  --exclude-host-file ./exclude-hosts.txt
```

Tune network bounds:

```bash
download_js_map_files -u https://example.com -o ./scan-output/example --timeout 10 --retries 1 --delay 0.2 --max-file-size 5242880
```

## CLI Reference

The help output is grouped by workflow area and shows default values.

### Target Selection

| Argument | Description |
|----------|-------------|
| `-u`, `--url` | Target URL to scan. Mutually exclusive with `--request`. |
| `-r`, `--request` | Raw HTTP request file to parse. Mutually exclusive with `--url`. |

### Output

| Argument | Description |
|----------|-------------|
| `-o`, `--output` | Required output directory. |

### Request Context

| Argument | Default | Description |
|----------|---------|-------------|
| `--header HEADER` | `None` | Extra HTTP header in `Name: value` format. Can be used multiple times. |
| `--cookie COOKIE` | `None` | Extra cookie in `name=value` format. Can be used multiple times. Multiple cookies are sent as one `Cookie` header. |

These options work for direct URL scans and raw request scans. When a CLI header repeats a header from a raw request file, the CLI value wins. CLI cookies are appended to an existing raw request `Cookie` header.

### Proxy And Scope

| Argument | Default | Description |
|----------|---------|-------------|
| `-p`, `--proxy [URL]` | `None` | Enable proxying. Uses `http://127.0.0.1:8080` when passed without a URL. |
| `--no-proxy` | `False` | Disable proxying even when `--proxy` is supplied. |
| `--include-third-party` | `False` | Process third-party script URLs instead of only recording them as skipped. |
| `--scope-host HOST` | `None` | Additional in-scope host or domain. Can be used multiple times. |
| `--scope-host-file PATH` | `None` | File with additional in-scope hosts, one per line. Can be used multiple times. |
| `--exclude-host HOST` | `None` | Host or domain to skip even if otherwise in scope. Can be used multiple times. |
| `--exclude-host-file PATH` | `None` | File with hosts to skip, one per line. Can be used multiple times. |

Host files are newline-based. Blank lines and comments beginning with `#` are ignored. Host values can be plain hosts, host:port values, or URLs; they are normalized before matching.

### Raw Request

| Argument | Choices | Default | Description |
|----------|---------|---------|-------------|
| `--scheme` | `http`, `https` | `https` | Scheme used when parsing raw request files. |

### Network Limits

| Argument | Default | Description |
|----------|---------|-------------|
| `--timeout` | `20.0` | HTTP timeout in seconds. |
| `--retries` | `3` | Retry count for transient HTTP failures. |
| `--delay` | `0.0` | Delay in seconds before each external script or source-map request. |
| `--max-file-size` | `10485760` | Maximum response size in bytes for HTML, JavaScript, and source-map downloads. |

### Metadata

| Argument | Description |
|----------|-------------|
| `--version` | Print the installed CLI version. |

## Output Structure

The selected output directory can contain:

* `inline_scripts/`: extracted inline JavaScript blocks.
* `compiled/`: beautified compiled JavaScript when source extraction is unavailable.
* `source_maps/`: original sources reconstructed from source maps.
* `source_maps/_metadata/`: source-map `sources` and `names` intelligence.
* `urls.txt`: in-scope JavaScript URLs discovered on the page.
* `skipped_third_party_urls.txt`: third-party script URLs recorded but not processed by default.
* `findings.txt`: potential secrets and suspicious source-map variable names.
* `discovered_endpoints.txt`: detailed endpoint and RPC-like context.
* `endpoints.jsonl`: machine-readable endpoint findings.
* `all_endpoints_unique.txt`: unique URL/API path wordlist.
* `clean_rpc_endpoints.txt`: extracted RPC/method-name wordlist.
* `summary.json`: machine-readable scan status, limits, script processing records, generated files, and secret findings.

## Status Semantics

The CLI exits `0` when a scan completes successfully, including scans where no source maps are found. Fatal target or output errors return a non-zero exit code. `summary.json` and the final console status use values such as `sourcemaps_found`, `beautified_only`, `no_scripts_found`, and `target_fetch_failed`. `summary.json` also records configured `scope_hosts` and `exclude_hosts`.

## Source Map Discovery

The scanner first honors explicit source-map hints from `SourceMap`/`X-SourceMap` headers and `sourceMappingURL` comments. When no usable hint exists, it automatically tries bounded sibling candidates next to the JavaScript file, such as `app.js.map`, `app.map`, and for `app.min.js` also `app.js.map`. These fallback probes stay within the normal scope rules.

## Raw Request Preservation

Raw request mode preserves method, Host header, cookies, authorization headers, custom headers, body content, and the selected scheme. This is useful for authenticated applications and virtual-host test environments where a plain URL is not enough context.

## Development

```bash
make format
make lint
make test
make test-e2e
make all
```

`make test` enforces at least 95 percent unit-test coverage for the `download_js_map_files` package. `make test-e2e` installs the local project through pipx in an isolated temporary environment and exercises the console script.
