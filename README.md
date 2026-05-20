# JavaScript Source Map Downloader & Recon Tool

A pipx-friendly CLI for security reconnaissance against JavaScript-heavy web applications. It discovers inline and external scripts, downloads source maps when available, extracts original sources, falls back to beautified compiled JavaScript, and writes endpoint and secret findings to disk.

## Features

* Source-map discovery through `SourceMap`/`X-SourceMap` headers and `sourceMappingURL` comments.
* Safe source-map extraction that prevents path traversal outside the output directory.
* Inline and external JavaScript processing.
* Beautified fallback output for compiled or minified scripts without usable source maps.
* Static scanning for common secret patterns, API paths, AJAX/fetch calls, full URLs, and RPC-like method definitions.
* Raw HTTP request parsing with preserved method, headers, host, and body.
* Optional proxy support for Burp Suite, Caido, or similar tools.

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

Scan a URL directly:

```bash
download_js_map_files -u https://example.com -o ./js_recon_out --no-proxy
```

Scan from a raw HTTP request file:

```bash
download_js_map_files -r request.txt --scheme https -o ./js_recon_out
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

## Arguments

| Argument | Description |
|----------|-------------|
| `-u`, `--url` | Target URL to scan. Mutually exclusive with `--request`. |
| `-r`, `--request` | Raw HTTP request file to parse. Mutually exclusive with `--url`. |
| `-o`, `--output` | Output directory. Defaults to `./js_recon_out`. |
| `-p`, `--proxy` | Proxy URL. Defaults to `http://127.0.0.1:8080` when passed without a value. |
| `--no-proxy` | Disable proxying. |
| `--scheme` | Scheme used when parsing raw request files. Defaults to `https`. |
| `--version` | Print the installed CLI version. |

## Output Structure

The selected output directory can contain:

* `inline_scripts/`: extracted inline JavaScript blocks.
* `compiled/`: beautified compiled JavaScript when source extraction is unavailable.
* `source_maps/`: original sources reconstructed from source maps.
* `source_maps/_metadata/`: source-map `sources` and `names` intelligence.
* `urls.txt`: in-scope JavaScript URLs discovered on the page.
* `findings.txt`: potential secrets and suspicious source-map variable names.
* `discovered_endpoints.txt`: detailed endpoint and RPC-like context.
* `all_endpoints_unique.txt`: unique URL/API path wordlist.
* `clean_rpc_endpoints.txt`: extracted RPC/method-name wordlist.

## Development

```bash
make format
make lint
make test
make test-e2e
make all
```

`make test` enforces at least 95 percent unit-test coverage for the `download_js_map_files` package. `make test-e2e` installs the local project through pipx in an isolated temporary environment and exercises the console script.
