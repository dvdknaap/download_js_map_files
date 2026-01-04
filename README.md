# JavaScript Source Map Downloader & Recon Tool

A CLI tool designed for security reconnaissance that detects, downloads, and analyzes JavaScript files from a target website.

The tool prioritizes extracting original source code via Source Maps (`.js.map`). If no source map is found, it falls back to downloading the minified code and beautifying it. Additionally, it performs static analysis on both inline and external scripts to identify potential secrets (API keys, tokens, etc.).

## Features

* **Source Map Extraction:** Automatically detects and downloads `.js.map` files to reconstruct the original source tree.
* **Inline & External Analysis:** Processes both external JS files and inline `<script>` blocks found in the HTML.
* **Fallback Beautification:** Uses `jsbeautifier` to unminify code when source maps are unavailable.
* **Secret Scanning:** Scans all processed code for sensitive patterns, including AWS keys, Google API keys, and private tokens.
* **Proxy Support:** Integrated support for routing traffic through proxies (e.g., Burp Suite) with automatic SSL verification handling.
* **Path Traversal Protection:** Prevents malicious source maps from writing files outside the target directory.

## Installation

### Prerequisites
* Python 3.8+
* pip / pipx

### Installation via pipx
```bash
pipx install git+https://github.com/dvdknaap/download_js_map_files.git

```

## Usage

### Basic Scan

Scan a target URL and save the output to the default directory (`./js_recon_out`).

```bash
download_js_map_files -u https://example.com

```

### Custom Output Directory

Specify a custom folder for the results.

```bash
download_js_map_files -u https://example.com -o ./target_output

```

### Proxy Integration

Route traffic through a proxy (default: `http://127.0.0.1:8080`). 
This automatically disables SSL verification to allow traffic inspection via tools like Burp Suite or Caido.

```bash
# Default proxy (127.0.0.1:8080)
download_js_map_files -u https://example.com -p

# Custom upstream proxy
download_js_map_files -u https://example.com -p http://10.10.10.50:8888
```

## Output Structure

The tool generates the following directory structure upon completion:

* `compiled/`: Contains beautified versions of minified JavaScript files (used as a fallback).
* `source_maps/`: Contains the original source code reconstructed from `.js.map` files, maintaining the original directory structure.
* `inline_scripts/`: Contains extracted inline JavaScript blocks from the HTML.
* `urls.txt`: A list of all unique JavaScript URLs discovered on the target.
* `findings.txt`: A report containing potential secrets found during static analysis, including file names and line numbers.

## Configuration

### Arguments

| Argument | Flag             | Description                       | Default                                     |
|----------|------------------|-----------------------------------|---------------------------------------------|
| URL      | `-u`, `--url`    | The target URL to scan.           | Required                                    |
| Output   | `-o`, `--output` | The directory to save results.    | `./js_recon_out`                            |
| Proxy    | `-p`, `--proxy`  | Proxy URL for traffic inspection. | `None` (or `127.0.0.1:8080` if flag is set) |
