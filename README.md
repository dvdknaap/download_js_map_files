# download JS map files

A simple CLI tool to detect and download `.js.map` (JavaScript source map) files from a website, then extract the original source files.

## What does this tool do?

- Fetches a target webpage
- Detects all `<script src=...>` tags
- Checks if a related `.js.map` file exists (via `sourceMappingURL` or direct guess)
- Parses the source map (if available)
- Writes the original source files (from `sourcesContent`) to a local folder

## Installation with pipx
`pipx install git+https://github.com/dvdknaap/download_js_map_files.git`

## Usage
`download_js_map_files <URL> [OUTPUT_DIR]`
