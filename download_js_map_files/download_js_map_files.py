#!/usr/bin/env python3

import os
import sys
import re
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def fetch_html(url: str) -> str:
    response = requests.get(url)
    response.raise_for_status()

    return response.text

def extract_js_urls(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script', src=True)

    return [urljoin(base_url, tag['src']) for tag in scripts]

def find_map_url(js_url: str, js_content: str) -> str | None:
    match = re.search(r'//# sourceMappingURL=(.*)', js_content)

    if match:
        candidate = match.group(1).strip()

        # Only relative or absolute URLs ending in .map (no blob:/data:)
        if candidate.startswith("blob:") or candidate.startswith("data:"):
            print("[*] Skipping inline or blob-based sourceMappingURL")
            return None

        if candidate.endswith(".map"):
            return urljoin(js_url, candidate)
    
    if js_url.endswith('.js'):
        return js_url + '.map'
    
    return None

def fetch_sourcemap(map_url: str) -> dict:
    print(f"[+] Source map found: {map_url}")

    resp = requests.get(map_url)
    resp.raise_for_status()

    return resp.json()

def write_sources(map_json: dict, output_dir: str):
    sources = map_json.get('sources', [])
    contents = map_json.get('sourcesContent', [])

    if not sources or not contents:
        print("[!] No resources or content found in source map.")
        return

    os.makedirs(output_dir, exist_ok=True)
    output_dir_abs = os.path.abspath(output_dir)

    for path, content in zip(sources, contents):
        # 1. Normalize path (remove ../, //, etc.)
        norm_path = os.path.normpath(path)

        # 2. Strip leading ../ and slashes
        cleaned_path = re.sub(r'^(\.\.[\\/])+', '', norm_path).lstrip("/\\")

        # 3. Final destination within output_dir
        full_path = os.path.abspath(os.path.join(output_dir, cleaned_path))

        # Check if the path remains within the output folder
        if not full_path.startswith(output_dir_abs):
            print(f"[!] Skipping file outside target directory: {path}")
            continue

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"[+] Written: {full_path}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <url> <output_dir>")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Detect and parse .js.map files from a website.')
    parser.add_argument('url', help='The URL of the website to scan')
    parser.add_argument('output_dir', nargs='?', default='sourcemap_sources', help='The URL of the website to scanOutputmap for the source files (default: sourcemap_sources)')

    args = parser.parse_args()
    url = args.url
    output_dir = args.output_dir

    print(f"[*] Visit: {url}")

    html = fetch_html(url)
    js_urls = extract_js_urls(html, url)

    for js_url in js_urls:
        print(f"[*] Check JS file: {js_url}")

        try:
            js_content = requests.get(js_url).text
            map_url = find_map_url(js_url, js_content)

            if map_url:
                try:
                    map_json = fetch_sourcemap(map_url)
                    print(f"map_json: {map_json}")
                    write_sources(map_json, output_dir)
                except Exception as e:
                    print(f"[!] Could not retrieve map: {map_url} ({e})")

        except Exception as e:
            print(f"[!] Error retrieving {js_url}: {e}")

if __name__ == '__main__':
    main()
