#!/usr/bin/env python3
"""
JavaScript Reconnaissance Tool v2.0
-----------------------------------
"""

import argparse
import os
import re
import sys
import json
import urllib3
import requests
import jsbeautifier
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
from typing import List, Dict, Optional, Set

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class JavaScriptRecon:

    SECRET_PATTERNS: Dict[str, str] = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic API Key": r"(?i)(api_key|apikey|secret|token)[\s]*[:=][\s]*['\"][\w\-]{10,}['\"]",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "JWT Token": r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "Firebase URL": r"[\w-]+\.firebaseio\.com",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
    }

    def __init__(self, url: str, output_dir: str, proxy: Optional[str] = None, cookies: Optional[str] = None):
        self.target_url = url if url.endswith('/') else url + '/'
        netloc = urlparse(self.target_url).netloc
        self.base_domain = netloc[4:] if netloc.startswith("www.") else netloc
        self.output_dir = output_dir
        self.session = requests.Session()

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        })

        if cookies:
            cookie_dict = {p.split('=')[0].strip(): p.split('=')[1].strip() for p in cookies.split(';') if '=' in p}
            self.session.cookies.update(cookie_dict)

        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
            self.session.verify = False

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run(self) -> None:
        print(f"{Colors.HEADER}[*] Starting analysis on: {self.target_url}{Colors.RESET}")
        html_content = self._fetch_html_text()
        if not html_content: return

        soup = BeautifulSoup(html_content, 'html.parser')
        page_title = soup.title.string.strip() if soup.title else "No Title"
        print(f"{Colors.CYAN}[i] Page Title: '{page_title}'{Colors.RESET}")

        print(f"\n{Colors.HEADER}[*] Phase 1: Analyzing Inline Scripts{Colors.RESET}")
        self._process_inline_scripts(html_content)

        print(f"\n{Colors.HEADER}[*] Phase 2: Discovery (External Files){Colors.RESET}")
        discovered_urls = self._discover_js_urls(soup)
        in_scope_urls = {u for u in discovered_urls if self._is_in_scope(u)}
        print(f"{Colors.BLUE}[*] Found {len(in_scope_urls)} in-scope scripts.{Colors.RESET}")

        for url in in_scope_urls:
            self._process_single_external_js(url)

        print(f"\n{Colors.GREEN}[+] Reconnaissance complete. Results in: {self.output_dir}{Colors.RESET}")

    def _is_in_scope(self, url: str) -> bool:
        try:
            domain = urlparse(url).netloc.lower().split(':')[0]
            return domain == self.base_domain or domain.endswith('.' + self.base_domain)
        except: return False

    def _fetch_html_text(self) -> Optional[str]:
        try:
            r = self.session.get(self.target_url, timeout=20)
            r.raise_for_status()
            return r.text
        except Exception as e:
            print(f"{Colors.RED}[-] Fetch failed: {e}{Colors.RESET}")
            return None

    def _discover_js_urls(self, soup: BeautifulSoup) -> Set[str]:
        js_urls = set()
        for script in soup.find_all('script'):
            for attr in ['src', 'data-src', 'data-href']:
                val = script.get(attr)
                if val and not val.startswith('data:'):
                    js_urls.add(urljoin(self.target_url, val))
        return js_urls

    def _process_inline_scripts(self, html_content: str) -> None:
        inline_dir = os.path.join(self.output_dir, "inline_scripts")
        processed_hashes = set()
        regex_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)

        count = 0
        for raw_content in regex_scripts:
            content = raw_content.strip()
            if len(content) < 10: continue
            c_hash = hash(content)
            if c_hash in processed_hashes: continue
            processed_hashes.add(c_hash)

            count += 1
            filename = f"inline_{count:03d}.js"
            print(f"    {Colors.BLUE}-> Found Inline Script #{count} ({len(content)} bytes){Colors.RESET}")

            if "%7B" in content[:100]:
                try:
                    decoded = unquote(content)
                    self._save_file(decoded, inline_dir, filename + "_decoded.js")
                    self._scan_content(decoded, f"Inline (Decoded): {filename}")
                except: pass

            self._beautify_and_scan(f"Inline: {filename}", content, inline_dir, filename)

    def _process_single_external_js(self, js_url: str) -> None:
        print(f"{Colors.CYAN}[*] Fetching: {js_url}{Colors.RESET}")
        try:
            r = self.session.get(js_url, timeout=20)
            if r.status_code != 200: return

            js_content = r.text
            compiled_dir = os.path.join(self.output_dir, "compiled")
            sourcemap_dir = os.path.join(self.output_dir, "source_maps")

            map_url = self._find_map_url(js_url, js_content)
            map_processed = False

            if map_url and self._is_in_scope(map_url):
                # Attempt silent map download
                map_processed = self._extract_sourcemap(map_url, sourcemap_dir)

            if not map_processed:
                parsed = urlparse(js_url)
                fname = os.path.basename(parsed.path) or f"script_{hash(js_url)}.js"
                fname = self._get_unique_filename(compiled_dir, fname)
                self._beautify_and_scan(f"Compiled: {fname}", js_content, compiled_dir, fname)
        except Exception:
            pass

    def _find_map_url(self, js_url: str, content: str) -> Optional[str]:
        match = re.search(r'//# sourceMappingURL=(.*)', content)
        if match:
            candidate = match.group(1).strip()
            if not candidate.startswith(("data:", "blob:")): return urljoin(js_url, candidate)
        return js_url + '.map' if js_url.endswith('.js') else None

    def _extract_sourcemap(self, map_url: str, output_base: str) -> bool:
        try:
            r = self.session.get(map_url, timeout=20)
            if r.status_code != 200: return False # Silent fail for 404s

            map_json = r.json()
            sources, contents = map_json.get('sources', []), map_json.get('sourcesContent', [])
            if not sources or not contents: return False

            print(f"    {Colors.GREEN}[!] Source Map Found: {map_url}{Colors.RESET}")
            print(f"    {Colors.GREEN}[+] Extracting {len(sources)} source files...{Colors.RESET}")
            os.makedirs(output_base, exist_ok=True)
            for src_path, content in zip(sources, contents):
                if not content: continue
                safe_path = os.path.normpath(src_path).replace("..", "").lstrip("/\\")
                full_path = os.path.join(output_base, safe_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'w', encoding='utf-8') as f: f.write(content)
                self._scan_content(content, f"SourceMap: {safe_path}")
            return True
        except: return False

    def _beautify_and_scan(self, label: str, content: str, out_dir: str, fname: str) -> None:
        os.makedirs(out_dir, exist_ok=True)
        fpath = os.path.join(out_dir, fname)
        try:
            formatted = jsbeautifier.beautify(content) if len(content) < 2_000_000 else content
        except: formatted = content
        with open(fpath, 'w', encoding='utf-8') as f: f.write(formatted)
        print(f"    [+] Saved: {fname}")
        self._scan_content(formatted, label)

    def _scan_content(self, content: str, label: str) -> None:
        lines = content.split('\n')
        findings_file = os.path.join(self.output_dir, "findings.txt")

        for i, line in enumerate(lines):
            if len(line) > 100000: continue

            for name, pattern in self.SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    # Context extraction (3 lines before, current, 3 lines after)
                    start = max(0, i - 3)
                    end = min(len(lines), i + 4)
                    context = lines[start:end]

                    header = f"--- [!] {name} GEVONDEN IN {label} (Regel {i+1}) ---"
                    print(f"       {Colors.RED}{Colors.BOLD}{header}{Colors.RESET}")

                    with open(findings_file, "a", encoding="utf-8") as f:
                        f.write(f"\n{header}\n")
                        for idx, ctx_line in enumerate(context):
                            line_num = start + idx + 1
                            prefix = ">>> " if line_num == i + 1 else "    "
                            output_line = f"{line_num}: {prefix}{ctx_line.strip()[:200]}"
                            f.write(output_line + "\n")
                        f.write("-" * len(header) + "\n")

    def _get_unique_filename(self, directory: str, filename: str) -> str:
        base, ext = os.path.splitext(filename)
        counter, new_name = 1, filename
        while os.path.exists(os.path.join(directory, new_name)):
            new_name = f"{base}_{counter}{ext}"
            counter += 1
        return new_name

    def _save_file(self, content: str, out_dir: str, fname: str):
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, fname), 'w', encoding='utf-8') as f: f.write(content)

    def _save_url_list(self, urls: Set[str]) -> None:
        with open(os.path.join(self.output_dir, "urls.txt"), "w") as f:
            for u in urls: f.write(u + "\n")

def main():
    parser = argparse.ArgumentParser(description="Advanced JS Recon v7.1")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-o", "--output", default="./js_recon_out")
    parser.add_argument("-p", "--proxy")
    parser.add_argument("-c", "--cookies")
    args = parser.parse_args()
    try:
        recon = JavaScriptRecon(args.url, args.output, args.proxy, args.cookies)
        recon.run()
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e: print(f"{Colors.RED}Fatal: {e}{Colors.RESET}")

if __name__ == '__main__':
    main()
