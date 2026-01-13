#!/usr/bin/env python3
"""
JavaScript Reconnaissance Tool v2.2
----------------------------------------------------------
This tool performs static analysis on JavaScript files found on a target URL.
It extracts inline scripts, discovers external scripts, downloads them,
beautifies the code, and scans for potential sensitive secrets (API keys, tokens).
"""

import argparse
import os
import re
import sys
import hashlib
import urllib3
import requests
import jsbeautifier
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
from typing import List, Dict, Optional, Set, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings globally for pentesting contexts (Burp uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI Color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class JavaScriptRecon:
    """
    Main reconnaissance class handling the extraction and analysis
    of JavaScript resources from a specific target.
    """

    # Extended dictionary of regex patterns to identify secrets
    SECRET_PATTERNS: Dict[str, str] = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic API Key": r"(?i)(api_key|apikey|secret|token|auth)[\s]*[:=][\s]*['\"][\w\-]{10,}['\"]",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "JWT Token": r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "Firebase URL": r"[\w-]+\.firebaseio\.com",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
        "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    }

    def __init__(self, url: str, output_dir: str, proxy: Optional[str] = None, cookies: Optional[str] = None):
        """
        Initialize the reconnaissance tool with target and configuration.

        Args:
            url (str): The target URL.
            output_dir (str): Directory to save results.
            proxy (str, optional): Proxy URL (e.g., http://127.0.0.1:8080).
            cookies (str, optional): Raw cookie string.
        """
        # Ensure URL has a valid schema, default to https if missing
        if not url.startswith(('http://', 'https://')):
            print(f"{Colors.YELLOW}[!] No schema detected. Defaulting to https://{Colors.RESET}")
            url = f"https://{url}"

        self.target_url = url if url.endswith('/') else url + '/'
        
        # Robust Base Domain Extraction
        try:
            parsed_url = urlparse(self.target_url)
            netloc = parsed_url.netloc
            # Remove port if present
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            # Handle www prefix
            self.base_domain = netloc[4:] if netloc.startswith("www.") else netloc
        except Exception as e:
            print(f"{Colors.RED}[!] Error parsing base domain: {e}{Colors.RESET}")
            sys.exit(1)

        self.output_dir = output_dir
        self.session = self._configure_session(proxy, cookies)

        # Create output directory structure
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except OSError as e:
                print(f"{Colors.RED}[!] Could not create output directory: {e}{Colors.RESET}")
                sys.exit(1)

    def _configure_session(self, proxy: Optional[str], cookies: Optional[str]) -> requests.Session:
        """
        Configures a requests Session with retries, headers, and proxies.
        """
        session = requests.Session()
        
        # Configure Retry Strategy for unstable connections
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Standard Headers to avoid bot detection
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        if cookies:
            try:
                cookie_dict = {p.split('=')[0].strip(): p.split('=')[1].strip() for p in cookies.split(';') if '=' in p}
                session.cookies.update(cookie_dict)
            except IndexError:
                print(f"{Colors.YELLOW}[!] Warning: Could not parse cookies. Ignoring.{Colors.RESET}")

        session.verify = False  # Always ignore SSL for pentesting/recon tools
        
        if proxy:
            session.proxies.update({'http': proxy, 'https': proxy})
            print(f"{Colors.BLUE}[i] Proxy Configured: {proxy}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[i] No Proxy Configured (Direct Connection){Colors.RESET}")

        return session

    def run(self) -> None:
        """
        Executes the main reconnaissance logic.
        """
        print(f"{Colors.HEADER}[*] Starting analysis on: {self.target_url}{Colors.RESET}")
        print(f"{Colors.BLUE}[i] Base Domain Scope: {self.base_domain}{Colors.RESET}")

        html_content = self._fetch_html_text()
        if not html_content: 
            print(f"{Colors.RED}[!] Critical: Could not retrieve target HTML. Aborting.{Colors.RESET}")
            return

        soup = BeautifulSoup(html_content, 'html.parser')
        page_title = soup.title.string.strip() if soup.title else "No Title Found"
        print(f"{Colors.CYAN}[i] Target Page Title: '{page_title}'{Colors.RESET}")

        # Phase 1: Inline Scripts
        print(f"\n{Colors.HEADER}[*] Phase 1: Analyzing Inline Scripts{Colors.RESET}")
        self._process_inline_scripts(soup, html_content)

        # Phase 2: External Scripts
        print(f"\n{Colors.HEADER}[*] Phase 2: Discovery & Download (External Files){Colors.RESET}")
        discovered_urls = self._discover_js_urls(soup)
        
        if not discovered_urls:
            print(f"{Colors.YELLOW}[!] No script tags found via standard parsing.{Colors.RESET}")

        # Filter in-scope vs out-of-scope
        in_scope_urls = set()
        out_scope_urls = set()

        for u in discovered_urls:
            if self._is_in_scope(u):
                in_scope_urls.add(u)
            else:
                out_scope_urls.add(u)

        print(f"{Colors.BLUE}[*] Found {len(in_scope_urls)} in-scope scripts.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Ignored {len(out_scope_urls)} out-of-scope scripts (3rd party/CDNs).{Colors.RESET}")

        # Save the list of URLs
        self._save_url_list(in_scope_urls)

        # Process downloads
        for i, url in enumerate(in_scope_urls, 1):
            print(f"    [{i}/{len(in_scope_urls)}] Processing...", end='\r')
            self._process_single_external_js(url)

        print(f"\n{Colors.GREEN}[+] Reconnaissance complete. Results stored in: {os.path.abspath(self.output_dir)}{Colors.RESET}")

    def _is_in_scope(self, url: str) -> bool:
        """
        Determines if a URL is within the testing scope based on the base domain.
        Handles subdomains properly.
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Allow exact match
            if domain == self.base_domain:
                return True
            # Allow subdomains (e.g., api.target.com)
            if domain.endswith('.' + self.base_domain):
                return True
            
            return False
        except Exception:
            return False

    def _fetch_html_text(self) -> Optional[str]:
        """
        Fetches the initial HTML of the target with error handling.
        """
        try:
            r = self.session.get(self.target_url, timeout=30)
            r.raise_for_status()
            return r.text
        except requests.exceptions.ProxyError:
            print(f"{Colors.RED}[-] Proxy Error. Is Burp Suite running on the configured port?{Colors.RESET}")
        except requests.exceptions.HTTPError as e:
            print(f"{Colors.RED}[-] HTTP Error: {e}{Colors.RESET}")
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[-] Connection Error. Host might be down or blocking connection.{Colors.RESET}")
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[-] Timeout Error. Target is responding too slowly.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Unexpected Fetch failed: {e}{Colors.RESET}")
        return None

    def _discover_js_urls(self, soup: BeautifulSoup) -> Set[str]:
        """
        Extracts script URLs from HTML tags using standard attributes.
        """
        js_urls = set()
        
        # Standard script tags
        for script in soup.find_all('script'):
            # Check common attributes for JS sources
            for attr in ['src', 'data-src', 'data-href', 'data-url']:
                val = script.get(attr)
                if val and isinstance(val, str):
                    clean_val = val.strip()
                    # Skip data URIs or empty strings
                    if not clean_val or clean_val.startswith(('data:', 'blob:', 'mailto:')):
                        continue
                    
                    full_url = urljoin(self.target_url, clean_val)
                    js_urls.add(full_url)
        
        return js_urls

    def _process_inline_scripts(self, soup: BeautifulSoup, html_content: str) -> None:
        """
        Extracts and processes inline JavaScript. 
        Uses BeautifulSoup first, falls back to Regex if needed.
        """
        inline_dir = os.path.join(self.output_dir, "inline_scripts")
        processed_hashes = set()
        count = 0

        # Method 1: BeautifulSoup Extraction (Safer)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'): continue # Skip external
            content = script.string
            if content:
                self._handle_inline_content(content, inline_dir, processed_hashes)
                count += 1

        # Method 2: Regex fallback (for scripts inside comments or weird templating)
        if count == 0:
            regex_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
            for raw_content in regex_scripts:
                self._handle_inline_content(raw_content, inline_dir, processed_hashes)

    def _handle_inline_content(self, content: str, output_dir: str, hashes: Set[int]) -> None:
        """Helper to process, save and scan a single inline script block."""
        if not content or len(content.strip()) < 10: 
            return
        
        content = content.strip()
        c_hash = hash(content)
        
        if c_hash in hashes: 
            return
        hashes.add(c_hash)

        # Generate a filename based on content hash to avoid collisions
        file_hash_str = hashlib.md5(content.encode('utf-8')).hexdigest()[:8]
        filename = f"inline_{file_hash_str}.js"

        print(f"    {Colors.BLUE}-> Processing Inline Script ({len(content)} bytes){Colors.RESET}")

        # Check for URL encoded payloads
        if "%7B" in content[:100] or "%20" in content[:100]:
            try:
                decoded = unquote(content)
                self._save_file(decoded, output_dir, filename + "_decoded.js")
                self._scan_content(decoded, f"Inline (Decoded): {filename}")
            except Exception: 
                pass

        self._beautify_and_scan(f"Inline: {filename}", content, output_dir, filename)

    def _process_single_external_js(self, js_url: str) -> None:
        """
        Downloads and processes a single external JavaScript file.
        Includes SourceMap detection.
        """
        print(f"{Colors.CYAN}[*] Fetching: {js_url}{Colors.RESET}")
        try:
            r = self.session.get(js_url, timeout=20)
            
            if r.status_code != 200:
                print(f"    {Colors.RED}[-] Failed to download. Status: {r.status_code}{Colors.RESET}")
                return

            js_content = r.text
            compiled_dir = os.path.join(self.output_dir, "compiled")
            sourcemap_dir = os.path.join(self.output_dir, "source_maps")

            # Check for Source Maps
            map_url = self._find_map_url(js_url, js_content)
            map_processed = False

            if map_url and self._is_in_scope(map_url):
                map_processed = self._extract_sourcemap(map_url, sourcemap_dir)

            # If no map or map failed, process the compiled JS
            if not map_processed:
                parsed = urlparse(js_url)
                # Fallback filename if path is empty
                fname = os.path.basename(parsed.path) or f"script_{hash(js_url)}.js"
                
                # Ensure valid filename
                if not fname.endswith('.js'):
                    fname += ".js"
                    
                fname = self._get_unique_filename(compiled_dir, fname)
                self._beautify_and_scan(f"Compiled: {fname}", js_content, compiled_dir, fname)

        except Exception as e:
            print(f"    {Colors.RED}[-] Error processing {js_url}: {str(e)}{Colors.RESET}")

    def _find_map_url(self, js_url: str, content: str) -> Optional[str]:
        """Detects sourceMappingUrl directive."""
        match = re.search(r'//# sourceMappingURL=(.*)', content)
        if match:
            candidate = match.group(1).strip()
            if not candidate.startswith(("data:", "blob:")): 
                return urljoin(js_url, candidate)
        
        # Heuristic check: sometimes .map exists even if not referenced
        return js_url + '.map'

    def _extract_sourcemap(self, map_url: str, output_base: str) -> bool:
        """Downloads and extracts files from a JS Source Map."""
        try:
            r = self.session.get(map_url, timeout=20)
            if r.status_code != 200: 
                return False

            map_json = r.json()
            sources = map_json.get('sources', [])
            contents = map_json.get('sourcesContent', [])
            
            if not sources or not contents: 
                return False

            print(f"    {Colors.GREEN}[!] Source Map Detected: {map_url}{Colors.RESET}")
            print(f"    {Colors.GREEN}[+] Extracting {len(sources)} source files from map...{Colors.RESET}")
            
            for src_path, content in zip(sources, contents):
                if not content: continue
                
                # Sanitize path to prevent directory traversal
                safe_path = os.path.normpath(src_path).replace("..", "").lstrip("/\\")
                # Remove protocol if present in source path (e.g. webpack://)
                if "://" in safe_path:
                    safe_path = safe_path.split("://")[-1]

                full_path = os.path.join(output_base, safe_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                with open(full_path, 'w', encoding='utf-8') as f: 
                    f.write(content)
                
                self._scan_content(content, f"SourceMap: {safe_path}")
            return True
        except Exception as e:
            print(f"    {Colors.YELLOW}[!] Source Map extraction failed: {e}{Colors.RESET}")
            return False

    def _beautify_and_scan(self, label: str, content: str, out_dir: str, fname: str) -> None:
        """Beautifies JS content and triggers the secret scan."""
        os.makedirs(out_dir, exist_ok=True)
        fpath = os.path.join(out_dir, fname)
        
        formatted = content
        # Only beautify if content isn't massively huge to prevent hanging
        if len(content) < 2_500_000:
            try:
                formatted = jsbeautifier.beautify(content)
            except Exception: 
                pass # Fail silently and use raw
        
        with open(fpath, 'w', encoding='utf-8') as f: 
            f.write(formatted)
            
        print(f"    [+] Saved: {fname}")
        self._scan_content(formatted, label)

    def _scan_content(self, content: str, label: str) -> None:
        """Scans the provided content against regex patterns for secrets."""
        lines = content.split('\n')
        findings_file = os.path.join(self.output_dir, "findings.txt")

        for i, line in enumerate(lines):
            # Skip extremely long lines (minified code that failed beautification)
            if len(line) > 10000: continue

            for name, pattern in self.SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    # Context extraction (3 lines before, current, 3 lines after)
                    start = max(0, i - 3)
                    end = min(len(lines), i + 4)
                    context = lines[start:end]

                    header = f"--- [!] {name} FOUND IN {label} (Line {i+1}) ---"
                    print(f"       {Colors.RED}{Colors.BOLD}{header}{Colors.RESET}")

                    with open(findings_file, "a", encoding="utf-8") as f:
                        f.write(f"\n{header}\n")
                        for idx, ctx_line in enumerate(context):
                            line_num = start + idx + 1
                            prefix = ">>> " if line_num == i + 1 else "    "
                            # Truncate very long lines in log
                            output_line = f"{line_num}: {prefix}{ctx_line.strip()[:250]}"
                            f.write(output_line + "\n")
                        f.write("-" * len(header) + "\n")

    def _get_unique_filename(self, directory: str, filename: str) -> str:
        """Ensures filenames are unique to prevent overwriting."""
        base, ext = os.path.splitext(filename)
        # Sanitize filename characters
        base = re.sub(r'[^\w\-_\.]', '_', base)
        
        counter = 1
        new_name = f"{base}{ext}"
        while os.path.exists(os.path.join(directory, new_name)):
            new_name = f"{base}_{counter}{ext}"
            counter += 1
        return new_name

    def _save_file(self, content: str, out_dir: str, fname: str) -> None:
        """Utility to save string content to a file."""
        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(os.path.join(out_dir, fname), 'w', encoding='utf-8') as f: 
                f.write(content)
        except OSError:
            pass

    def _save_url_list(self, urls: Set[str]) -> None:
        """Saves the list of discovered URLs for reference."""
        try:
            with open(os.path.join(self.output_dir, "urls.txt"), "w") as f:
                for u in sorted(list(urls)):
                    f.write(u + "\n")
        except OSError:
            print(f"{Colors.YELLOW}[!] Warning: Could not save urls.txt{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Advanced JS Recon v2.2")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="./js_recon_out", help="Output directory")
    
    # Updated Proxy logic: Defaults to Burp, can be disabled with --no-proxy
    parser.add_argument("-p", "--proxy", default="http://127.0.0.1:8080", 
                        help="Proxy URL (Default: http://127.0.0.1:8080)")
    parser.add_argument("--no-proxy", action="store_true", 
                        help="Disable the default Burp proxy and connect directly")
    parser.add_argument("-c", "--cookies", help="Cookies in format 'key=value; key2=value2'")
    
    args = parser.parse_args()
    
    # Logic to handle the mutually exclusive desire for a default proxy OR no proxy
    active_proxy = args.proxy
    if args.no_proxy:
        active_proxy = None
    
    try:
        recon = JavaScriptRecon(args.url, args.output, active_proxy, args.cookies)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Fatal Error in main execution: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()