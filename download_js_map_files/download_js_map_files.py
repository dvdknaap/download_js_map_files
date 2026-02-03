#!/usr/bin/env python3
"""
JavaScript Reconnaissance Tool v3.0
----------------------------------------------------------
Advanced static analysis tool for JavaScript files.

Features:
- Parses raw HTTP requests for context (Cookies/Headers).
- Robust Source Map discovery & Intelligence Extraction.
- Heuristic Proximity Scanning for RPC/API definitions.
- Surgical Extraction of RPC Method Names for Fuzzing lists.
- Extracts secrets, inline scripts, and beautifies code.
- Detailed logging and strict error handling.
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
from typing import List, Dict, Optional, Set, Tuple, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings globally for pentesting contexts
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


class RequestParser:
    """
    Parses a raw HTTP request file to extract URL, method, and headers.
    """

    @staticmethod
    def parse(file_path: str, scheme: str = "https") -> Tuple[str, str, Dict[str, str]]:
        """
        Parses the raw request file line by line.

        Args:
            file_path (str): Path to the request file.
            scheme (str): Protocol scheme (http/https).

        Returns:
            Tuple[str, str, Dict]: Target URL, Method, and Headers.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Request file not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if not lines:
            raise ValueError("Request file is empty")

        # Parse Request Line (e.g., POST /api/v1/login HTTP/1.1)
        req_line_parts = lines[0].strip().split()
        if len(req_line_parts) < 2:
            raise ValueError("Invalid HTTP request line")

        method = req_line_parts[0]
        path = req_line_parts[1]
        headers = {}
        host = ""

        # Parse Headers
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
                if key.lower() == 'host':
                    host = value.strip()

        if not host:
            raise ValueError("Host header missing in request file")

        url = f"{scheme}://{host}{path}"
        return url, method, headers


class EndpointExtractor:
    """
    Dedicated logic to extract API endpoints and RPC methods using
    both Regex patterns and Heuristic Proximity Analysis.
    """

    # Regex for standard API paths (e.g., /api/user, /v1/auth)
    PATH_PATTERN = r"""['"](\/(?:api|v[0-9]|auth|user|admin|svc|rest|graphql)[^'"\s]*)['"]"""

    # Regex for full URLs
    URL_PATTERN = r"""https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^'"\s]*"""

    # Regex for AJAX calls (axios.get, $.post, fetch)
    AJAX_PATTERN = r"""(?:\.get|\.post|\.put|\.delete|fetch|axios|super\.invoke)\s*\(\s*['"]([^'"]+)['"]"""

    # Keywords for Proximity Analysis (RPC detection)
    PROXIMITY_KEYWORDS = [
        "name", "param", "params", "method", "endpoint",
        "url", "action", "invoke", "options", "query",
        "mutation", "operation", "service"
    ]

    @staticmethod
    def extract(content: str) -> Dict[str, Set[str]]:
        """
        Performs deep scanning of JS content using multiple vectors.

        Args:
            content (str): The JavaScript source code.

        Returns:
            Dict: Categorized findings.
        """
        results = {
            "api_paths": set(),
            "full_urls": set(),
            "ajax_calls": set(),
            "heuristic_rpc": set() # Contains the code blocks
        }

        # 1. Standard Regex Scanning
        results["api_paths"].update(re.findall(EndpointExtractor.PATH_PATTERN, content))
        results["full_urls"].update(re.findall(EndpointExtractor.URL_PATTERN, content))
        results["ajax_calls"].update(re.findall(EndpointExtractor.AJAX_PATTERN, content))

        # 2. Heuristic Proximity Scanning (Window-based)
        proximity_findings = EndpointExtractor._scan_proximity(content)
        results["heuristic_rpc"].update(proximity_findings)

        return results

    @staticmethod
    def _scan_proximity(content: str, window_size: int = 6, threshold: int = 3) -> Set[str]:
        """
        Scans code using a sliding window. If a block of lines contains multiple
        distinct API-related keywords, it is flagged as a potential RPC definition.

        Args:
            content (str): Code content.
            window_size (int): Lines to analyze together.
            threshold (int): Minimum keyword matches.

        Returns:
            Set[str]: Formatted findings with context.
        """
        lines = content.split('\n')
        findings = set()

        # Optimization: Skip massive minified lines to prevent regex DoS or hanging
        clean_lines = [line.strip() for line in lines if len(line) < 1000]

        for i in range(len(clean_lines)):
            window_end = min(i + window_size, len(clean_lines))
            window_block = clean_lines[i:window_end]
            joined_block = " ".join(window_block).lower()

            hit_count = 0
            found_keywords = []

            for keyword in EndpointExtractor.PROXIMITY_KEYWORDS:
                if keyword in joined_block:
                    hit_count += 1
                    found_keywords.append(keyword)

            if hit_count >= threshold:
                snippet = "\n".join(window_block)
                formatted = (
                    f"Keys found: {', '.join(found_keywords)}\n"
                    f"Code Block (Line {i+1}):\n{snippet}"
                )
                findings.add(formatted)

        return findings


class JavaScriptRecon:
    """
    Main reconnaissance class handling the extraction and analysis
    of JavaScript resources from a specific target.
    """

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

    SENSITIVE_VAR_NAMES: List[str] = [
        "password", "passwd", "secret", "token", "apiKey", "auth", "credential", "private"
    ]

    def __init__(self, url: str, method: str, headers: Dict[str, str], output_dir: str, proxy: Optional[str] = None):
        """
        Initialize the reconnaissance tool.

        Args:
            url (str): Target URL.
            method (str): HTTP Method.
            headers (Dict): Headers map.
            output_dir (str): Output path.
            proxy (str): Proxy URL.
        """
        self.target_url = url
        self.method = method
        self.headers = headers
        self.output_dir = output_dir
        self.base_domain = self._extract_base_domain(url)
        self.session = self._configure_session(proxy)

        # Global storage for findings across all files
        self.all_discovered_endpoints: Set[str] = set()
        self.clean_rpc_names: Set[str] = set()

        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except OSError as e:
                print(f"{Colors.RED}[!] Could not create output directory: {e}{Colors.RESET}")
                sys.exit(1)

    def _extract_base_domain(self, url: str) -> str:
        """
        Extracts the base domain for scope validation.
        """
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            return netloc[4:] if netloc.startswith("www.") else netloc
        except Exception:
            return ""

    def _configure_session(self, proxy: Optional[str]) -> requests.Session:
        """
        Configures a requests Session with retries, headers, and proxies.
        """
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        session.headers.update(self.headers)
        session.verify = False

        if proxy:
            session.proxies.update({'http': proxy, 'https': proxy})
            print(f"{Colors.BLUE}[i] Proxy Active: {proxy}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[i] No Proxy Configured (Direct Connection){Colors.RESET}")

        return session

    def run(self) -> None:
        """
        Executes the main reconnaissance logic phases.
        """
        print(f"{Colors.HEADER}[*] Starting analysis on: {self.target_url}{Colors.RESET}")
        print(f"{Colors.BLUE}[i] Scope: {self.base_domain}{Colors.RESET}")

        html_content = self._fetch_initial_html()
        if not html_content:
            print(f"{Colors.RED}[!] Critical: Could not retrieve target HTML. Aborting.{Colors.RESET}")
            return

        soup = BeautifulSoup(html_content, 'html.parser')
        page_title = soup.title.string.strip() if soup.title else "No Title"
        print(f"{Colors.CYAN}[i] Page Title: '{page_title}'{Colors.RESET}")

        # Phase 1: Inline Scripts
        print(f"\n{Colors.HEADER}[*] Phase 1: Analyzing Inline Scripts{Colors.RESET}")
        self._process_inline_scripts(soup, html_content)

        # Phase 2: External Scripts
        print(f"\n{Colors.HEADER}[*] Phase 2: Discovery & Download (External Files){Colors.RESET}")
        discovered_urls = self._discover_js_urls(soup)

        in_scope_urls = {u for u in discovered_urls if self._is_in_scope(u)}
        out_scope_urls = discovered_urls - in_scope_urls

        print(f"{Colors.BLUE}[*] Found {len(in_scope_urls)} in-scope scripts.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Ignored {len(out_scope_urls)} out-of-scope scripts.{Colors.RESET}")

        self._save_url_list(in_scope_urls)

        for i, url in enumerate(in_scope_urls, 1):
            print(f"    [{i}/{len(in_scope_urls)}] Processing...", end='\r')
            self._process_single_external_js(url)

        # Final Reporting
        self._save_aggregated_endpoints()
        print(f"\n{Colors.GREEN}[+] Reconnaissance complete. Results: {os.path.abspath(self.output_dir)}{Colors.RESET}")

    def _is_in_scope(self, url: str) -> bool:
        """
        Validates if a URL belongs to the target domain or subdomains.
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]
            return domain == self.base_domain or domain.endswith('.' + self.base_domain)
        except Exception:
            return False

    def _fetch_initial_html(self) -> Optional[str]:
        """
        Fetches the initial HTML page.
        """
        try:
            if self.method.upper() == 'POST':
                r = self.session.post(self.target_url, timeout=30)
            else:
                r = self.session.get(self.target_url, timeout=30)

            r.raise_for_status()
            return r.text
        except Exception as e:
            print(f"{Colors.RED}[-] Fetch failed: {e}{Colors.RESET}")
            return None

    def _discover_js_urls(self, soup: BeautifulSoup) -> Set[str]:
        """
        Extracts script URLs from HTML tags using common attributes.
        """
        js_urls = set()
        for script in soup.find_all('script'):
            for attr in ['src', 'data-src', 'data-href', 'data-url']:
                val = script.get(attr)
                if val and isinstance(val, str):
                    clean_val = val.strip()
                    if clean_val and not clean_val.startswith(('data:', 'blob:', 'mailto:')):
                        js_urls.add(urljoin(self.target_url, clean_val))
        return js_urls

    def _process_inline_scripts(self, soup: BeautifulSoup, html_content: str) -> None:
        """
        Extracts and scans inline JavaScript blocks (BS4 + Regex Fallback).
        """
        inline_dir = os.path.join(self.output_dir, "inline_scripts")
        processed_hashes = set()
        count = 0

        # Method 1: BeautifulSoup
        for script in soup.find_all('script'):
            if not script.get('src') and script.string:
                self._handle_inline_content(script.string, inline_dir, processed_hashes)
                count += 1

        # Method 2: Regex Fallback
        if count == 0:
            regex_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
            for raw_content in regex_scripts:
                self._handle_inline_content(raw_content, inline_dir, processed_hashes)

    def _handle_inline_content(self, content: str, output_dir: str, hashes: Set[int]) -> None:
        """
        Processes a single block of inline JavaScript.
        """
        if not content or len(content.strip()) < 10:
            return

        content = content.strip()
        c_hash = hash(content)
        if c_hash in hashes:
            return
        hashes.add(c_hash)

        file_hash_str = hashlib.md5(content.encode('utf-8')).hexdigest()[:8]
        filename = f"inline_{file_hash_str}.js"

        print(f"    {Colors.BLUE}-> Processing Inline Script ({len(content)} bytes){Colors.RESET}")

        # Decode simplistic URL encoding commonly found in inline injects
        if "%7B" in content[:100]:
            try:
                decoded = unquote(content)
                self._save_file(decoded, output_dir, filename + "_decoded.js")
                self._beautify_and_scan(f"Inline (Decoded): {filename}", decoded, output_dir, filename + "_decoded.js")
            except Exception:
                pass

        self._beautify_and_scan(f"Inline: {filename}", content, output_dir, filename)

    def _process_single_external_js(self, js_url: str) -> None:
        """
        Downloads JS file, checks for Source Maps.
        Extracts Metadata (Sources/Names) AND Content if available.
        Falls back to Minified JS if full source reconstruction is impossible.
        """
        print(f"{Colors.CYAN}[*] Fetching: {js_url}{Colors.RESET}")
        try:
            r = self.session.get(js_url, timeout=20)
            if r.status_code != 200:
                print(f"    {Colors.RED}[-] Failed. Status: {r.status_code}{Colors.RESET}")
                return

            js_content = r.text
            headers = r.headers
            compiled_dir = os.path.join(self.output_dir, "compiled")
            sourcemap_dir = os.path.join(self.output_dir, "source_maps")

            # 1. Attempt to find and extract Map
            map_url = self._detect_sourcemap_url(js_url, js_content, headers)
            map_success = False

            if map_url and self._is_in_scope(map_url):
                # Returns True only if actual SOURCE CODE was extracted.
                # Metadata is extracted regardless inside the method.
                map_success = self._extract_sourcemap(map_url, sourcemap_dir)

            # 2. Logic: If map source extraction failed/incomplete, we scan compiled JS.
            if not map_success:
                fname = os.path.basename(urlparse(js_url).path) or f"script_{hash(js_url)}.js"
                if not fname.endswith('.js'):
                    fname += ".js"
                fname = self._get_unique_filename(compiled_dir, fname)
                self._beautify_and_scan(f"Compiled: {fname}", js_content, compiled_dir, fname)

        except Exception as e:
            print(f"    {Colors.RED}[-] Error processing {js_url}: {str(e)}{Colors.RESET}")

    def _detect_sourcemap_url(self, js_url: str, content: str, headers: Dict[str, Any]) -> Optional[str]:
        """
        Detects the Source Map URL from HTTP headers or file content footer.
        """
        # Vector 1: HTTP Headers
        for header in ['SourceMap', 'X-SourceMap']:
            if header in headers:
                print(f"    {Colors.GREEN}[!] Found SourceMap Header: {header}{Colors.RESET}")
                return urljoin(js_url, headers[header])

        # Vector 2: Source Mapping URL directive
        match = re.search(r'(?://|/\*)\s*[#@]\s*sourceMappingURL=([^\s\'"]+)\s*(?:\*/)?', content)
        if match:
            candidate = match.group(1).strip()
            if not candidate.startswith(("data:", "blob:")):
                return urljoin(js_url, candidate)

        return None

    def _extract_sourcemap(self, map_url: str, output_base: str) -> bool:
        """
        Downloads Source Map.
        1. Extracts METADATA (Filenames + Variable Names) -> Intelligence.
        2. Extracts CONTENT if 'sourcesContent' is present.
        """
        try:
            r = self.session.get(map_url, timeout=20)
            if r.status_code != 200:
                print(f"    {Colors.YELLOW}[-] Map file not reachable ({r.status_code}){Colors.RESET}")
                return False

            map_json = r.json()
            sources = map_json.get('sources', [])
            names = map_json.get('names', [])
            contents = map_json.get('sourcesContent', [])

            # --- INTELLIGENCE EXTRACTION START ---
            meta_dir = os.path.join(output_base, "_metadata")
            os.makedirs(meta_dir, exist_ok=True)

            # Save file paths (Structure Intelligence)
            if sources:
                with open(os.path.join(meta_dir, "map_sources.txt"), "a", encoding="utf-8") as f:
                    f.write(f"\n--- Map: {map_url} ---\n")
                    f.write("\n".join(sources) + "\n")

            # Save and Scan Variable Names (Semantic Intelligence)
            if names:
                self._scan_variable_names(names, map_url)
                with open(os.path.join(meta_dir, "map_names.txt"), "a", encoding="utf-8") as f:
                    f.write(f"\n--- Map: {map_url} ---\n")
                    f.write(", ".join(names) + "\n")

                print(f"    {Colors.BLUE}[i] Extracted {len(names)} variable names & {len(sources)} paths.{Colors.RESET}")
            # --- INTELLIGENCE EXTRACTION END ---

            # Check for actual source code content
            if not contents:
                print(f"    {Colors.YELLOW}[!] Map 'sourcesContent' empty. Saved metadata only.{Colors.RESET}")
                return False

            print(f"    {Colors.GREEN}[+] Extracting {len(sources)} source files...{Colors.RESET}")

            files_extracted = 0
            for i, src_path in enumerate(sources):
                if i >= len(contents) or contents[i] is None:
                    continue

                content = contents[i]

                # Sanitize path to prevent directory traversal
                safe_path = os.path.normpath(src_path).replace("..", "").lstrip("/\\")
                if "webpack:///" in safe_path:
                    safe_path = safe_path.replace("webpack:///", "")
                elif "://" in safe_path:
                    safe_path = safe_path.split("://")[-1]

                if '?' in safe_path:
                    safe_path = safe_path.split('?')[0]

                if safe_path.startswith("../") or safe_path.startswith("/") or "\\" in safe_path:
                    safe_path = os.path.basename(safe_path)

                full_path = os.path.join(output_base, safe_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Also scan the extracted source for endpoints!
                self._beautify_and_scan(f"SourceMap: {safe_path}", content, os.path.dirname(full_path), os.path.basename(full_path))
                files_extracted += 1

            return files_extracted > 0

        except Exception as e:
            print(f"    {Colors.YELLOW}[!] Source Map processing error: {e}{Colors.RESET}")
            return False

    def _scan_variable_names(self, names: List[str], origin: str) -> None:
        """
        Scans extracted variable names for suspicious terminology.
        """
        findings_file = os.path.join(self.output_dir, "findings.txt")
        suspicious = []

        for name in names:
            for pattern in self.SENSITIVE_VAR_NAMES:
                if pattern in name.lower():
                    suspicious.append(name)
                    break

        if suspicious:
            header = f"--- [!] SUSPICIOUS VARIABLES IN MAP: {os.path.basename(origin)} ---"
            with open(findings_file, "a", encoding="utf-8") as f:
                f.write(f"\n{header}\n")
                f.write(f"Matches: {', '.join(suspicious)}\n")
                f.write("-" * len(header) + "\n")

    def _beautify_and_scan(self, label: str, content: str, out_dir: str, fname: str) -> None:
        """
        Beautifies and scans content. Saves result to file.
        """
        os.makedirs(out_dir, exist_ok=True)
        fpath = os.path.join(out_dir, fname)

        formatted = content
        if len(content) < 2_500_000:
            try:
                formatted = jsbeautifier.beautify(content)
            except Exception:
                pass

        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(formatted)

        print(f"    [+] Saved: {fname}")
        self._scan_secrets(formatted, label)
        self._scan_endpoints(formatted, label)

    def _scan_secrets(self, content: str, label: str) -> None:
        """
        Scans content for defined secret patterns.
        """
        lines = content.split('\n')
        findings_file = os.path.join(self.output_dir, "findings.txt")

        for i, line in enumerate(lines):
            if len(line) > 10000: continue

            for name, pattern in self.SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    header = f"--- [!] {name} FOUND IN {label} (Line {i+1}) ---"
                    print(f"       {Colors.RED}{Colors.BOLD}{header}{Colors.RESET}")

                    with open(findings_file, "a", encoding="utf-8") as f:
                        f.write(f"\n{header}\n{lines[i].strip()[:200]}\n")
                        f.write("-" * len(header) + "\n")

    def _scan_endpoints(self, content: str, label: str) -> None:
        """
        Uses EndpointExtractor to find API calls and processes heuristic clusters
        into clean RPC names.
        """
        extracted = EndpointExtractor.extract(content)

        has_findings = any(extracted.values())
        if not has_findings: return

        formatted_endpoints = []

        # 1. Process Heuristic RPC Clusters -> Extract Clean Names
        if extracted["heuristic_rpc"]:
            formatted_endpoints.append("\n--- HEURISTIC RPC/API CLUSTERS ---")
            for block in extracted["heuristic_rpc"]:
                formatted_endpoints.append(f"{block}\n----------------")

                # Perform surgical extraction on the block
                self._extract_clean_rpc_names(block)

        # 2. Add Standard Regex Matches
        if extracted["api_paths"]:
            formatted_endpoints.append("\n--- API Paths ---")
            formatted_endpoints.extend([f"  > {m}" for m in sorted(extracted["api_paths"])])

        if extracted["ajax_calls"]:
            formatted_endpoints.append("\n--- AJAX Calls ---")
            formatted_endpoints.extend([f"  > {m}" for m in sorted(extracted["ajax_calls"])])

        if extracted["full_urls"]:
            formatted_endpoints.append("\n--- Full URLs ---")
            formatted_endpoints.extend([f"  > {m}" for m in sorted(extracted["full_urls"])])

        # Add to global unique set
        self.all_discovered_endpoints.update(extracted["api_paths"])
        self.all_discovered_endpoints.update(extracted["full_urls"])
        self.all_discovered_endpoints.update(extracted["ajax_calls"])

        # Log details to script-specific file
        endpoint_log = os.path.join(self.output_dir, "discovered_endpoints.txt")
        with open(endpoint_log, "a", encoding="utf-8") as f:
            f.write(f"\n\n=== Endpoints/Signatures in {label} ===\n")
            f.write("\n".join(formatted_endpoints))

    def _extract_clean_rpc_names(self, code_block: str) -> None:
        """
        Surgically extracts the method name from a discovered proximity block.
        Looks for patterns like name: "MethodName" or action: "MethodName".

        Args:
            code_block (str): The code snippet flagged by Proximity Scanning.
        """
        # Regex looks for: key followed by colon, optional space, quote, VALUE, quote
        rpc_pattern = r"""(?i)(?:name|action|method|operation)\s*[:=]\s*['"]([a-zA-Z0-9_\-\/]+)['"]"""

        clean_matches = re.findall(rpc_pattern, code_block)
        for clean_name in clean_matches:
            # Filter out common JS keywords/noise to keep the wordlist high quality
            ignore_list = ['get', 'post', 'utf-8', 'viewport', 'json', 'application', 'true', 'false']
            if clean_name.lower() not in ignore_list:
                self.clean_rpc_names.add(clean_name)

    def _save_aggregated_endpoints(self) -> None:
        """
        Saves clean lists of all unique endpoints found to separate files.
        """
        # Save Standard Endpoints (Paths/URLs)
        if self.all_discovered_endpoints:
            path = os.path.join(self.output_dir, "all_endpoints_unique.txt")
            with open(path, "w", encoding="utf-8") as f:
                for ep in sorted(self.all_discovered_endpoints):
                    f.write(ep + "\n")
            print(f"{Colors.GREEN}[+] Extracted {len(self.all_discovered_endpoints)} unique URL/API paths.{Colors.RESET}")

        # Save Clean RPC Names (The Fuzzer List)
        if self.clean_rpc_names:
            rpc_path = os.path.join(self.output_dir, "clean_rpc_endpoints.txt")
            with open(rpc_path, "w", encoding="utf-8") as f:
                for name in sorted(self.clean_rpc_names):
                    f.write(name + "\n")
            print(f"{Colors.GREEN}[+] Extracted {len(self.clean_rpc_names)} unique RPC methods to: {rpc_path}{Colors.RESET}")

    def _get_unique_filename(self, directory: str, filename: str) -> str:
        """
        Generates a unique filename to prevent overwrites.
        """
        base, ext = os.path.splitext(filename)
        base = re.sub(r'[^\w\-_\.]', '_', base)

        counter = 1
        new_name = f"{base}{ext}"
        while os.path.exists(os.path.join(directory, new_name)):
            new_name = f"{base}_{counter}{ext}"
            counter += 1
        return new_name

    def _save_file(self, content: str, out_dir: str, fname: str) -> None:
        """
        Writes content to file.
        """
        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(os.path.join(out_dir, fname), 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass

    def _save_url_list(self, urls: Set[str]) -> None:
        """
        Saves discovered URLs to disk.
        """
        try:
            with open(os.path.join(self.output_dir, "urls.txt"), "w") as f:
                for u in sorted(list(urls)):
                    f.write(u + "\n")
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Advanced JS Recon v3.0")
    parser.add_argument("-r", "--request", required=True, help="Path to raw HTTP request file")
    parser.add_argument("-o", "--output", default="./js_recon_out", help="Output directory")

    parser.add_argument("--proxy", nargs='?', const="http://127.0.0.1:8080", default="http://127.0.0.1:8080",
                        help="Proxy URL (Default: http://127.0.0.1:8080)")
    parser.add_argument("--no-proxy", action="store_true",
                        help="Disable the default proxy")

    args = parser.parse_args()

    active_proxy = None if args.no_proxy else args.proxy

    try:
        print(f"{Colors.HEADER}[*] Parsing Request File: {args.request}{Colors.RESET}")
        url, method, headers = RequestParser.parse(args.request)

        recon = JavaScriptRecon(
            url=url,
            method=method,
            headers=headers,
            output_dir=args.output,
            proxy=active_proxy
        )
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Fatal Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()
