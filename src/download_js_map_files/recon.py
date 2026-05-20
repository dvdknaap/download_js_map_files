"""Scanner orchestration for JavaScript and source-map reconnaissance."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import jsbeautifier
import requests
from bs4 import BeautifulSoup

from .analysis.endpoints import EndpointExtractor
from .analysis.secrets import SecretFinding, SecretScanner
from .colors import Colors
from .http import create_session
from .io import append_text, ensure_directory, unique_filename, write_text
from .models import ScannerConfig, ScanTarget
from .reports import ReportWriter
from .sourcemaps import detect_sourcemap_url, safe_source_path


class JavaScriptRecon:
    """Coordinate discovery, download, extraction, analysis, and reporting."""

    def __init__(self, target: ScanTarget, config: ScannerConfig) -> None:
        self.target = target
        self.config = config
        self.base_domain = self._extract_base_domain(target.url)
        self.session = create_session(target.headers, config.proxy, config.retries)
        self.reporter = ReportWriter(config.output_dir)
        self.all_discovered_endpoints: set[str] = set()
        self.clean_rpc_names: set[str] = set()
        ensure_directory(config.output_dir)

    def run(self) -> None:
        """Execute the complete reconnaissance workflow."""

        self._print_startup()
        html_content = self._fetch_initial_html()
        if not html_content:
            print(f"{Colors.RED}[!] Critical: Could not retrieve target HTML. Aborting.{Colors.RESET}")
            return

        soup = BeautifulSoup(html_content, "html.parser")
        page_title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
        print(f"{Colors.CYAN}[i] Page Title: '{page_title}'{Colors.RESET}")

        print(f"\n{Colors.HEADER}[*] Phase 1: Analyzing Inline Scripts{Colors.RESET}")
        self._process_inline_scripts(soup, html_content)

        print(f"\n{Colors.HEADER}[*] Phase 2: Discovery & Download (External Files){Colors.RESET}")
        discovered_urls = self._discover_js_urls(soup)
        in_scope_urls = {url for url in discovered_urls if self._is_in_scope(url)}
        out_scope_urls = discovered_urls - in_scope_urls

        print(f"{Colors.BLUE}[*] Found {len(in_scope_urls)} in-scope scripts.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Ignored {len(out_scope_urls)} out-of-scope scripts.{Colors.RESET}")
        self.reporter.write_url_list(in_scope_urls)

        for index, js_url in enumerate(sorted(in_scope_urls), start=1):
            print(f"    [{index}/{len(in_scope_urls)}] Processing...", end="\r")
            self._process_single_external_js(js_url)

        self.reporter.write_aggregated_endpoints(self.all_discovered_endpoints, self.clean_rpc_names)
        print(f"\n{Colors.GREEN}[+] Reconnaissance complete. Results: {self.config.output_dir.resolve()}{Colors.RESET}")

    def _print_startup(self) -> None:
        print(f"{Colors.HEADER}[*] Starting analysis on: {self.target.url}{Colors.RESET}")
        print(f"{Colors.BLUE}[i] Scope: {self.base_domain}{Colors.RESET}")
        if self.config.proxy:
            print(f"{Colors.BLUE}[i] Proxy Active: {self.config.proxy}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[i] No Proxy Configured (Direct Connection){Colors.RESET}")

    @staticmethod
    def _extract_base_domain(url: str) -> str:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().split(":")[0]
        return netloc[4:] if netloc.startswith("www.") else netloc

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        return domain == self.base_domain or domain.endswith(f".{self.base_domain}")

    def _fetch_initial_html(self) -> str | None:
        try:
            response = self.session.request(
                self.target.method,
                self.target.url,
                data=self.target.body or None,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as exc:
            print(f"{Colors.RED}[-] Fetch failed: {exc}{Colors.RESET}")
            return None

    def _discover_js_urls(self, soup: BeautifulSoup) -> set[str]:
        js_urls: set[str] = set()
        for script in soup.find_all("script"):
            for attr in ("src", "data-src", "data-href", "data-url"):
                value = script.get(attr)
                if not isinstance(value, str):
                    continue
                clean_value = value.strip()
                if clean_value and not clean_value.startswith(("data:", "blob:", "mailto:")):
                    js_urls.add(urljoin(self.target.url, clean_value))
        return js_urls

    def _process_inline_scripts(self, soup: BeautifulSoup, html_content: str) -> None:
        inline_dir = self.config.output_dir / "inline_scripts"
        processed_hashes: set[str] = set()
        count = 0

        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            content = script.string or script.get_text()
            if content:
                self._handle_inline_content(content, inline_dir, processed_hashes)
                count += 1

        if count:
            return

        for raw_content in self._regex_inline_scripts(html_content):
            self._handle_inline_content(raw_content, inline_dir, processed_hashes)

    @staticmethod
    def _regex_inline_scripts(html_content: str) -> list[str]:
        import re

        return re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)

    def _handle_inline_content(self, content: str, output_dir: Path, hashes: set[str]) -> None:
        clean_content = content.strip()
        if len(clean_content) < 10:
            return

        content_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()
        if content_hash in hashes:
            return
        hashes.add(content_hash)

        file_hash = hashlib.md5(clean_content.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        filename = f"inline_{file_hash}.js"
        print(f"    {Colors.BLUE}-> Processing Inline Script ({len(clean_content)} bytes){Colors.RESET}")

        if "%7B" in clean_content[:100]:
            decoded = unquote(clean_content)
            decoded_name = f"{filename}_decoded.js"
            write_text(output_dir / decoded_name, decoded)
            self._beautify_and_scan(f"Inline (Decoded): {filename}", decoded, output_dir, decoded_name)

        self._beautify_and_scan(f"Inline: {filename}", clean_content, output_dir, filename)

    def _process_single_external_js(self, js_url: str) -> None:
        print(f"{Colors.CYAN}[*] Fetching: {js_url}{Colors.RESET}")
        try:
            response = self.session.get(js_url, timeout=self.config.timeout)
            if response.status_code != 200:
                print(f"    {Colors.RED}[-] Failed. Status: {response.status_code}{Colors.RESET}")
                return
        except requests.RequestException as exc:
            print(f"    {Colors.RED}[-] Error processing {js_url}: {exc}{Colors.RESET}")
            return

        compiled_dir = self.config.output_dir / "compiled"
        sourcemap_dir = self.config.output_dir / "source_maps"
        map_url = detect_sourcemap_url(js_url, response.text, response.headers)
        map_success = bool(map_url and self._is_in_scope(map_url) and self._extract_sourcemap(map_url, sourcemap_dir))

        if map_success:
            return

        filename = Path(urlparse(js_url).path).name or f"script_{hashlib.sha1(js_url.encode()).hexdigest()[:8]}.js"
        if not filename.endswith(".js"):
            filename = f"{filename}.js"
        safe_filename = unique_filename(compiled_dir, filename)
        self._beautify_and_scan(f"Compiled: {safe_filename}", response.text, compiled_dir, safe_filename)

    def _extract_sourcemap(self, map_url: str, output_base: Path) -> bool:
        try:
            response = self.session.get(map_url, timeout=self.config.timeout)
            if response.status_code != 200:
                print(f"    {Colors.YELLOW}[-] Map file not reachable ({response.status_code}){Colors.RESET}")
                return False
            map_json = response.json()
        except (requests.RequestException, ValueError) as exc:
            print(f"    {Colors.YELLOW}[!] Source Map processing error: {exc}{Colors.RESET}")
            return False

        sources = self._string_list(map_json.get("sources", []))
        names = self._string_list(map_json.get("names", []))
        contents = map_json.get("sourcesContent", [])

        self._write_sourcemap_metadata(output_base, map_url, sources, names)
        if not contents:
            print(f"    {Colors.YELLOW}[!] Map 'sourcesContent' empty. Saved metadata only.{Colors.RESET}")
            return False

        print(f"    {Colors.GREEN}[+] Extracting {len(sources)} source files...{Colors.RESET}")
        files_extracted = 0
        for index, source in enumerate(sources):
            if index >= len(contents) or contents[index] is None:
                continue

            content = str(contents[index])
            safe_path = safe_source_path(source)
            full_path = output_base / safe_path
            write_text(full_path, content)
            self._beautify_and_scan(f"SourceMap: {safe_path}", content, full_path.parent, full_path.name)
            files_extracted += 1

        return files_extracted > 0

    @staticmethod
    def _string_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _write_sourcemap_metadata(self, output_base: Path, map_url: str, sources: list[str], names: list[str]) -> None:
        metadata_dir = output_base / "_metadata"
        if sources:
            append_text(
                metadata_dir / "map_sources.txt",
                f"\n--- Map: {map_url} ---\n" + "\n".join(sources) + "\n",
            )

        if not names:
            return

        self.reporter.append_suspicious_variables(names, map_url)
        append_text(
            metadata_dir / "map_names.txt",
            f"\n--- Map: {map_url} ---\n" + ", ".join(names) + "\n",
        )
        print(f"    {Colors.BLUE}[i] Extracted {len(names)} variable names & {len(sources)} paths.{Colors.RESET}")

    def _beautify_and_scan(self, label: str, content: str, output_dir: Path, filename: str) -> None:
        ensure_directory(output_dir)
        formatted = self._beautify(content)
        write_text(output_dir / filename, formatted)

        print(f"    [+] Saved: {filename}")
        self._record_secret_findings(SecretScanner.scan(formatted, label))
        self._scan_endpoints(formatted, label)

    @staticmethod
    def _beautify(content: str) -> str:
        if len(content) >= 2_500_000:
            return content
        try:
            return str(jsbeautifier.beautify(content))
        except (TypeError, ValueError):
            return content

    def _record_secret_findings(self, findings: list[SecretFinding]) -> None:
        for finding in findings:
            print(f"       {Colors.RED}{Colors.BOLD}{finding.header}{Colors.RESET}")
        self.reporter.append_secret_findings(findings)

    def _scan_endpoints(self, content: str, label: str) -> None:
        findings = EndpointExtractor.extract(content)
        if not findings.has_findings:
            return

        for block in findings.heuristic_rpc:
            self.clean_rpc_names.update(EndpointExtractor.extract_rpc_names(block))

        self.all_discovered_endpoints.update(findings.standard_endpoints)
        self.reporter.append_endpoint_findings(label, findings)

    def relative_output(self, path: Path) -> str:
        """Return an output path relative to the configured output directory."""

        return os.fspath(path.relative_to(self.config.output_dir))
