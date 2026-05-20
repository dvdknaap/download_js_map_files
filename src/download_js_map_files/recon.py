"""Scanner orchestration for JavaScript and source-map reconnaissance."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import jsbeautifier
import requests
from bs4 import BeautifulSoup

from .analysis.endpoints import EndpointExtractor
from .analysis.scripts import extract_script_references
from .analysis.secrets import SecretFinding, SecretScanner
from .colors import Colors
from .http import create_session
from .io import append_text, ensure_directory, unique_filename, write_text
from .models import ScannerConfig, ScanResult, ScanTarget
from .reports import ReportWriter
from .scope import host_matches, normalize_host
from .sourcemaps import extract_sourcemap_entries, resolve_source_url, safe_source_path, source_map_candidates


class JavaScriptRecon:
    """Coordinate discovery, download, extraction, analysis, and reporting."""

    def __init__(self, target: ScanTarget, config: ScannerConfig) -> None:
        self.target = target
        self.config = config
        self.base_domain = self._extract_base_domain(target.url)
        self.session = create_session(target.headers, config.proxy, config.retries)
        self.reporter = ReportWriter(config.output_dir)
        self.all_discovered_endpoints: set[str] = set()
        self.normalized_endpoints: set[str] = set()
        self.clean_rpc_names: set[str] = set()
        self.discovered_script_urls: set[str] = set()
        self.in_scope_script_urls: set[str] = set()
        self.skipped_third_party_urls: set[str] = set()
        self.scope_decisions: list[dict[str, Any]] = []
        self.processed_scripts: list[dict[str, Any]] = []
        self.secret_records: list[dict[str, Any]] = []
        self.source_maps_found = 0
        self.beautified_files = 0
        self.scripts_processed = 0
        self.inline_scripts_processed = 0
        ensure_directory(config.output_dir)

    def run(self) -> ScanResult:
        """Execute the complete reconnaissance workflow."""

        self._print_startup()
        html_content = self._fetch_initial_html()
        if not html_content:
            print(f"{Colors.RED}[!] Critical: Could not retrieve target HTML. Aborting.{Colors.RESET}")
            status = "target_fetch_failed"
            self._write_final_machine_reports(status)
            return ScanResult(status=status, fatal=True)

        soup = BeautifulSoup(html_content, "html.parser")
        page_title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
        print(f"{Colors.CYAN}[i] Page Title: '{page_title}'{Colors.RESET}")

        print(f"\n{Colors.HEADER}[*] Phase 1: Analyzing Inline Scripts{Colors.RESET}")
        self._process_inline_scripts(soup, html_content)

        print(f"\n{Colors.HEADER}[*] Phase 2: Discovery & Download (External Files){Colors.RESET}")
        self.discovered_script_urls = self._discover_js_urls(soup)
        self.in_scope_script_urls, self.skipped_third_party_urls = self._filter_script_urls(self.discovered_script_urls)

        print(f"{Colors.BLUE}[*] Found {len(self.in_scope_script_urls)} scripts selected for processing.{Colors.RESET}")
        skipped_count = len(self.skipped_third_party_urls)
        print(f"{Colors.YELLOW}[*] Recorded {skipped_count} skipped third-party scripts.{Colors.RESET}")
        if self.skipped_third_party_urls:
            self._verbose(f"Skipped third-party scripts: {', '.join(sorted(self.skipped_third_party_urls))}")
        self.reporter.write_url_list(self.in_scope_script_urls)
        self.reporter.write_skipped_third_party(self.skipped_third_party_urls)
        self.reporter.write_scope_report(self._build_scope_report())

        for index, js_url in enumerate(sorted(self.in_scope_script_urls), start=1):
            print(f"    [{index}/{len(self.in_scope_script_urls)}] Processing...", end="\r")
            self._process_single_external_js(js_url)

        self.reporter.write_aggregated_endpoints(
            self.all_discovered_endpoints,
            self.clean_rpc_names,
            self.normalized_endpoints,
        )
        status = self._final_status()
        self._write_final_machine_reports(status)
        print(f"{Colors.BLUE}[i] Final status: {status}{Colors.RESET}")
        print(f"\n{Colors.GREEN}[+] Reconnaissance complete. Results: {self.config.output_dir.resolve()}{Colors.RESET}")
        return ScanResult(status=status)

    def _print_startup(self) -> None:
        print(f"{Colors.HEADER}[*] Starting analysis on: {self.target.url}{Colors.RESET}")
        print(f"{Colors.BLUE}[i] Scope: {self.base_domain}{Colors.RESET}")
        self._verbose(f"Target method: {self.target.method}")
        self._verbose(f"Output directory: {self.config.output_dir.resolve()}")
        self._verbose(f"Include third-party: {self.config.include_third_party}")
        if self.config.scope_hosts:
            print(
                f"{Colors.BLUE}[i] Additional scope hosts: {', '.join(sorted(self.config.scope_hosts))}{Colors.RESET}"
            )
        if self.config.exclude_hosts:
            print(f"{Colors.YELLOW}[i] Excluded hosts: {', '.join(sorted(self.config.exclude_hosts))}{Colors.RESET}")
        if self.config.proxy:
            print(f"{Colors.BLUE}[i] Proxy Active: {self.config.proxy}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[i] No Proxy Configured (Direct Connection){Colors.RESET}")
        print(
            f"{Colors.BLUE}[i] Network: timeout={self.config.timeout}s, retries={self.config.retries}, "
            f"delay={self.config.delay}s, max_file_size={self.config.max_file_size} bytes{Colors.RESET}"
        )

    @staticmethod
    def _extract_base_domain(url: str) -> str:
        parsed = urlparse(url)
        return normalize_host(parsed.hostname or parsed.netloc)

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = normalize_host(parsed.hostname or parsed.netloc)
        if any(host_matches(domain, excluded_host) for excluded_host in self.config.exclude_hosts):
            return False
        if host_matches(domain, self.base_domain):
            return True
        return any(host_matches(domain, scope_host) for scope_host in self.config.scope_hosts)

    def _fetch_initial_html(self) -> str | None:
        try:
            response = self.session.request(
                self.target.method,
                self.target.url,
                data=self.target.body or None,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            if self._response_exceeds_limit(response):
                print(f"{Colors.RED}[-] Target HTML exceeds max file size limit.{Colors.RESET}")
                return None
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
            if not script.get("src"):
                content = script.string or script.get_text()
                for reference in extract_script_references(content):
                    js_urls.add(urljoin(self.target.url, reference))
        return js_urls

    def _filter_script_urls(self, urls: set[str]) -> tuple[set[str], set[str]]:
        selected: set[str] = set()
        skipped: set[str] = set()
        self.scope_decisions = []

        for script_url in urls:
            decision = self._scope_decision(script_url)
            self.scope_decisions.append(decision)
            if decision["selected"]:
                selected.add(script_url)
            else:
                skipped.add(script_url)

        return selected, skipped

    def _scope_decision(self, script_url: str) -> dict[str, Any]:
        parsed = urlparse(script_url)
        domain = normalize_host(parsed.hostname or parsed.netloc)
        decision: dict[str, Any] = {
            "url": script_url,
            "host": domain,
            "selected": False,
            "reason": "out_of_scope_third_party",
            "matched_host": None,
        }

        excluded_host = self._matching_host(domain, self.config.exclude_hosts)
        if excluded_host:
            decision["reason"] = "excluded_host"
            decision["matched_host"] = excluded_host
            return decision

        if host_matches(domain, self.base_domain):
            decision["selected"] = True
            decision["reason"] = "base_domain"
            decision["matched_host"] = self.base_domain
            return decision

        scope_host = self._matching_host(domain, self.config.scope_hosts)
        if scope_host:
            decision["selected"] = True
            decision["reason"] = "scope_host"
            decision["matched_host"] = scope_host
            return decision

        if self.config.include_third_party:
            decision["selected"] = True
            decision["reason"] = "include_third_party"

        return decision

    @staticmethod
    def _matching_host(domain: str, candidates: frozenset[str]) -> str | None:
        for candidate in sorted(candidates):
            if host_matches(domain, candidate):
                return candidate
        return None

    def _process_inline_scripts(self, soup: BeautifulSoup, html_content: str) -> None:
        inline_dir = self.config.output_dir / "inline_scripts"
        processed_hashes: set[str] = set()
        count = 0

        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            content = script.string or script.get_text()
            if content:
                if self._handle_inline_content(content, inline_dir, processed_hashes):
                    count += 1

        if count:
            return

        for raw_content in self._regex_inline_scripts(html_content):
            self._handle_inline_content(raw_content, inline_dir, processed_hashes)

    @staticmethod
    def _regex_inline_scripts(html_content: str) -> list[str]:
        import re

        return re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)

    def _handle_inline_content(self, content: str, output_dir: Path, hashes: set[str]) -> bool:
        clean_content = content.strip()
        if len(clean_content) < 10:
            return False

        content_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()
        if content_hash in hashes:
            return False
        hashes.add(content_hash)

        file_hash = hashlib.md5(clean_content.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        filename = f"inline_{file_hash}.js"
        print(f"    {Colors.BLUE}-> Processing Inline Script ({len(clean_content)} bytes){Colors.RESET}")
        self.inline_scripts_processed += 1
        self.scripts_processed += 1
        self.processed_scripts.append({"kind": "inline", "status": "processed", "label": filename})

        if "%7B" in clean_content[:100]:
            decoded = unquote(clean_content)
            decoded_name = f"{filename}_decoded.js"
            write_text(output_dir / decoded_name, decoded)
            self._beautify_and_scan(f"Inline (Decoded): {filename}", decoded, output_dir, decoded_name)

        self._beautify_and_scan(f"Inline: {filename}", clean_content, output_dir, filename)
        return True

    def _process_single_external_js(self, js_url: str) -> None:
        print(f"{Colors.CYAN}[*] Fetching: {js_url}{Colors.RESET}")
        record: dict[str, Any] = {"kind": "external", "url": js_url, "status": "pending", "source_map_url": None}
        try:
            self._delay_if_needed()
            response = self.session.get(js_url, timeout=self.config.timeout)
            if response.status_code != 200:
                print(f"    {Colors.RED}[-] Failed. Status: {response.status_code}{Colors.RESET}")
                record["status"] = "http_error"
                record["status_code"] = response.status_code
                self.processed_scripts.append(record)
                return
            if self._response_exceeds_limit(response):
                print(f"    {Colors.YELLOW}[-] Skipped. Response exceeds max file size limit.{Colors.RESET}")
                record["status"] = "skipped_oversize"
                self.processed_scripts.append(record)
                return
        except requests.RequestException as exc:
            print(f"    {Colors.RED}[-] Error processing {js_url}: {exc}{Colors.RESET}")
            record["status"] = "request_error"
            record["error"] = str(exc)
            self.processed_scripts.append(record)
            return

        compiled_dir = self.config.output_dir / "compiled"
        sourcemap_dir = self.config.output_dir / "source_maps"
        map_urls = source_map_candidates(js_url, response.text, response.headers)
        record["source_map_candidates"] = map_urls
        record["source_map_url"] = map_urls[0] if map_urls else None
        if map_urls:
            self._verbose(f"Source-map candidates for {js_url}: {', '.join(map_urls)}")
        extracted_map_url = self._extract_first_sourcemap(map_urls, sourcemap_dir)

        if extracted_map_url:
            self.source_maps_found += 1
            self.scripts_processed += 1
            record["source_map_url"] = extracted_map_url
            record["status"] = "sourcemap_extracted"
            self.processed_scripts.append(record)
            return

        filename = Path(urlparse(js_url).path).name or f"script_{hashlib.sha1(js_url.encode()).hexdigest()[:8]}.js"
        if not filename.endswith(".js"):
            filename = f"{filename}.js"
        safe_filename = unique_filename(compiled_dir, filename)
        self._beautify_and_scan(f"Compiled: {safe_filename}", response.text, compiled_dir, safe_filename)
        self.beautified_files += 1
        self.scripts_processed += 1
        record["status"] = "beautified_fallback"
        self.processed_scripts.append(record)

    def _extract_first_sourcemap(self, map_urls: list[str], output_base: Path) -> str | None:
        for map_url in map_urls:
            if self._can_process_url(map_url) and self._extract_sourcemap(map_url, output_base):
                return map_url
        return None

    def _extract_sourcemap(self, map_url: str, output_base: Path) -> bool:
        try:
            self._delay_if_needed()
            response = self.session.get(map_url, timeout=self.config.timeout)
            if response.status_code != 200:
                print(f"    {Colors.YELLOW}[-] Map file not reachable ({response.status_code}){Colors.RESET}")
                return False
            if self._response_exceeds_limit(response):
                print(f"    {Colors.YELLOW}[!] Source Map exceeds max file size limit.{Colors.RESET}")
                return False
            map_json = response.json()
        except (requests.RequestException, ValueError) as exc:
            print(f"    {Colors.YELLOW}[!] Source Map processing error: {exc}{Colors.RESET}")
            return False

        if not isinstance(map_json, dict):
            print(f"    {Colors.YELLOW}[!] Source Map payload is not an object.{Colors.RESET}")
            return False

        source_entries, names = extract_sourcemap_entries(map_json)
        sources = [entry.path for entry in source_entries]
        self._write_sourcemap_metadata(output_base, map_url, sources, names)
        if not source_entries:
            print(f"    {Colors.YELLOW}[!] Source Map does not list source files. Saved metadata only.{Colors.RESET}")
            return False

        print(f"    {Colors.GREEN}[+] Extracting {len(source_entries)} source files...{Colors.RESET}")
        files_extracted = 0
        missing_content = 0
        for entry in source_entries:
            content = entry.content
            if content is None:
                missing_content += 1
                content = self._fetch_sourcemap_source(map_url, entry.path)
            if content is None:
                continue

            safe_path = safe_source_path(entry.path)
            full_path = output_base / safe_path
            write_text(full_path, content)
            self._beautify_and_scan(f"SourceMap: {safe_path}", content, full_path.parent, full_path.name)
            files_extracted += 1

        if missing_content and files_extracted == 0:
            print(f"    {Colors.YELLOW}[!] Map 'sourcesContent' unavailable. Saved metadata only.{Colors.RESET}")
        return files_extracted > 0

    def _fetch_sourcemap_source(self, map_url: str, source_path: str) -> str | None:
        source_url = resolve_source_url(map_url, source_path)
        if not source_url or not self._can_process_url(source_url):
            return None

        try:
            self._delay_if_needed()
            response = self.session.get(source_url, timeout=self.config.timeout)
            if response.status_code != 200 or self._response_exceeds_limit(response):
                return None
            return response.text
        except requests.RequestException:
            return None

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
        output_path = output_dir / filename
        self._record_secret_findings(SecretScanner.scan(formatted, label), output_path)
        self._scan_endpoints(formatted, label)

    @staticmethod
    def _beautify(content: str) -> str:
        if len(content) >= 2_500_000:
            return content
        try:
            return str(jsbeautifier.beautify(content))
        except (TypeError, ValueError):
            return content

    def _record_secret_findings(self, findings: list[SecretFinding], output_path: Path) -> None:
        records: list[dict[str, Any]] = []
        for finding in findings:
            print(f"       {Colors.RED}{Colors.BOLD}{finding.header}{Colors.RESET}")
            record = {
                "type": "secret",
                "pattern": finding.name,
                "confidence": "pattern-match",
                "label": finding.label,
                "path": self.relative_output(output_path),
                "line_number": finding.line_number,
                "line_excerpt": finding.line_excerpt,
            }
            records.append(record)
            self.secret_records.append(record)
        self.reporter.append_secret_findings(findings)
        self.reporter.append_secret_export(records)

    def _scan_endpoints(self, content: str, label: str) -> None:
        findings = EndpointExtractor.extract(content)
        if not findings.has_findings:
            return

        for block in findings.heuristic_rpc:
            self.clean_rpc_names.update(EndpointExtractor.extract_rpc_names(block))

        self.all_discovered_endpoints.update(findings.standard_endpoints)
        self.normalized_endpoints.update(findings.normalized_endpoints)
        self.reporter.append_endpoint_findings(label, findings)
        self.reporter.append_endpoint_export(label, findings)

    def _can_process_url(self, url: str) -> bool:
        if self._is_excluded_url(url):
            return False
        return self.config.include_third_party or self._is_in_scope(url)

    def _is_excluded_url(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = normalize_host(parsed.hostname or parsed.netloc)
        return any(host_matches(domain, excluded_host) for excluded_host in self.config.exclude_hosts)

    def _delay_if_needed(self) -> None:
        if self.config.delay > 0:
            time.sleep(self.config.delay)

    def _verbose(self, message: str) -> None:
        if self.config.verbose:
            print(f"{Colors.CYAN}[v] {message}{Colors.RESET}")

    def _response_exceeds_limit(self, response: requests.Response) -> bool:
        if self.config.max_file_size <= 0:
            return False

        content_length = response.headers.get("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > self.config.max_file_size:
            return True

        content = getattr(response, "content", None)
        if isinstance(content, bytes):
            return len(content) > self.config.max_file_size

        return len(response.text.encode("utf-8")) > self.config.max_file_size

    def _final_status(self) -> str:
        if self.scripts_processed == 0:
            return "no_scripts_found"
        if self.source_maps_found:
            return "sourcemaps_found"
        return "beautified_only"

    def _build_summary(self, status: str) -> dict[str, Any]:
        files_written = self._collect_output_files()
        if "summary.json" not in files_written:
            files_written.append("summary.json")
        if "artifact_manifest.json" not in files_written:
            files_written.append("artifact_manifest.json")

        return {
            "target": {
                "url": self.target.url,
                "method": self.target.method,
                "base_domain": self.base_domain,
            },
            "status": status,
            "proxy_enabled": self.config.proxy is not None,
            "include_third_party": self.config.include_third_party,
            "scope_hosts": sorted(self.config.scope_hosts),
            "exclude_hosts": sorted(self.config.exclude_hosts),
            "scope_report": "scope_report.json" if (self.config.output_dir / "scope_report.json").exists() else None,
            "limits": {
                "timeout_seconds": self.config.timeout,
                "retries": self.config.retries,
                "delay_seconds": self.config.delay,
                "max_file_size_bytes": self.config.max_file_size,
            },
            "scripts": {
                "discovered": sorted(self.discovered_script_urls),
                "selected": sorted(self.in_scope_script_urls),
                "skipped_third_party": sorted(self.skipped_third_party_urls),
                "processed": self.processed_scripts,
            },
            "files_written": sorted(files_written),
            "secret_findings": self.secret_records,
            "endpoint_export": "endpoints.jsonl" if (self.config.output_dir / "endpoints.jsonl").exists() else None,
            "counts": {
                "scripts_discovered": len(self.discovered_script_urls),
                "scripts_selected": len(self.in_scope_script_urls),
                "scripts_processed": self.scripts_processed,
                "inline_scripts_processed": self.inline_scripts_processed,
                "source_maps_found": self.source_maps_found,
                "beautified_files": self.beautified_files,
                "secret_findings": len(self.secret_records),
                "unique_endpoints": len(self.all_discovered_endpoints),
                "normalized_endpoints": len(self.normalized_endpoints),
                "clean_rpc_names": len(self.clean_rpc_names),
                "skipped_third_party": len(self.skipped_third_party_urls),
            },
        }

    def _build_scope_report(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "base_domain": self.base_domain,
            "include_third_party": self.config.include_third_party,
            "scope_hosts": sorted(self.config.scope_hosts),
            "exclude_hosts": sorted(self.config.exclude_hosts),
            "decisions": sorted(self.scope_decisions, key=lambda decision: str(decision["url"])),
        }

    def _write_final_machine_reports(self, status: str) -> None:
        self.reporter.write_summary(self._build_summary(status))
        self.reporter.write_artifact_manifest(self._build_artifact_manifest())

    def _build_artifact_manifest(self) -> dict[str, Any]:
        artifacts: list[dict[str, Any]] = []
        if self.config.output_dir.exists():
            for path in sorted(self.config.output_dir.rglob("*")):
                if not path.is_file() or path.name == "artifact_manifest.json":
                    continue
                artifacts.append(
                    {
                        "path": self.relative_output(path),
                        "size_bytes": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )

        return {
            "schema_version": 1,
            "generated_by": "download_js_map_files",
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
        }

    def _collect_output_files(self) -> list[str]:
        if not self.config.output_dir.exists():
            return []
        return sorted(
            self.relative_output(path)
            for path in self.config.output_dir.rglob("*")
            if path.is_file() and path.name != "summary.json"
        )

    def relative_output(self, path: Path) -> str:
        """Return an output path relative to the configured output directory."""

        return os.fspath(path.relative_to(self.config.output_dir))
