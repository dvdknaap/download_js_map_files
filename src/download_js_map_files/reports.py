"""Output report writing."""

from __future__ import annotations

from pathlib import Path

from .analysis.endpoints import EndpointFindings
from .analysis.secrets import SecretFinding
from .io import append_text, write_text

SENSITIVE_VARIABLE_NAMES = ("password", "passwd", "secret", "token", "apikey", "auth", "credential", "private")


class ReportWriter:
    """Persist scanner reports and aggregate lists."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def write_url_list(self, urls: set[str]) -> None:
        """Write discovered JavaScript URLs."""

        write_text(self.output_dir / "urls.txt", "".join(f"{url}\n" for url in sorted(urls)))

    def append_secret_findings(self, findings: list[SecretFinding]) -> None:
        """Append secret findings to the findings report."""

        for finding in findings:
            header = finding.header
            append_text(
                self.output_dir / "findings.txt",
                f"\n{header}\n{finding.line_excerpt}\n{'-' * len(header)}\n",
            )

    def append_suspicious_variables(self, names: list[str], origin: str) -> list[str]:
        """Record suspicious source-map variable names and return the matches."""

        suspicious = [name for name in names if any(pattern in name.lower() for pattern in SENSITIVE_VARIABLE_NAMES)]
        if not suspicious:
            return []

        header = f"--- [!] SUSPICIOUS VARIABLES IN MAP: {Path(origin).name} ---"
        append_text(
            self.output_dir / "findings.txt",
            f"\n{header}\nMatches: {', '.join(suspicious)}\n{'-' * len(header)}\n",
        )
        return suspicious

    def append_endpoint_findings(self, label: str, findings: EndpointFindings) -> None:
        """Append categorized endpoint findings for a single content block."""

        if not findings.has_findings:
            return

        sections: list[str] = []
        if findings.heuristic_rpc:
            sections.append("\n--- HEURISTIC RPC/API CLUSTERS ---")
            sections.extend(f"{block}\n----------------" for block in sorted(findings.heuristic_rpc))

        if findings.api_paths:
            sections.append("\n--- API Paths ---")
            sections.extend(f"  > {match}" for match in sorted(findings.api_paths))

        if findings.ajax_calls:
            sections.append("\n--- AJAX Calls ---")
            sections.extend(f"  > {match}" for match in sorted(findings.ajax_calls))

        if findings.full_urls:
            sections.append("\n--- Full URLs ---")
            sections.extend(f"  > {match}" for match in sorted(findings.full_urls))

        append_text(
            self.output_dir / "discovered_endpoints.txt",
            f"\n\n=== Endpoints/Signatures in {label} ===\n" + "\n".join(sections),
        )

    def write_aggregated_endpoints(self, endpoints: set[str], rpc_names: set[str]) -> None:
        """Write unique endpoint and RPC wordlists."""

        if endpoints:
            write_text(self.output_dir / "all_endpoints_unique.txt", "".join(f"{item}\n" for item in sorted(endpoints)))

        if rpc_names:
            write_text(self.output_dir / "clean_rpc_endpoints.txt", "".join(f"{item}\n" for item in sorted(rpc_names)))
