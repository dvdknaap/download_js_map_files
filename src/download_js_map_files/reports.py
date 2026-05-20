"""Output report writing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analysis.endpoints import EndpointFindings, normalize_endpoint
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

    def append_secret_export(self, records: list[dict[str, Any]]) -> None:
        """Append secret findings as JSON lines for automation."""

        if records:
            append_text(
                self.output_dir / "findings.jsonl",
                "".join(f"{json.dumps(record, sort_keys=True)}\n" for record in records),
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

    def append_endpoint_export(self, label: str, findings: EndpointFindings) -> None:
        """Append endpoint findings as JSON lines for automation."""

        records: list[dict[str, str]] = []
        records.extend(self._endpoint_record(label, "api_path", item) for item in sorted(findings.api_paths))
        records.extend(self._endpoint_record(label, "ajax_call", item) for item in sorted(findings.ajax_calls))
        records.extend(self._endpoint_record(label, "full_url", item) for item in sorted(findings.full_urls))

        if records:
            append_text(
                self.output_dir / "endpoints.jsonl",
                "".join(f"{json.dumps(record, sort_keys=True)}\n" for record in records),
            )

    @staticmethod
    def _endpoint_record(label: str, finding_type: str, value: str) -> dict[str, str]:
        return {
            "source": label,
            "type": finding_type,
            "value": value,
            "normalized_value": normalize_endpoint(value),
        }

    def write_aggregated_endpoints(
        self,
        endpoints: set[str],
        rpc_names: set[str],
        normalized_endpoints: set[str],
    ) -> None:
        """Write unique endpoint and RPC wordlists."""

        if endpoints:
            write_text(self.output_dir / "all_endpoints_unique.txt", "".join(f"{item}\n" for item in sorted(endpoints)))

        if normalized_endpoints:
            write_text(
                self.output_dir / "all_endpoints_normalized.txt",
                "".join(f"{item}\n" for item in sorted(normalized_endpoints)),
            )

        if rpc_names:
            write_text(self.output_dir / "clean_rpc_endpoints.txt", "".join(f"{item}\n" for item in sorted(rpc_names)))

    def write_skipped_third_party(self, urls: set[str]) -> None:
        """Write skipped third-party script URLs for operator review."""

        if urls:
            write_text(self.output_dir / "skipped_third_party_urls.txt", "".join(f"{url}\n" for url in sorted(urls)))

    def write_summary(self, summary: dict[str, Any]) -> None:
        """Write the machine-readable scan summary."""

        write_text(self.output_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")

    def write_artifact_manifest(self, manifest: dict[str, Any]) -> None:
        """Write file hashes for generated artifacts."""

        write_text(self.output_dir / "artifact_manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    def write_scope_report(self, report: dict[str, Any]) -> None:
        """Write script scope decisions for review."""

        write_text(self.output_dir / "scope_report.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
