"""Endpoint and RPC extraction for JavaScript content."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EndpointFindings:
    """Categorized endpoint extraction results."""

    api_paths: set[str] = field(default_factory=set)
    full_urls: set[str] = field(default_factory=set)
    ajax_calls: set[str] = field(default_factory=set)
    heuristic_rpc: set[str] = field(default_factory=set)

    @property
    def has_findings(self) -> bool:
        """Return whether any category contains results."""

        return any((self.api_paths, self.full_urls, self.ajax_calls, self.heuristic_rpc))

    @property
    def standard_endpoints(self) -> set[str]:
        """Return URL-like findings that can be aggregated globally."""

        return set().union(self.api_paths, self.full_urls, self.ajax_calls)


class EndpointExtractor:
    """Extract endpoints and RPC-like definitions from JavaScript source."""

    PATH_PATTERN = re.compile(r"""['"](\/(?:api|v[0-9]|auth|user|admin|svc|rest|graphql)[^'"\s]*)['"]""")
    URL_PATTERN = re.compile(r"""https?:\/\/[a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}[^'"\s]*""")
    AJAX_PATTERN = re.compile(r"""(?:\.get|\.post|\.put|\.delete|fetch|axios|super\.invoke)\s*\(\s*['"]([^'"]+)['"]""")
    RPC_NAME_PATTERN = re.compile(r"""(?i)(?:name|action|method|operation)\s*[:=]\s*['"]([a-zA-Z0-9_\-/]+)['"]""")
    PROXIMITY_KEYWORDS = (
        "name",
        "param",
        "params",
        "method",
        "endpoint",
        "url",
        "action",
        "invoke",
        "options",
        "query",
        "mutation",
        "operation",
        "service",
    )
    IGNORED_RPC_NAMES = {"get", "post", "utf-8", "viewport", "json", "application", "true", "false"}

    @classmethod
    def extract(cls, content: str) -> EndpointFindings:
        """Scan JavaScript content with direct regexes and proximity heuristics."""

        return EndpointFindings(
            api_paths=set(cls.PATH_PATTERN.findall(content)),
            full_urls=set(cls.URL_PATTERN.findall(content)),
            ajax_calls=set(cls.AJAX_PATTERN.findall(content)),
            heuristic_rpc=cls._scan_proximity(content),
        )

    @classmethod
    def extract_rpc_names(cls, code_block: str) -> set[str]:
        """Extract clean method names from a heuristic RPC block."""

        return {
            match for match in cls.RPC_NAME_PATTERN.findall(code_block) if match.lower() not in cls.IGNORED_RPC_NAMES
        }

    @classmethod
    def _scan_proximity(cls, content: str, window_size: int = 6, threshold: int = 3) -> set[str]:
        lines = [line.strip() for line in content.splitlines() if len(line) < 1000]
        findings: set[str] = set()

        for index in range(len(lines)):
            window = lines[index : index + window_size]
            joined_window = " ".join(window).lower()
            found_keywords = [keyword for keyword in cls.PROXIMITY_KEYWORDS if keyword in joined_window]

            if len(found_keywords) >= threshold:
                snippet = "\n".join(window)
                findings.add(f"Keys found: {', '.join(found_keywords)}\n" f"Code Block (Line {index + 1}):\n{snippet}")

        return findings
