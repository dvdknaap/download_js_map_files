"""Endpoint and RPC extraction for JavaScript content."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

UUID_SEGMENT = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{8,}$")
NUMBER_SEGMENT = re.compile(r"^[0-9]+$")


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

    @property
    def normalized_endpoints(self) -> set[str]:
        """Return normalized URL-like findings for generic automation."""

        return {normalize_endpoint(endpoint) for endpoint in self.standard_endpoints}


def normalize_endpoint(value: str) -> str:
    """Return a stable endpoint shape while preserving the original finding elsewhere."""

    cleaned = value.strip().strip("\"'").rstrip(");,")
    if not cleaned:
        return cleaned

    parsed = urlsplit(cleaned)
    normalized_path = _normalize_path(parsed.path)
    normalized_query = _normalize_query(parsed.query)

    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), normalized_path or "/", normalized_query, ""))

    if parsed.netloc:
        return urlunsplit(("", parsed.netloc.lower(), normalized_path or "/", normalized_query, ""))

    if "?" in cleaned:
        path, _, query = cleaned.partition("?")
        return _join_path_query(_normalize_path(path), _normalize_query(query))

    return _normalize_path(cleaned)


def _normalize_path(path: str) -> str:
    decoded_path = unquote(path)
    leading_slash = decoded_path.startswith("/")
    segments = [segment for segment in decoded_path.split("/") if segment]
    normalized = [_normalize_segment(segment) for segment in segments]
    prefix = "/" if leading_slash else ""
    return prefix + "/".join(normalized)


def _normalize_segment(segment: str) -> str:
    if UUID_SEGMENT.fullmatch(segment):
        return "{uuid}"
    if NUMBER_SEGMENT.fullmatch(segment):
        return "{id}"
    if HEX_SEGMENT.fullmatch(segment):
        return "{hex}"
    return segment


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{key}={{value}}" for key, _value in sorted(pairs))


def _join_path_query(path: str, query: str) -> str:
    if not query:
        return path
    return f"{path}?{query}"


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
