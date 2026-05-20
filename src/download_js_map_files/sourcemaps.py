"""Source-map detection and path sanitizing."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

SOURCE_MAPPING_PATTERN = re.compile(r"""(?://|/\*)\s*[#@]\s*sourceMappingURL=([^\s'"]+)\s*(?:\*/)?""")


def detect_sourcemap_url(js_url: str, content: str, headers: Mapping[str, object]) -> str | None:
    """Detect a source-map URL from response headers or JS footer comments."""

    for key, value in headers.items():
        if key.lower() in {"sourcemap", "x-sourcemap"}:
            return urljoin(js_url, str(value))

    match = SOURCE_MAPPING_PATTERN.search(content)
    if not match:
        return None

    candidate = match.group(1).strip()
    if candidate.startswith(("data:", "blob:")):
        return None

    return cast(str, urljoin(js_url, candidate))


def fallback_sourcemap_urls(js_url: str) -> list[str]:
    """Return bounded source-map URL candidates next to a JavaScript URL."""

    parsed = urlsplit(js_url)
    path = parsed.path
    if not path:
        return []

    candidates: list[str] = []

    def add(candidate_path: str) -> None:
        candidate = urlunsplit((parsed.scheme, parsed.netloc, candidate_path, "", ""))
        if candidate not in candidates:
            candidates.append(candidate)

    lower_path = path.lower()
    if not lower_path.endswith(".map"):
        add(f"{path}.map")

    if lower_path.endswith(".min.js"):
        add(f"{path[:-7]}.js.map")

    if lower_path.endswith(".js"):
        add(f"{path[:-3]}.map")

    return candidates


def source_map_candidates(js_url: str, content: str, headers: Mapping[str, object]) -> list[str]:
    """Return explicit and fallback source-map candidates in priority order."""

    candidates: list[str] = []
    explicit_url = detect_sourcemap_url(js_url, content, headers)
    if explicit_url:
        candidates.append(explicit_url)

    for fallback_url in fallback_sourcemap_urls(js_url):
        if fallback_url not in candidates:
            candidates.append(fallback_url)

    return candidates


def safe_source_path(source_path: str) -> Path:
    """Convert a source-map source path into a safe relative output path."""

    source = unquote(source_path).split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    parsed = urlsplit(source)

    if parsed.scheme:
        source = parsed.path or parsed.netloc

    source = source.removeprefix("webpack:///").removeprefix("webpack://")
    cleaned_parts = [part for part in source.split("/") if part not in {"", ".", ".."}]
    sanitized_parts = [re.sub(r"[^\w\-_.]", "_", part).strip("._") for part in cleaned_parts]
    safe_parts = [part for part in sanitized_parts if part]

    if not safe_parts:
        return Path("source.js")

    return Path(*safe_parts)
