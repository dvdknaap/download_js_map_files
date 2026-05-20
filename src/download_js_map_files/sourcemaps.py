"""Source-map detection and path sanitizing."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

SOURCE_MAPPING_PATTERN = re.compile(r"""(?://|/\*)\s*[#@]\s*sourceMappingURL=([^\s'"]+)\s*(?:\*/)?""")


@dataclass(frozen=True)
class SourceMapEntry:
    """A source file referenced by a source map."""

    path: str
    content: str | None


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


def extract_sourcemap_entries(map_json: Mapping[str, Any]) -> tuple[list[SourceMapEntry], list[str]]:
    """Return flattened source entries and names for standard or indexed source maps."""

    entries: list[SourceMapEntry] = []
    names: list[str] = []

    def collect(current_map: Mapping[str, Any]) -> None:
        sections = current_map.get("sections")
        if isinstance(sections, list):
            for section in sections:
                if not isinstance(section, dict):
                    continue
                section_map = section.get("map")
                if isinstance(section_map, dict):
                    collect(section_map)
            return

        source_root = current_map.get("sourceRoot", "")
        prefix = source_root if isinstance(source_root, str) else ""
        sources = _string_list(current_map.get("sources", []))
        contents = current_map.get("sourcesContent", [])
        names.extend(_string_list(current_map.get("names", [])))

        for index, source in enumerate(sources):
            content = None
            if isinstance(contents, list) and index < len(contents) and contents[index] is not None:
                content = str(contents[index])
            entries.append(SourceMapEntry(path=_join_source_root(prefix, source), content=content))

    collect(map_json)
    return entries, names


def resolve_source_url(map_url: str, source_path: str) -> str | None:
    """Resolve a source-map source path to a fetchable URL when possible."""

    parsed = urlsplit(source_path)
    if parsed.scheme in {"http", "https"}:
        return source_path
    if parsed.scheme or source_path.startswith(("webpack://", "ng://", "file://")):
        return None
    return urljoin(map_url, source_path)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _join_source_root(source_root: str, source: str) -> str:
    if not source_root:
        return source
    if urlsplit(source).scheme or source.startswith("/"):
        return source
    return f"{source_root.rstrip('/')}/{source.lstrip('/')}"
