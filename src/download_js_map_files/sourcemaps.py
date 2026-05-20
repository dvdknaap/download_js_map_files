"""Source-map detection and path sanitizing."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urljoin, urlsplit

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
