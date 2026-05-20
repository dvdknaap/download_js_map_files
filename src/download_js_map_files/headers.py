"""CLI header and cookie parsing helpers."""

from __future__ import annotations

from collections.abc import Mapping


def parse_header(value: str) -> tuple[str, str]:
    """Parse a CLI header value in `Name: value` format."""

    if ":" not in value:
        raise ValueError(f"Invalid header format: {value}. Use 'Name: value'.")

    name, header_value = value.split(":", 1)
    clean_name = name.strip()
    clean_value = header_value.strip()

    if not clean_name or not clean_value:
        raise ValueError(f"Invalid header format: {value}. Use 'Name: value'.")

    return clean_name, clean_value


def normalize_cookie(value: str) -> str:
    """Normalize a CLI cookie value into a cookie header fragment."""

    candidate = value.strip()
    if candidate.lower().startswith("cookie:"):
        candidate = candidate.split(":", 1)[1].strip()

    if not candidate or "=" not in candidate:
        raise ValueError(f"Invalid cookie format: {value}. Use 'name=value'.")

    return candidate


def merge_headers(
    base_headers: Mapping[str, str],
    header_values: list[str] | None,
    cookie_values: list[str] | None,
) -> dict[str, str]:
    """Merge base headers with repeatable CLI header and cookie values."""

    merged = dict(base_headers)
    header_names_by_lower = {name.lower(): name for name in merged}

    for raw_header in header_values or []:
        name, value = parse_header(raw_header)
        existing_name = header_names_by_lower.get(name.lower(), name)
        if existing_name != name and existing_name in merged:
            del merged[existing_name]
        merged[name] = value
        header_names_by_lower[name.lower()] = name

    cookie_fragments = [normalize_cookie(cookie) for cookie in cookie_values or []]
    if cookie_fragments:
        existing_cookie_name = header_names_by_lower.get("cookie", "Cookie")
        existing_cookie = merged.get(existing_cookie_name, "").strip()
        merged[existing_cookie_name] = "; ".join(
            fragment for fragment in [existing_cookie, *cookie_fragments] if fragment
        )

    return merged
