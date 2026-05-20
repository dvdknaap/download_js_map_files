"""Script reference extraction helpers."""

from __future__ import annotations

import re

SCRIPT_REFERENCE_PATTERN = re.compile(
    r"""(?P<quote>['"])(?P<value>(?!data:|blob:|mailto:)[^'"]+?\.(?:mjs|js)(?:\?[^'"]*)?)(?P=quote)"""
)


def extract_script_references(content: str) -> set[str]:
    """Extract JavaScript file references from inline loader code."""

    references: set[str] = set()
    for match in SCRIPT_REFERENCE_PATTERN.finditer(content):
        value = match.group("value").strip()
        if value:
            references.add(value)
    return references
