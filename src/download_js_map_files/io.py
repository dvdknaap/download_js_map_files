"""File-system helpers for scanner output."""

from __future__ import annotations

import re
from pathlib import Path


def ensure_directory(path: Path) -> None:
    """Create a directory and its parents if needed."""

    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text, creating parent directories first."""

    ensure_directory(path.parent)
    path.write_text(content, encoding="utf-8")


def append_text(path: Path, content: str) -> None:
    """Append UTF-8 text, creating parent directories first."""

    ensure_directory(path.parent)
    with path.open("a", encoding="utf-8") as file_obj:
        file_obj.write(content)


def unique_filename(directory: Path, filename: str) -> str:
    """Return a sanitized filename that does not already exist in a directory."""

    raw_base, raw_ext = Path(filename).stem, Path(filename).suffix
    base = re.sub(r"[^\w\-_.]", "_", raw_base).strip("._") or "script"
    ext = raw_ext if raw_ext else ".js"
    candidate = f"{base}{ext}"
    counter = 1

    while (directory / candidate).exists():
        candidate = f"{base}_{counter}{ext}"
        counter += 1

    return candidate
