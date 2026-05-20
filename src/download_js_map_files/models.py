"""Shared data models for scan configuration and parsed requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class ScanTarget:
    """A normalized target request for the scanner."""

    url: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass(frozen=True)
class ScannerConfig:
    """Runtime scanner settings."""

    output_dir: Path
    proxy: str | None = None
    timeout: float = 20.0
    retries: int = 3
