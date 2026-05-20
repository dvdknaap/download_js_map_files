"""Host scope parsing and matching helpers."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit


def normalize_host(value: str) -> str:
    """Normalize a host, URL, or host:port value for scope matching."""

    candidate = value.strip()
    if not candidate:
        raise ValueError("Scope host values cannot be empty")

    if "://" in candidate:
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
    else:
        host = urlsplit(f"//{candidate.split('/', 1)[0]}").hostname or ""

    normalized = host.lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    if not normalized:
        raise ValueError(f"Invalid scope host value: {value}")

    return normalized


def load_host_file(file_path: str | Path) -> set[str]:
    """Load newline-separated hosts from a file, ignoring blanks and comments."""

    path = Path(file_path)
    hosts: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate = line.split("#", 1)[0].strip()
        if candidate:
            hosts.add(normalize_host(candidate))
    return hosts


def resolve_hosts(values: list[str] | None, files: list[str] | None) -> frozenset[str]:
    """Resolve repeated host arguments and host-list files into normalized hosts."""

    hosts = {normalize_host(value) for value in values or []}
    for file_path in files or []:
        hosts.update(load_host_file(file_path))
    return frozenset(hosts)


def host_matches(host: str, scope_host: str) -> bool:
    """Return whether a host matches a configured scope host or subdomain."""

    normalized_host = normalize_host(host)
    return normalized_host == scope_host or normalized_host.endswith(f".{scope_host}")
