"""Parsing for raw HTTP request files."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .models import ScanTarget


class RequestParser:
    """Parse browser/proxy raw HTTP request exports into scanner targets."""

    @staticmethod
    def parse(file_path: str | Path, scheme: str = "https") -> ScanTarget:
        """Parse a raw HTTP request file."""

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Request file not found: {path}")

        raw = path.read_text(encoding="utf-8")
        if not raw:
            raise ValueError("Request file is empty")

        header_block, body = RequestParser._split_headers_and_body(raw)
        lines = header_block.splitlines()
        if not lines:
            raise ValueError("Request file is empty")

        method, request_target = RequestParser._parse_request_line(lines[0])
        headers = RequestParser._parse_headers(lines[1:])
        url = RequestParser._build_url(request_target, headers, scheme)

        return ScanTarget(url=url, method=method, headers=headers, body=body)

    @staticmethod
    def _split_headers_and_body(raw: str) -> tuple[str, str]:
        normalized = raw.replace("\r\n", "\n")
        if "\n\n" not in normalized:
            return normalized, ""
        header_block, body = normalized.split("\n\n", 1)
        return header_block, body

    @staticmethod
    def _parse_request_line(line: str) -> tuple[str, str]:
        parts = line.strip().split()
        if len(parts) < 2:
            raise ValueError("Invalid HTTP request line")
        return parts[0].upper(), parts[1]

    @staticmethod
    def _parse_headers(lines: Iterable[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in lines:
            clean_line = line.strip()
            if not clean_line:
                break
            if ":" not in clean_line:
                continue
            key, value = clean_line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    @staticmethod
    def _build_url(request_target: str, headers: dict[str, str], scheme: str) -> str:
        parsed_target = urlsplit(request_target)
        if parsed_target.scheme and parsed_target.netloc:
            return request_target

        host = next((value for key, value in headers.items() if key.lower() == "host"), "")
        if not host:
            raise ValueError("Host header missing in request file")

        path = request_target if request_target.startswith("/") else f"/{request_target}"
        return f"{scheme}://{host}{path}"
