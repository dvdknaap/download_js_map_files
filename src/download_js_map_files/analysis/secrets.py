"""Secret-pattern scanning for JavaScript content."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    """A single secret-pattern match."""

    name: str
    label: str
    line_number: int
    line_excerpt: str

    @property
    def header(self) -> str:
        """Human-readable finding header."""

        return f"--- [!] {self.name} FOUND IN {self.label} (Line {self.line_number}) ---"


class SecretScanner:
    """Scan source text for common client-side credential leaks."""

    SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
        "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Generic API Key": re.compile(r"""(?i)(api_key|apikey|secret|token|auth)[\s]*[:=][\s]*['"][\w\-]{10,}['"]"""),
        "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "JWT Token": re.compile(r"eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"),
        "Private Key": re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "Firebase URL": re.compile(r"[\w-]+\.firebaseio\.com"),
        "Slack Token": re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"),
        "GitHub Token": re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),
        "Heroku API Key": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    }

    @classmethod
    def scan(cls, content: str, label: str) -> list[SecretFinding]:
        """Return all secret-pattern findings for a content block."""

        findings: list[SecretFinding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if len(line) > 10_000:
                continue

            for name, pattern in cls.SECRET_PATTERNS.items():
                if pattern.search(line):
                    findings.append(
                        SecretFinding(
                            name=name,
                            label=label,
                            line_number=line_number,
                            line_excerpt=line.strip()[:200],
                        )
                    )

        return findings
