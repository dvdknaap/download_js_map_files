from __future__ import annotations

from download_js_map_files.analysis.secrets import SecretScanner


def test_secret_scanner_finds_patterns_and_skips_huge_lines() -> None:
    content = "\n".join(
        [
            'const api_key = "abcdefghijklmnop";',
            "const aws = 'AKIAABCDEFGHIJKLMNOP';",
            "x" * 10001,
        ]
    )

    findings = SecretScanner.scan(content, "fixture.js")
    headers = [finding.header for finding in findings]

    assert any("Generic API Key" in header for header in headers)
    assert any("AWS Access Key" in header for header in headers)
    assert all(finding.line_number < 3 for finding in findings)
