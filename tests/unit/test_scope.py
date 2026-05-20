from __future__ import annotations

import pytest

from download_js_map_files.scope import host_matches, load_host_file, normalize_host, resolve_hosts


def test_normalize_host_accepts_urls_ports_and_www() -> None:
    assert normalize_host("https://www.Example.test:8443/path") == "example.test"
    assert normalize_host("cdn.example.test:443") == "cdn.example.test"


def test_normalize_host_rejects_empty_values() -> None:
    with pytest.raises(ValueError):
        normalize_host("  ")


def test_host_file_loading_supports_comments_and_inline_comments(tmp_path) -> None:  # type: ignore[no-untyped-def]
    host_file = tmp_path / "hosts.txt"
    host_file.write_text(
        """
        # comment
        api.example.test
        https://static.example.test/assets # inline comment

        """,
        encoding="utf-8",
    )

    assert load_host_file(host_file) == {"api.example.test", "static.example.test"}


def test_resolve_hosts_combines_repeated_values_and_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    host_file = tmp_path / "hosts.txt"
    host_file.write_text("cdn.example.test\n", encoding="utf-8")

    assert resolve_hosts(["api.example.test"], [str(host_file)]) == frozenset({"api.example.test", "cdn.example.test"})


def test_host_matches_exact_hosts_and_subdomains() -> None:
    assert host_matches("assets.example.test", "example.test")
    assert host_matches("example.test", "example.test")
    assert not host_matches("example.test.evil", "example.test")
