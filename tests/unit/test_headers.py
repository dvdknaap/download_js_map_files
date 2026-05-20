from __future__ import annotations

import pytest

from download_js_map_files.headers import merge_headers, normalize_cookie, parse_header


def test_parse_header_accepts_name_value_pairs() -> None:
    assert parse_header("Authorization: Bearer token") == ("Authorization", "Bearer token")


def test_parse_header_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        parse_header("Authorization")
    with pytest.raises(ValueError):
        parse_header(": value")
    with pytest.raises(ValueError):
        parse_header("Name: ")


def test_normalize_cookie_accepts_cookie_fragments_and_header_style_values() -> None:
    assert normalize_cookie("session=abc") == "session=abc"
    assert normalize_cookie("Cookie: theme=dark") == "theme=dark"


def test_normalize_cookie_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        normalize_cookie("session")


def test_merge_headers_overrides_case_insensitive_names_and_appends_cookies() -> None:
    merged = merge_headers(
        {"authorization": "old", "Cookie": "existing=1"},
        ["Authorization: Bearer new", "X-Custom: yes"],
        ["session=abc", "theme=dark"],
    )

    assert "authorization" not in merged
    assert merged["Authorization"] == "Bearer new"
    assert merged["X-Custom"] == "yes"
    assert merged["Cookie"] == "existing=1; session=abc; theme=dark"
