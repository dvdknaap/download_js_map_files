from __future__ import annotations

import pytest

from download_js_map_files.request_parser import RequestParser


def test_parse_raw_request_preserves_method_headers_and_body(tmp_path) -> None:  # type: ignore[no-untyped-def]
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "POST /login?next=/app HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "Cookie: session=abc\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"username":"alice"}',
        encoding="utf-8",
    )

    target = RequestParser.parse(request_file, scheme="http")

    assert target.url == "http://example.test/login?next=/app"
    assert target.method == "POST"
    assert target.headers["Cookie"] == "session=abc"
    assert target.body == '{"username":"alice"}'


def test_parse_absolute_url_request_without_host(tmp_path) -> None:  # type: ignore[no-untyped-def]
    request_file = tmp_path / "request.txt"
    request_file.write_text("GET https://example.test/app HTTP/1.1\nAccept: */*\n", encoding="utf-8")

    assert RequestParser.parse(request_file).url == "https://example.test/app"


def test_parse_headers_skips_malformed_lines_and_stops_at_blank() -> None:
    headers = RequestParser._parse_headers(["Host: example.test", "Bad-Header", "", "Ignored: yes"])

    assert headers == {"Host": "example.test"}


def test_parse_errors_for_missing_or_invalid_request(tmp_path) -> None:  # type: ignore[no-untyped-def]
    empty = tmp_path / "empty.txt"
    invalid = tmp_path / "invalid.txt"
    missing_host = tmp_path / "missing_host.txt"
    empty.write_text("", encoding="utf-8")
    invalid.write_text("BROKEN\nHost: example.test\n", encoding="utf-8")
    missing_host.write_text("GET / HTTP/1.1\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        RequestParser.parse(tmp_path / "missing.txt")
    with pytest.raises(ValueError, match="empty"):
        RequestParser.parse(empty)
    with pytest.raises(ValueError, match="Invalid"):
        RequestParser.parse(invalid)
    with pytest.raises(ValueError, match="Host"):
        RequestParser.parse(missing_host)
