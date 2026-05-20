from __future__ import annotations

from download_js_map_files.http import create_session


def test_create_session_applies_headers_proxy_and_disables_verify() -> None:
    session = create_session({"User-Agent": "pytest"}, "http://127.0.0.1:8080", retries=1)

    assert session.headers["User-Agent"] == "pytest"
    assert session.proxies == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    assert session.verify is False
