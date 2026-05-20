from __future__ import annotations

from pathlib import Path

from download_js_map_files.sourcemaps import (
    detect_sourcemap_url,
    fallback_sourcemap_urls,
    safe_source_path,
    source_map_candidates,
)


def test_detect_sourcemap_from_headers_and_footer() -> None:
    assert detect_sourcemap_url("https://example.test/app.js", "", {"x-sourcemap": "app.js.map"}) == (
        "https://example.test/app.js.map"
    )
    assert detect_sourcemap_url("https://example.test/static/app.js", "//# sourceMappingURL=../app.js.map", {}) == (
        "https://example.test/app.js.map"
    )
    assert (
        detect_sourcemap_url("https://example.test/app.js", "//# sourceMappingURL=data:application/json;base64,abc", {})
        is None
    )


def test_fallback_sourcemap_urls_are_bounded_to_js_siblings() -> None:
    assert fallback_sourcemap_urls("https://example.test/static/app.js?v=1") == [
        "https://example.test/static/app.js.map",
        "https://example.test/static/app.map",
    ]
    assert fallback_sourcemap_urls("https://example.test/static/app.min.js") == [
        "https://example.test/static/app.min.js.map",
        "https://example.test/static/app.js.map",
        "https://example.test/static/app.min.map",
    ]
    assert fallback_sourcemap_urls("https://example.test/static/bundle") == ["https://example.test/static/bundle.map"]


def test_source_map_candidates_prioritize_explicit_urls_and_deduplicate() -> None:
    assert source_map_candidates("https://example.test/static/app.js", "", {"SourceMap": "app.js.map"}) == [
        "https://example.test/static/app.js.map",
        "https://example.test/static/app.map",
    ]


def test_safe_source_path_strips_traversal_urls_and_empty_values() -> None:
    assert safe_source_path("webpack:///../src/auth.js") == Path("src/auth.js")
    assert safe_source_path("https://cdn.example.test/libs/app.js?cache=1") == Path("libs/app.js")
    assert safe_source_path("../../../../secret.js") == Path("secret.js")
    assert safe_source_path("..") == Path("source.js")
