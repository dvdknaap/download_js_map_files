from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import requests
from bs4 import BeautifulSoup

from download_js_map_files.models import ScannerConfig, ScanTarget
from download_js_map_files.recon import JavaScriptRecon

# pylint: disable=protected-access


def write_fixture_site(root: Path) -> None:
    static = root / "static"
    static.mkdir()
    (root / "index.html").write_text(
        """
        <html>
          <head><title>Recon Fixture</title></head>
          <body>
            <script>
              const api_key = "abcdefghijklmnopqrstuvwxyz";
              fetch("/api/inline");
            </script>
            <script>%7B%22token%22%3A%22abcdefghijklmnopqrstuvwxyz%22%7D</script>
            <script src="/static/app.js"></script>
            <script data-src="/static/fallback.min.js"></script>
            <script src="https://cdn.example.test/out-of-scope.js"></script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )
    (static / "app.js").write_text('console.log("mapped");\n//# sourceMappingURL=app.js.map', encoding="utf-8")
    (static / "app.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["webpack:///../src/auth.js"],
                "names": ["accessToken", "displayName"],
                "sourcesContent": [
                    """
                    const service = {
                      name: "AuthLogin",
                      params: ["email"],
                      endpoint: "/api/source",
                      method: "POST",
                      url: "/v1/source"
                    };
                    fetch("/api/source-fetch");
                    const github = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
                    """
                ],
            }
        ),
        encoding="utf-8",
    )
    (static / "fallback.min.js").write_text(
        'const svc={name:"FallbackAction",params:{},endpoint:"/rest/fallback",method:"GET"};fetch("/api/fallback");',
        encoding="utf-8",
    )


def test_recon_processes_inline_external_sourcemap_and_reports(  # type: ignore[no-untyped-def]
    tmp_path,
    serve_directory,
) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    write_fixture_site(site_root)
    output_dir = tmp_path / "out"

    with serve_directory(site_root) as base_url:
        recon = JavaScriptRecon(
            ScanTarget(url=f"{base_url}/index.html"),
            ScannerConfig(output_dir=output_dir, proxy=None, timeout=5),
        )
        result = recon.run()

    urls = (output_dir / "urls.txt").read_text(encoding="utf-8")
    endpoints = (output_dir / "all_endpoints_unique.txt").read_text(encoding="utf-8")
    normalized_endpoints = (output_dir / "all_endpoints_normalized.txt").read_text(encoding="utf-8")
    endpoint_export = (output_dir / "endpoints.jsonl").read_text(encoding="utf-8")
    secret_export = [
        json.loads(line) for line in (output_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    findings = (output_dir / "findings.txt").read_text(encoding="utf-8")
    rpc_names = (output_dir / "clean_rpc_endpoints.txt").read_text(encoding="utf-8")
    skipped = (output_dir / "skipped_third_party_urls.txt").read_text(encoding="utf-8")
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))

    assert result.status == "sourcemaps_found"
    assert "out-of-scope" not in urls
    assert "out-of-scope" in skipped
    assert "/static/app.js" in urls
    assert (output_dir / "source_maps" / "src" / "auth.js").exists()
    assert (output_dir / "compiled" / "fallback.min.js").exists()
    assert list((output_dir / "inline_scripts").glob("inline_*.js"))
    assert "/api/inline" in endpoints
    assert "/api/inline" in normalized_endpoints
    assert "/api/source-fetch" in endpoints
    assert "/api/fallback" in endpoints
    assert "Generic API Key" in findings
    assert "GitHub Token" in findings
    assert "SUSPICIOUS VARIABLES" in findings
    assert "/api/source-fetch" in endpoint_export
    assert any(record["type"] == "secret" and record["pattern"] == "Generic API Key" for record in secret_export)
    assert "AuthLogin" in rpc_names
    assert "FallbackAction" in rpc_names
    assert summary["status"] == "sourcemaps_found"
    assert summary["endpoint_export"] == "endpoints.jsonl"
    assert summary["counts"]["skipped_third_party"] == 1
    assert summary["counts"]["normalized_endpoints"] >= 1
    assert summary["secret_findings"][0]["path"]
    assert recon.relative_output(output_dir / "urls.txt") == "urls.txt"


def test_recon_writes_manifest_and_scope_report(  # type: ignore[no-untyped-def]
    tmp_path,
    serve_directory,
) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    write_fixture_site(site_root)
    output_dir = tmp_path / "out"

    with serve_directory(site_root) as base_url:
        JavaScriptRecon(
            ScanTarget(url=f"{base_url}/index.html"),
            ScannerConfig(output_dir=output_dir, proxy=None, timeout=5),
        ).run()

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "artifact_manifest.json").read_text(encoding="utf-8"))
    manifest_artifacts = {artifact["path"]: artifact for artifact in manifest["artifacts"]}
    scope_report = json.loads((output_dir / "scope_report.json").read_text(encoding="utf-8"))
    scope_decisions = {decision["url"]: decision for decision in scope_report["decisions"]}

    assert summary["scope_report"] == "scope_report.json"
    assert "artifact_manifest.json" in summary["files_written"]
    assert manifest["schema_version"] == 1
    assert manifest["artifact_count"] == len(manifest["artifacts"])
    assert "summary.json" in manifest_artifacts
    assert "artifact_manifest.json" not in manifest_artifacts
    assert manifest_artifacts["summary.json"]["size_bytes"] == (output_dir / "summary.json").stat().st_size
    assert len(manifest_artifacts["summary.json"]["sha256"]) == 64
    assert scope_decisions["https://cdn.example.test/out-of-scope.js"]["reason"] == "out_of_scope_third_party"
    assert scope_decisions["https://cdn.example.test/out-of-scope.js"]["selected"] is False


def test_recon_handles_missing_initial_html(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = JavaScriptRecon(
        ScanTarget(url="http://127.0.0.1:1/missing"),
        ScannerConfig(output_dir=tmp_path / "out", proxy=None, timeout=0.01, retries=0),
    )

    result = recon.run()

    assert result.fatal is True
    assert result.status == "target_fetch_failed"
    assert (tmp_path / "out" / "summary.json").exists()
    assert (tmp_path / "out" / "artifact_manifest.json").exists()
    assert not (tmp_path / "out" / "urls.txt").exists()


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        json_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._json_data = json_data or {}
        self._json_error = json_error

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError("boom")

    def json(self) -> dict[str, Any]:
        if self._json_error:
            raise self._json_error
        return self._json_data


class FakeGetSession:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response

    def get(self, *_args: object, **_kwargs: object) -> FakeResponse:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class SequenceGetSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def get(self, url: str, *_args: object, **_kwargs: object) -> FakeResponse:
        self.urls.append(url)
        return self.responses.pop(0)


def make_recon(tmp_path, proxy: str | None = None) -> JavaScriptRecon:  # type: ignore[no-untyped-def]
    return JavaScriptRecon(
        ScanTarget(url="https://www.example.test/index.html"),
        ScannerConfig(output_dir=tmp_path / "out", proxy=proxy, timeout=1, retries=0),
    )


def test_recon_proxy_scope_inline_and_beautify_branches(  # type: ignore[no-untyped-def]
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recon = make_recon(tmp_path, proxy="http://127.0.0.1:8080")
    recon._print_startup()
    assert recon._extract_base_domain("https://www.example.test/app") == "example.test"
    assert recon._is_in_scope("https://assets.example.test/app.js")
    assert not recon._can_process_url("https://cdn.other.test/app.js")

    soup = BeautifulSoup("<main>No scripts parsed here</main>", "html.parser")
    recon._process_inline_scripts(soup, '<script>fetch("/api/regex-inline")</script>')
    assert recon._handle_inline_content("tiny", tmp_path / "out" / "inline_scripts", set()) is False
    hashes: set[str] = set()
    assert recon._handle_inline_content('fetch("/api/dupe")', tmp_path / "out" / "inline_scripts", hashes) is True
    assert recon._handle_inline_content('fetch("/api/dupe")', tmp_path / "out" / "inline_scripts", hashes) is False

    assert recon._beautify("x" * 2_500_000) == "x" * 2_500_000
    monkeypatch.setattr(
        "download_js_map_files.recon.jsbeautifier.beautify", lambda _content: (_ for _ in ()).throw(ValueError)
    )
    assert recon._beautify("const a=1") == "const a=1"


def test_recon_external_error_and_fallback_branches(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = make_recon(tmp_path)
    recon.session = FakeGetSession(requests.ConnectionError("nope"))  # type: ignore[assignment]
    recon._process_single_external_js("https://example.test/broken.js")

    recon.session = FakeGetSession(FakeResponse(status_code=404))  # type: ignore[assignment]
    recon._process_single_external_js("https://example.test/missing.js")

    recon.session = FakeGetSession(FakeResponse(text='fetch("/api/no-extension")'))  # type: ignore[assignment]
    recon._process_single_external_js("https://example.test/static/asset")

    assert (tmp_path / "out" / "compiled" / "asset.js").exists()


def test_recon_automatically_tries_sourcemap_fallback_candidates(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = make_recon(tmp_path)
    session = SequenceGetSession(
        [
            FakeResponse(text='console.log("hintless");'),
            FakeResponse(status_code=404),
            FakeResponse(
                json_data={
                    "sources": ["webpack:///src/hintless.js"],
                    "names": [],
                    "sourcesContent": ['fetch("/api/hintless-map");'],
                }
            ),
        ]
    )
    recon.session = session  # type: ignore[assignment]

    recon._process_single_external_js("https://example.test/static/hintless.js")

    assert session.urls == [
        "https://example.test/static/hintless.js",
        "https://example.test/static/hintless.js.map",
        "https://example.test/static/hintless.map",
    ]
    assert (tmp_path / "out" / "source_maps" / "src" / "hintless.js").exists()
    assert not (tmp_path / "out" / "compiled" / "hintless.js").exists()
    assert recon.processed_scripts[-1]["status"] == "sourcemap_extracted"


def test_recon_extracts_indexed_sourcemaps(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = make_recon(tmp_path)
    recon.session = SequenceGetSession(
        [
            FakeResponse(text='console.log("indexed");\n//# sourceMappingURL=indexed.js.map'),
            FakeResponse(
                json_data={
                    "sections": [
                        {
                            "offset": {"line": 0, "column": 0},
                            "map": {
                                "sourceRoot": "src",
                                "sources": ["indexed-a.ts"],
                                "names": [],
                                "sourcesContent": ['fetch("/api/indexed-a");'],
                            },
                        },
                        {
                            "offset": {"line": 1, "column": 0},
                            "map": {
                                "sources": ["src/indexed-b.ts"],
                                "names": [],
                                "sourcesContent": ['fetch("/api/indexed-b");'],
                            },
                        },
                    ]
                }
            ),
        ]
    )  # type: ignore[assignment]

    recon._process_single_external_js("https://example.test/static/indexed.js")

    assert (tmp_path / "out" / "source_maps" / "src" / "indexed-a.ts").exists()
    assert (tmp_path / "out" / "source_maps" / "src" / "indexed-b.ts").exists()
    assert recon.processed_scripts[-1]["status"] == "sourcemap_extracted"


def test_recon_fetches_sources_when_sourcemap_has_no_sources_content(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = make_recon(tmp_path)
    session = SequenceGetSession(
        [
            FakeResponse(text='console.log("missing");\n//# sourceMappingURL=missing.js.map'),
            FakeResponse(
                json_data={
                    "sources": ["src/original.ts"],
                    "names": [],
                }
            ),
            FakeResponse(text='fetch("/api/fetched-source");'),
        ]
    )
    recon.session = session  # type: ignore[assignment]

    recon._process_single_external_js("https://example.test/static/missing.js")

    assert session.urls == [
        "https://example.test/static/missing.js",
        "https://example.test/static/missing.js.map",
        "https://example.test/static/src/original.ts",
    ]
    assert (tmp_path / "out" / "source_maps" / "src" / "original.ts").exists()
    assert recon.processed_scripts[-1]["status"] == "sourcemap_extracted"


def test_recon_include_third_party_and_size_limit_branches(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = JavaScriptRecon(
        ScanTarget(url="https://example.test/index.html"),
        ScannerConfig(output_dir=tmp_path / "out", include_third_party=True, max_file_size=5, retries=0),
    )

    selected, skipped = recon._filter_script_urls({"https://cdn.other.test/app.js"})
    assert selected == {"https://cdn.other.test/app.js"}
    assert skipped == set()
    assert recon._can_process_url("https://cdn.other.test/app.js")
    assert recon._response_exceeds_limit(FakeResponse(text="123456")) is True
    assert recon._response_exceeds_limit(FakeResponse(text="1", headers={"Content-Length": "6"})) is True


def test_recon_scope_allowlist_and_denylist_filtering(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = JavaScriptRecon(
        ScanTarget(url="https://example.test/index.html"),
        ScannerConfig(
            output_dir=tmp_path / "out",
            include_third_party=True,
            scope_hosts=frozenset({"cdn.other.test"}),
            exclude_hosts=frozenset({"blocked.example.test"}),
            retries=0,
        ),
    )

    selected, skipped = recon._filter_script_urls(
        {
            "https://cdn.other.test/app.js",
            "https://blocked.example.test/app.js",
            "https://other.example.invalid/app.js",
        }
    )

    assert "https://cdn.other.test/app.js" in selected
    assert "https://other.example.invalid/app.js" in selected
    assert "https://blocked.example.test/app.js" in skipped
    assert not recon._can_process_url("https://blocked.example.test/app.js")
    decisions = {decision["url"]: decision for decision in recon.scope_decisions}
    assert decisions["https://cdn.other.test/app.js"]["reason"] == "scope_host"
    assert decisions["https://blocked.example.test/app.js"]["reason"] == "excluded_host"
    assert decisions["https://other.example.invalid/app.js"]["reason"] == "include_third_party"


def test_recon_sourcemap_error_and_edge_branches(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recon = make_recon(tmp_path)
    output = tmp_path / "out" / "source_maps"

    recon.session = FakeGetSession(FakeResponse(status_code=404))  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False

    recon.session = FakeGetSession(requests.ConnectionError("map down"))  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False

    recon.session = FakeGetSession(FakeResponse(json_error=ValueError("bad json")))  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False

    recon.session = FakeGetSession(
        FakeResponse(json_data={"sources": ["webpack:///app.js"], "names": [], "sourcesContent": []})
    )  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False

    recon.session = FakeGetSession(
        FakeResponse(json_data={"sources": "bad", "names": "bad", "sourcesContent": ["ignored"]})
    )  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False

    recon.session = FakeGetSession(
        FakeResponse(
            json_data={
                "sources": ["webpack:///a.js", "webpack:///b.js"],
                "names": ["safeName"],
                "sourcesContent": [None],
            }
        )
    )  # type: ignore[assignment]
    assert recon._extract_sourcemap("https://example.test/app.js.map", output) is False
