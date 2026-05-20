from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COMMAND_NAME = "download_js_map_files"


def project_version() -> str:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as project_file:
        metadata = tomllib.load(project_file)
    return str(metadata["project"]["version"])


@pytest.fixture(scope="session")
def pipx_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    if not shutil.which("pipx"):
        pytest.skip("pipx is required for the e2e install test")

    temp_root = tmp_path_factory.mktemp("pipx")
    bin_dir = temp_root / "bin"
    env = os.environ.copy()
    env.update(
        {
            "PIPX_HOME": str(temp_root / "home"),
            "PIPX_BIN_DIR": str(bin_dir),
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
        }
    )
    subprocess.run(["pipx", "install", ".", "--force"], cwd=PROJECT_ROOT, env=env, check=True, text=True)

    try:
        yield env
    finally:
        subprocess.run(["pipx", "uninstall", "download-js-map-files"], env=env, check=False, text=True)


def run_cli(
    env: dict[str, str],
    *args: str | Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [COMMAND_NAME, *[str(arg) for arg in args]],
        check=check,
        text=True,
        capture_output=True,
        env=env,
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_json_lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_schema(name: str) -> dict[str, object]:
    return read_json(PROJECT_ROOT / "schemas" / name)


def assert_schema_required_keys(record: dict[str, object], schema: dict[str, object]) -> None:
    required = schema["required"]
    assert isinstance(required, list)
    assert set(required).issubset(record)


def write_sourcemap_site(root: Path) -> None:
    static = root / "static"
    static.mkdir()
    (root / "index.html").write_text(
        """
        <html>
          <head><title>E2E Source Map Fixture</title></head>
          <body>
            <script>
              const api_key = "abcdefghijklmnop";
              fetch("/api/e2e-inline");
              fetch("/api/orders/123?token=secret");
            </script>
            <script src="/static/app.js"></script>
            <script src="https://cdn.example.invalid/vendor.js"></script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )
    (static / "app.js").write_text('console.log("e2e");\n//# sourceMappingURL=app.js.map', encoding="utf-8")
    (static / "app.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["webpack:///../../escape.js"],
                "names": ["sessionToken"],
                "sourcesContent": ['const rpc={name:"E2EAction",params:{},endpoint:"/api/e2e-source",method:"POST"};'],
            }
        ),
        encoding="utf-8",
    )


def write_fallback_site(root: Path) -> None:
    (root / "index.html").write_text('<script src="/fallback.min.js"></script>', encoding="utf-8")
    (root / "fallback.min.js").write_text(
        'const svc={name:"FallbackE2E",params:{},endpoint:"/rest/e2e",method:"GET"};fetch("/api/fallback-e2e");',
        encoding="utf-8",
    )


def write_hintless_sourcemap_site(root: Path) -> None:
    (root / "index.html").write_text('<script src="/hintless.js"></script>', encoding="utf-8")
    (root / "hintless.js").write_text('console.log("hintless");', encoding="utf-8")
    (root / "hintless.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "file": "hintless.js",
                "sources": ["webpack:///src/hintless.js"],
                "names": [],
                "sourcesContent": ['fetch("/api/hintless-sourcemap");'],
            }
        ),
        encoding="utf-8",
    )


def write_sourcemap_variant_site(root: Path) -> None:
    static = root / "static"
    source_dir = static / "src"
    source_dir.mkdir(parents=True)
    (root / "index.html").write_text(
        '<script src="/static/indexed.js"></script><script src="/static/missing-content.js"></script>',
        encoding="utf-8",
    )
    (static / "indexed.js").write_text('console.log("indexed");\n//# sourceMappingURL=indexed.js.map', encoding="utf-8")
    (static / "indexed.js.map").write_text(
        json.dumps(
            {
                "sections": [
                    {
                        "offset": {"line": 0, "column": 0},
                        "map": {
                            "sourceRoot": "src",
                            "sources": ["indexed-a.ts"],
                            "names": [],
                            "sourcesContent": ['fetch("/api/e2e-indexed-a");'],
                        },
                    },
                    {
                        "offset": {"line": 1, "column": 0},
                        "map": {
                            "sources": ["src/indexed-b.ts"],
                            "names": [],
                            "sourcesContent": ['fetch("/api/e2e-indexed-b");'],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (static / "missing-content.js").write_text(
        'console.log("missing");\n//# sourceMappingURL=missing-content.js.map',
        encoding="utf-8",
    )
    (static / "missing-content.js.map").write_text(
        json.dumps({"sources": ["src/missing.ts"], "names": []}),
        encoding="utf-8",
    )
    (source_dir / "missing.ts").write_text('fetch("/api/e2e-missing-content");', encoding="utf-8")


def write_no_script_site(root: Path) -> None:
    (root / "index.html").write_text("<html><body>No JavaScript here</body></html>", encoding="utf-8")


def write_oversize_site(root: Path) -> None:
    (root / "index.html").write_text('<script src="/large.js"></script>', encoding="utf-8")
    (root / "large.js").write_text("x" * 512, encoding="utf-8")


def write_dynamic_script_site(root: Path) -> None:
    chunks = root / "chunks"
    chunks.mkdir()
    (root / "index.html").write_text(
        """
        <script>
          const script = document.createElement("script");
          script.src = "/chunks/runtime.js";
          document.head.appendChild(script);
        </script>
        """,
        encoding="utf-8",
    )
    (chunks / "runtime.js").write_text('fetch("/api/dynamic-runtime");', encoding="utf-8")


@contextmanager
def recording_app_server() -> Iterator[tuple[str, list[dict[str, str]]]]:
    records: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            records.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "cookie": self.headers.get("Cookie", ""),
                    "authorization": self.headers.get("Authorization", ""),
                    "x_custom": self.headers.get("X-Custom", ""),
                    "body": "",
                }
            )
            html = '<script>fetch("/api/url-header-inline");</script>'
            self._send(200, html, "text/html")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            records.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "cookie": self.headers.get("Cookie", ""),
                    "authorization": self.headers.get("Authorization", ""),
                    "x_custom": self.headers.get("X-Custom", ""),
                    "body": body,
                }
            )
            html = '<script>fetch("/api/raw-post-inline");</script>'
            self._send(200, html, "text/html")

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send(self, status: int, body: str, content_type: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", records
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@contextmanager
def proxy_fixture() -> Iterator[tuple[str, list[str]]]:
    requests_seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests_seen.append(self.path)
            if self.path.endswith("/index.html"):
                body = (
                    '<script src="http://target.example/app.js"></script>'
                    '<script src="http://cdn.example/vendor.js"></script>'
                )
                self._send(200, body, "text/html")
            elif self.path.endswith("/app.js"):
                self._send(200, 'fetch("/api/proxy-target");', "application/javascript")
            elif self.path.endswith("/vendor.js"):
                self._send(200, 'fetch("/api/proxy-vendor");', "application/javascript")
            else:
                self._send(404, "not found", "text/plain")

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send(self, status: int, body: str, content_type: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", requests_seen
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.e2e
def test_help_version_and_usage_errors(pipx_env: dict[str, str], tmp_path: Path) -> None:
    help_result = run_cli(pipx_env, "--help")
    no_args_result = run_cli(pipx_env)
    version_result = run_cli(pipx_env, "--version")
    missing_output = run_cli(pipx_env, "-u", "http://example.test", check=False)
    missing_target = run_cli(pipx_env, "-o", tmp_path / "out", check=False)
    mutually_exclusive = run_cli(
        pipx_env,
        "-u",
        "http://example.test",
        "-r",
        tmp_path / "request.txt",
        "-o",
        tmp_path / "out",
        check=False,
    )
    mutually_exclusive_output = run_cli(
        pipx_env,
        "-u",
        "http://example.test",
        "-o",
        tmp_path / "out",
        "--quiet",
        "--verbose",
        check=False,
    )

    for flag in (
        "--url",
        "--request",
        "--output",
        "--header",
        "--cookie",
        "--proxy",
        "--no-proxy",
        "--scheme",
        "--include-third-party",
        "--scope-host",
        "--scope-host-file",
        "--exclude-host",
        "--exclude-host-file",
        "--timeout",
        "--retries",
        "--delay",
        "--max-file-size",
        "--quiet",
        "--verbose",
        "--no-color",
        "--version",
    ):
        assert flag in help_result.stdout
    for heading in (
        "target selection",
        "output",
        "proxy and scope",
        "raw request",
        "network limits",
        "runtime output",
        "metadata",
    ):
        assert heading in help_result.stdout
        assert heading in no_args_result.stdout
    assert no_args_result.returncode == 0
    assert "--scheme {http,https}" in help_result.stdout
    assert "(default: 20.0)" in help_result.stdout
    assert "(default: 10485760)" in help_result.stdout
    assert project_version() in version_result.stdout
    assert missing_output.returncode == 2
    assert missing_target.returncode == 2
    assert mutually_exclusive.returncode == 2
    assert mutually_exclusive_output.returncode == 2


@pytest.mark.e2e
def test_runtime_output_flags_control_console_output(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    site_root.mkdir()
    write_no_script_site(site_root)

    with serve_directory(site_root) as base_url:
        quiet_output = tmp_path / "quiet"
        quiet_result = run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", quiet_output, "--quiet")
        no_color_result = run_cli(
            pipx_env,
            "-u",
            f"{base_url}/index.html",
            "-o",
            tmp_path / "no-color",
            "--no-color",
        )
        verbose_result = run_cli(
            pipx_env,
            "-u",
            f"{base_url}/index.html",
            "-o",
            tmp_path / "verbose",
            "--verbose",
        )

    assert quiet_result.stdout == ""
    assert (quiet_output / "summary.json").exists()
    assert "Starting analysis" in no_color_result.stdout
    assert "\033[" not in no_color_result.stdout
    assert "[v] Target method: GET" in verbose_result.stdout
    assert "[v] Output directory:" in verbose_result.stdout


@pytest.mark.e2e
def test_url_mode_sends_repeatable_headers_and_cookies(tmp_path: Path, pipx_env: dict[str, str]) -> None:
    output = tmp_path / "url-context-output"

    with recording_app_server() as (base_url, records):
        run_cli(
            pipx_env,
            "-u",
            f"{base_url}/entry",
            "-o",
            output,
            "--header",
            "Authorization: Bearer url-token",
            "--header",
            "X-Custom: url-custom",
            "--cookie",
            "session=url",
            "--cookie",
            "theme=dark",
        )

    assert records == [
        {
            "method": "GET",
            "path": "/entry",
            "cookie": "session=url; theme=dark",
            "authorization": "Bearer url-token",
            "x_custom": "url-custom",
            "body": "",
        }
    ]
    assert "/api/url-header-inline" in (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")


@pytest.mark.e2e
def test_url_scan_extracts_sourcemap_and_skips_third_party_by_default(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_sourcemap_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(
            pipx_env,
            "-u",
            f"{base_url}/index.html",
            "-o",
            output,
            "--timeout",
            "5",
            "--retries",
            "0",
            "--delay",
            "0.01",
            "--max-file-size",
            "10485760",
        )

    summary = read_json(output / "summary.json")
    skipped = (output / "skipped_third_party_urls.txt").read_text(encoding="utf-8")
    endpoint_records = read_json_lines(output / "endpoints.jsonl")
    secret_records = read_json_lines(output / "findings.jsonl")
    summary_schema = read_schema("summary.schema.json")
    manifest_schema = read_schema("artifact-manifest.schema.json")
    scope_schema = read_schema("scope-report.schema.json")
    endpoint_schema = read_schema("endpoint-record.schema.json")
    secret_schema = read_schema("secret-finding-record.schema.json")
    manifest = read_json(output / "artifact_manifest.json")
    manifest_artifacts = {artifact["path"]: artifact for artifact in manifest["artifacts"]}  # type: ignore[index]
    scope_report = read_json(output / "scope_report.json")

    assert summary["status"] == "sourcemaps_found"
    assert summary["include_third_party"] is False
    assert summary["counts"]["source_maps_found"] == 1  # type: ignore[index]
    assert "cdn.example.invalid" in skipped
    assert (output / "source_maps" / "escape.js").exists()
    assert not (output / "escape.js").exists()
    assert "E2EAction" in (output / "clean_rpc_endpoints.txt").read_text(encoding="utf-8")
    assert "/api/e2e-inline" in (output / "endpoints.jsonl").read_text(encoding="utf-8")
    assert "/api/orders/{id}?token={value}" in (output / "all_endpoints_normalized.txt").read_text(encoding="utf-8")
    assert summary["secret_findings"]  # type: ignore[index]
    assert secret_records[0]["type"] == "secret"
    assert secret_records[0]["path"].startswith("inline_scripts/")
    assert_schema_required_keys(summary, summary_schema)
    assert_schema_required_keys(manifest, manifest_schema)
    assert_schema_required_keys(scope_report, scope_schema)
    assert_schema_required_keys(endpoint_records[0], endpoint_schema)
    assert_schema_required_keys(secret_records[0], secret_schema)
    assert "artifact_manifest.json" in summary["files_written"]  # type: ignore[operator]
    assert summary["scope_report"] == "scope_report.json"
    assert "summary.json" in manifest_artifacts
    assert len(manifest_artifacts["summary.json"]["sha256"]) == 64
    assert any(record["normalized_value"] == "/api/orders/{id}?token={value}" for record in endpoint_records)


@pytest.mark.e2e
def test_raw_post_request_preserves_headers_body_and_scheme(tmp_path: Path, pipx_env: dict[str, str]) -> None:
    output = tmp_path / "raw-output"
    request_file = tmp_path / "request.txt"

    with recording_app_server() as (base_url, records):
        request_file.write_text(
            f"POST /entry HTTP/1.1\n"
            f"Host: {base_url.removeprefix('http://')}\n"
            "Cookie: session=e2e\n"
            "Authorization: Bearer test-token\n"
            "X-Custom: custom-value\n"
            "Content-Type: application/json\n"
            "\n"
            '{"ok": true}',
            encoding="utf-8",
        )
        run_cli(pipx_env, "-r", request_file, "--scheme", "http", "-o", output)

    summary = read_json(output / "summary.json")

    assert summary["target"]["method"] == "POST"  # type: ignore[index]
    assert records == [
        {
            "method": "POST",
            "path": "/entry",
            "cookie": "session=e2e",
            "authorization": "Bearer test-token",
            "x_custom": "custom-value",
            "body": '{"ok": true}',
        }
    ]
    assert "/api/raw-post-inline" in (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")


@pytest.mark.e2e
def test_no_scripts_status(tmp_path: Path, serve_directory, pipx_env: dict[str, str]) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_no_script_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output)

    summary = read_json(output / "summary.json")

    assert summary["status"] == "no_scripts_found"
    assert (output / "urls.txt").read_text(encoding="utf-8") == ""


@pytest.mark.e2e
def test_no_sourcemap_falls_back_to_beautified_compiled_js(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_fallback_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output)

    summary = read_json(output / "summary.json")

    assert summary["status"] == "beautified_only"
    assert (output / "compiled" / "fallback.min.js").exists()
    assert "/api/fallback-e2e" in (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")


@pytest.mark.e2e
def test_inline_dynamic_script_reference_is_processed(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_dynamic_script_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output)

    summary = read_json(output / "summary.json")

    assert summary["status"] == "beautified_only"
    assert f"{base_url}/chunks/runtime.js" in (output / "urls.txt").read_text(encoding="utf-8")
    assert (output / "compiled" / "runtime.js").exists()
    assert "/api/dynamic-runtime" in (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")


@pytest.mark.e2e
def test_hintless_sourcemap_is_probed_automatically(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_hintless_sourcemap_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output)

    summary = read_json(output / "summary.json")
    processed = summary["scripts"]["processed"]  # type: ignore[index]

    assert summary["status"] == "sourcemaps_found"
    assert processed[-1]["source_map_url"].endswith("/hintless.js.map")
    assert (output / "source_maps" / "src" / "hintless.js").exists()
    assert not (output / "compiled" / "hintless.js").exists()
    assert "/api/hintless-sourcemap" in (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")


@pytest.mark.e2e
def test_sourcemap_variants_indexed_and_missing_sources_content(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_sourcemap_variant_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output)

    summary = read_json(output / "summary.json")
    endpoints = (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")

    assert summary["status"] == "sourcemaps_found"
    assert summary["counts"]["source_maps_found"] == 2  # type: ignore[index]
    assert (output / "source_maps" / "src" / "indexed-a.ts").exists()
    assert (output / "source_maps" / "src" / "indexed-b.ts").exists()
    assert (output / "source_maps" / "src" / "missing.ts").exists()
    assert "/api/e2e-indexed-a" in endpoints
    assert "/api/e2e-missing-content" in endpoints


@pytest.mark.e2e
def test_external_file_over_max_size_is_skipped(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_oversize_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output, "--max-file-size", "128")

    summary = read_json(output / "summary.json")
    processed = summary["scripts"]["processed"]  # type: ignore[index]

    assert summary["status"] == "no_scripts_found"
    assert processed[0]["status"] == "skipped_oversize"
    assert not (output / "compiled" / "large.js").exists()


@pytest.mark.e2e
def test_include_third_party_and_custom_proxy_process_external_hosts(
    tmp_path: Path,
    pipx_env: dict[str, str],
) -> None:
    output = tmp_path / "proxy-output"

    with proxy_fixture() as (proxy_url, requests_seen):
        run_cli(
            pipx_env,
            "-u",
            "http://target.example/index.html",
            "-o",
            output,
            "--proxy",
            proxy_url,
            "--include-third-party",
            "--timeout",
            "5",
            "--retries",
            "0",
        )

    summary = read_json(output / "summary.json")
    endpoints = (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")

    assert summary["proxy_enabled"] is True
    assert summary["include_third_party"] is True
    assert any("target.example/index.html" in request for request in requests_seen)
    assert any("cdn.example/vendor.js" in request for request in requests_seen)
    assert "/api/proxy-target" in endpoints
    assert "/api/proxy-vendor" in endpoints


@pytest.mark.e2e
def test_scope_and_exclude_host_files_control_external_hosts(tmp_path: Path, pipx_env: dict[str, str]) -> None:
    output = tmp_path / "scope-output"
    scope_file = tmp_path / "scope-hosts.txt"
    exclude_file = tmp_path / "exclude-hosts.txt"
    scope_file.write_text("cdn.example\n", encoding="utf-8")
    exclude_file.write_text("target.example\n", encoding="utf-8")

    with proxy_fixture() as (proxy_url, requests_seen):
        run_cli(
            pipx_env,
            "-u",
            "http://target.example/index.html",
            "-o",
            output,
            "--proxy",
            proxy_url,
            "--scope-host-file",
            scope_file,
            "--exclude-host-file",
            exclude_file,
            "--timeout",
            "5",
            "--retries",
            "0",
        )

    summary = read_json(output / "summary.json")
    scope_report = read_json(output / "scope_report.json")
    decisions = {decision["url"]: decision for decision in scope_report["decisions"]}  # type: ignore[index]
    endpoints = (output / "all_endpoints_unique.txt").read_text(encoding="utf-8")

    assert summary["scope_hosts"] == ["cdn.example"]
    assert summary["exclude_hosts"] == ["target.example"]
    assert summary["scope_report"] == "scope_report.json"
    assert any("cdn.example/vendor.js" in request for request in requests_seen)
    assert not any("target.example/app.js" in request for request in requests_seen)
    assert "/api/proxy-vendor" in endpoints
    assert "/api/proxy-target" not in endpoints
    assert decisions["http://cdn.example/vendor.js"]["reason"] == "scope_host"
    assert decisions["http://target.example/app.js"]["reason"] == "excluded_host"
    assert decisions["http://target.example/app.js"]["selected"] is False


@pytest.mark.e2e
def test_proxy_shorthand_can_be_disabled_with_no_proxy(
    tmp_path: Path,
    serve_directory,
    pipx_env: dict[str, str],
) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    output = tmp_path / "out"
    site_root.mkdir()
    write_no_script_site(site_root)

    with serve_directory(site_root) as base_url:
        run_cli(pipx_env, "-u", f"{base_url}/index.html", "-o", output, "-p", "--no-proxy")

    summary = read_json(output / "summary.json")

    assert summary["proxy_enabled"] is False
    assert summary["status"] == "no_scripts_found"
