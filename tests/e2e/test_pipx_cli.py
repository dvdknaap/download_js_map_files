from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def pipx_cli(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    if shutil.which("pipx"):
        pipx_command = ["pipx"]
    elif importlib.util.find_spec("pipx"):
        pipx_command = [sys.executable, "-m", "pipx"]
    else:
        pytest.skip("pipx is required for the e2e install test")

    temp_root = tmp_path_factory.mktemp("pipx")
    bin_dir = temp_root / "bin"
    env = os.environ.copy()
    env.update(
        {
            "PIPX_HOME": str(temp_root / "home"),
            "PIPX_BIN_DIR": str(bin_dir),
            "PIPX_DEFAULT_PYTHON": sys.executable,
        }
    )
    subprocess.run(pipx_command + ["install", "--force", str(PROJECT_ROOT)], env=env, check=True, text=True)
    executable = bin_dir / ("download_js_map_files.exe" if os.name == "nt" else "download_js_map_files")

    try:
        yield executable
    finally:
        subprocess.run(pipx_command + ["uninstall", "download-js-map-files"], env=env, check=False, text=True)


def write_site(root: Path) -> None:
    static = root / "static"
    static.mkdir()
    (root / "index.html").write_text(
        """
        <html>
          <head><title>E2E Fixture</title></head>
          <body>
            <script>const api_key = "abcdefghijklmnop"; fetch("/api/e2e-inline");</script>
            <script src="/static/app.js"></script>
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
                "sources": ["webpack:///src/e2e.js"],
                "names": ["sessionToken"],
                "sourcesContent": ['const rpc={name:"E2EAction",params:{},endpoint:"/api/e2e-source",method:"POST"};'],
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.e2e
def test_pipx_console_script_exercises_cli_arguments(tmp_path, serve_directory, pipx_cli) -> None:  # type: ignore[no-untyped-def]
    site_root = tmp_path / "site"
    site_root.mkdir()
    write_site(site_root)

    help_result = subprocess.run([pipx_cli, "--help"], check=True, text=True, capture_output=True)
    version_result = subprocess.run([pipx_cli, "--version"], check=True, text=True, capture_output=True)
    assert "--request" in help_result.stdout
    assert "3.0.0" in version_result.stdout

    with serve_directory(site_root) as base_url:
        url_output = tmp_path / "url-output"
        request_output = tmp_path / "request-output"
        request_file = tmp_path / "request.txt"
        request_file.write_text(
            f"GET /index.html HTTP/1.1\nHost: {base_url.removeprefix('http://')}\nUser-Agent: e2e\n\n",
            encoding="utf-8",
        )

        subprocess.run(
            [
                pipx_cli,
                "-u",
                f"{base_url}/index.html",
                "-o",
                str(url_output),
                "--proxy",
                "http://127.0.0.1:1",
                "--no-proxy",
            ],
            check=True,
            text=True,
        )
        subprocess.run(
            [
                pipx_cli,
                "-r",
                str(request_file),
                "--scheme",
                "http",
                "-o",
                str(request_output),
                "-p",
                "--no-proxy",
            ],
            check=True,
            text=True,
        )

    assert "E2EAction" in (url_output / "clean_rpc_endpoints.txt").read_text(encoding="utf-8")
    assert "/api/e2e-inline" in (request_output / "all_endpoints_unique.txt").read_text(encoding="utf-8")
