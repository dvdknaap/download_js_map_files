from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from download_js_map_files.cli import DEFAULT_PROXY, build_config, build_target, create_parser, main
from download_js_map_files.colors import Colors, set_color_enabled
from download_js_map_files.models import ScanResult

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args(*args: str) -> argparse.Namespace:
    return create_parser().parse_args(list(args))


def project_version() -> str:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as project_file:
        metadata = tomllib.load(project_file)
    return str(metadata["project"]["version"])


def test_build_target_from_url() -> None:
    args = parse_args(
        "-u",
        "https://example.test/app",
        "-o",
        "out",
        "--header",
        "Authorization: Bearer token",
        "--cookie",
        "session=abc",
        "--cookie",
        "theme=dark",
    )

    target = build_target(args)

    assert target.url == "https://example.test/app"
    assert target.method == "GET"
    assert target.headers == {"Authorization": "Bearer token", "Cookie": "session=abc; theme=dark"}


def test_build_target_merges_raw_request_headers_with_cli_context(tmp_path) -> None:  # type: ignore[no-untyped-def]
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "\n".join(
            [
                "GET /app HTTP/1.1",
                "Host: example.test",
                "Cookie: existing=1",
                "Authorization: old",
                "",
            ]
        ),
        encoding="utf-8",
    )
    args = parse_args(
        "-r",
        str(request_file),
        "-o",
        "out",
        "--header",
        "Authorization: Bearer new",
        "--cookie",
        "session=abc",
    )

    target = build_target(args)

    assert target.headers["Authorization"] == "Bearer new"
    assert target.headers["Cookie"] == "existing=1; session=abc"


def test_proxy_defaults_and_no_proxy_override() -> None:
    proxied = parse_args("-u", "https://example.test", "-o", "out", "-p")
    disabled = parse_args(
        "-u",
        "https://example.test",
        "-o",
        "out",
        "--proxy",
        "http://127.0.0.1:9000",
        "--no-proxy",
    )

    assert build_config(proxied).proxy == DEFAULT_PROXY
    assert build_config(disabled).proxy is None


def test_build_config_includes_scope_and_network_limits() -> None:
    args = parse_args(
        "-u",
        "https://example.test",
        "-o",
        "out",
        "--include-third-party",
        "--scope-host",
        "https://api.example.test:8443/path",
        "--exclude-host",
        "analytics.example.test",
        "--verbose",
        "--timeout",
        "7.5",
        "--retries",
        "1",
        "--delay",
        "0.25",
        "--max-file-size",
        "1234",
    )

    config = build_config(args)

    assert config.include_third_party is True
    assert config.scope_hosts == frozenset({"api.example.test"})
    assert config.exclude_hosts == frozenset({"analytics.example.test"})
    assert config.verbose is True
    assert config.timeout == 7.5
    assert config.retries == 1
    assert config.delay == 0.25
    assert config.max_file_size == 1234


def test_parser_requires_url_or_request() -> None:
    with pytest.raises(SystemExit):
        create_parser().parse_args([])


def test_parser_rejects_quiet_and_verbose_together() -> None:
    with pytest.raises(SystemExit):
        parse_args("-u", "https://example.test", "-o", "out", "--quiet", "--verbose")


def test_main_without_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0

    output = capsys.readouterr().out
    assert "target selection" in output
    assert "network limits" in output
    assert "request context" in output
    assert "--header HEADER" in output
    assert "--cookie COOKIE" in output
    assert "--scheme {http,https}" in output
    assert "--quiet" in output
    assert "--verbose" in output
    assert "--no-color" in output
    assert "(default: 20.0)" in output


def test_quiet_suppresses_scan_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class PrintingRecon:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return

        def run(self) -> ScanResult:
            print("scan noise")
            return ScanResult(status="no_scripts_found")

    monkeypatch.setattr("download_js_map_files.cli.JavaScriptRecon", PrintingRecon)

    assert main(["-u", "https://example.test", "-o", "out", "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_no_color_disables_ansi_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class PrintingRecon:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return

        def run(self) -> ScanResult:
            print(f"{Colors.RED}colored{Colors.RESET}")
            return ScanResult(status="no_scripts_found")

    monkeypatch.setattr("download_js_map_files.cli.JavaScriptRecon", PrintingRecon)

    try:
        assert main(["-u", "https://example.test", "-o", "out", "--no-color"]) == 0
        output = capsys.readouterr().out
        assert output == "colored\n"
        assert "\033[" not in output
    finally:
        set_color_enabled(True)


def test_quiet_suppresses_cli_errors(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        "download_js_map_files.cli.build_target", lambda _args: (_ for _ in ()).throw(ValueError("bad"))
    )

    assert main(["-u", "https://example.test", "-o", "out", "--quiet"]) == 1
    assert capsys.readouterr().out == ""


def test_build_config_reads_scope_and_exclude_host_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.txt"
    exclude_file = tmp_path / "exclude.txt"
    scope_file.write_text("cdn.example.test\n", encoding="utf-8")
    exclude_file.write_text("tracker.example.test\n", encoding="utf-8")
    args = parse_args(
        "-u",
        "https://example.test",
        "-o",
        "out",
        "--scope-host-file",
        str(scope_file),
        "--exclude-host-file",
        str(exclude_file),
    )

    config = build_config(args)

    assert config.scope_hosts == frozenset({"cdn.example.test"})
    assert config.exclude_hosts == frozenset({"tracker.example.test"})


def test_version_argument_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        create_parser().parse_args(["--version"])

    assert project_version() in capsys.readouterr().out


def test_main_handles_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    class InterruptingRecon:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return

        def run(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr("download_js_map_files.cli.JavaScriptRecon", InterruptingRecon)

    assert main(["-u", "https://example.test", "-o", "out"]) == 130


def test_main_returns_failure_for_missing_request(tmp_path) -> None:  # type: ignore[no-untyped-def]
    missing_request = tmp_path / "missing.txt"

    assert main(["-r", str(missing_request), "-o", str(tmp_path / "out")]) == 1
