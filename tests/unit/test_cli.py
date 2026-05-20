from __future__ import annotations

import argparse

import pytest

from download_js_map_files.cli import DEFAULT_PROXY, build_config, build_target, create_parser, main


def parse_args(*args: str) -> argparse.Namespace:
    return create_parser().parse_args(list(args))


def test_build_target_from_url() -> None:
    args = parse_args("-u", "https://example.test/app", "-o", "out")

    target = build_target(args)

    assert target.url == "https://example.test/app"
    assert target.method == "GET"
    assert target.headers == {}


def test_proxy_defaults_and_no_proxy_override() -> None:
    proxied = parse_args("-u", "https://example.test", "-p")
    disabled = parse_args("-u", "https://example.test", "--proxy", "http://127.0.0.1:9000", "--no-proxy")

    assert build_config(proxied).proxy == DEFAULT_PROXY
    assert build_config(disabled).proxy is None


def test_parser_requires_url_or_request() -> None:
    with pytest.raises(SystemExit):
        create_parser().parse_args([])


def test_version_argument_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        create_parser().parse_args(["--version"])

    assert "3.0.0" in capsys.readouterr().out


def test_main_handles_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    class InterruptingRecon:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return

        def run(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr("download_js_map_files.cli.JavaScriptRecon", InterruptingRecon)

    assert main(["-u", "https://example.test"]) == 130


def test_main_returns_failure_for_missing_request(tmp_path) -> None:  # type: ignore[no-untyped-def]
    missing_request = tmp_path / "missing.txt"

    assert main(["-r", str(missing_request)]) == 1
