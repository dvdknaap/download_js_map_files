"""Command-line interface for the JavaScript recon tool."""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .colors import Colors
from .models import ScannerConfig, ScanTarget
from .recon import JavaScriptRecon
from .request_parser import RequestParser

DEFAULT_PROXY = "http://127.0.0.1:8080"
PACKAGE_NAME = "download-js-map-files"


def package_version() -> str:
    """Return the installed package version from project metadata."""

    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "unknown"


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Download and analyze JavaScript source maps.")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL to scan.")
    target_group.add_argument("-r", "--request", help="Path to a raw HTTP request file.")

    parser.add_argument("-o", "--output", default="./js_recon_out", help="Output directory.")
    parser.add_argument(
        "-p",
        "--proxy",
        nargs="?",
        const=DEFAULT_PROXY,
        default=None,
        help=f"Proxy URL. Defaults to {DEFAULT_PROXY} when passed without a value.",
    )
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxying even when --proxy is supplied.")
    parser.add_argument("--scheme", choices=("http", "https"), default="https", help="Scheme for raw request files.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    return parser


def build_target(args: argparse.Namespace) -> ScanTarget:
    """Build a scanner target from parsed CLI arguments."""

    if args.url:
        return ScanTarget(url=args.url)
    return RequestParser.parse(args.request, scheme=args.scheme)


def build_config(args: argparse.Namespace) -> ScannerConfig:
    """Build scanner configuration from parsed CLI arguments."""

    proxy = None if args.no_proxy else args.proxy
    return ScannerConfig(output_dir=Path(args.output), proxy=proxy)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        if args.request:
            print(f"{Colors.HEADER}[*] Parsing Request File: {args.request}{Colors.RESET}")
        recon = JavaScriptRecon(target=build_target(args), config=build_config(args))
        recon.run()
        return 0
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user.{Colors.RESET}")
        return 130
    except (OSError, ValueError) as exc:
        print(f"{Colors.RED}Fatal Error: {exc}{Colors.RESET}")
        return 1
