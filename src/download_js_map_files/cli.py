"""Command-line interface for the JavaScript recon tool."""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .colors import Colors
from .headers import merge_headers
from .models import ScannerConfig, ScanTarget
from .recon import JavaScriptRecon
from .request_parser import RequestParser
from .scope import resolve_hosts

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

    parser = argparse.ArgumentParser(
        description="Download and analyze JavaScript source maps.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target_arguments = parser.add_argument_group("target selection")
    target_group = target_arguments.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL to scan.")
    target_group.add_argument("-r", "--request", help="Path to a raw HTTP request file.")

    output_arguments = parser.add_argument_group("output")
    output_arguments.add_argument("-o", "--output", required=True, help="Output directory.")

    request_context_arguments = parser.add_argument_group("request context")
    request_context_arguments.add_argument(
        "--header",
        action="append",
        metavar="HEADER",
        help="Extra HTTP header in 'Name: value' format. Can be used multiple times.",
    )
    request_context_arguments.add_argument(
        "--cookie",
        action="append",
        metavar="COOKIE",
        help="Extra cookie in 'name=value' format. Can be used multiple times.",
    )

    proxy_arguments = parser.add_argument_group("proxy and scope")
    proxy_arguments.add_argument(
        "-p",
        "--proxy",
        nargs="?",
        const=DEFAULT_PROXY,
        default=None,
        help=f"Proxy URL. Defaults to {DEFAULT_PROXY} when passed without a value.",
    )
    proxy_arguments.add_argument(
        "--no-proxy", action="store_true", help="Disable proxying even when --proxy is supplied."
    )
    proxy_arguments.add_argument(
        "--include-third-party",
        action="store_true",
        help="Process third-party script URLs instead of only recording them as skipped.",
    )
    proxy_arguments.add_argument(
        "--scope-host",
        action="append",
        metavar="HOST",
        help="Additional in-scope host or domain. Can be used multiple times.",
    )
    proxy_arguments.add_argument(
        "--scope-host-file",
        action="append",
        metavar="PATH",
        help="File with additional in-scope hosts, one per line. Can be used multiple times.",
    )
    proxy_arguments.add_argument(
        "--exclude-host",
        action="append",
        metavar="HOST",
        help="Host or domain to skip even if otherwise in scope. Can be used multiple times.",
    )
    proxy_arguments.add_argument(
        "--exclude-host-file",
        action="append",
        metavar="PATH",
        help="File with hosts to skip, one per line. Can be used multiple times.",
    )

    raw_request_arguments = parser.add_argument_group("raw request")
    raw_request_arguments.add_argument(
        "--scheme", choices=("http", "https"), default="https", help="Scheme for raw request files."
    )

    network_arguments = parser.add_argument_group("network limits")
    network_arguments.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds.")
    network_arguments.add_argument("--retries", type=int, default=3, help="Retry count for transient HTTP failures.")
    network_arguments.add_argument(
        "--delay", type=float, default=0.0, help="Delay in seconds before each external script request."
    )
    network_arguments.add_argument(
        "--max-file-size",
        type=int,
        default=10_485_760,
        help="Maximum response size in bytes for HTML, JavaScript, and source-map downloads.",
    )

    metadata_arguments = parser.add_argument_group("metadata")
    metadata_arguments.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    return parser


def build_target(args: argparse.Namespace) -> ScanTarget:
    """Build a scanner target from parsed CLI arguments."""

    if args.url:
        return ScanTarget(url=args.url, headers=merge_headers({}, args.header, args.cookie))

    raw_target = RequestParser.parse(args.request, scheme=args.scheme)
    return ScanTarget(
        url=raw_target.url,
        method=raw_target.method,
        headers=merge_headers(raw_target.headers, args.header, args.cookie),
        body=raw_target.body,
    )


def build_config(args: argparse.Namespace) -> ScannerConfig:
    """Build scanner configuration from parsed CLI arguments."""

    proxy = None if args.no_proxy else args.proxy
    scope_hosts = resolve_hosts(args.scope_host, args.scope_host_file)
    exclude_hosts = resolve_hosts(args.exclude_host, args.exclude_host_file)
    return ScannerConfig(
        output_dir=Path(args.output),
        proxy=proxy,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        max_file_size=args.max_file_size,
        include_third_party=args.include_third_party,
        scope_hosts=scope_hosts,
        exclude_hosts=exclude_hosts,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = create_parser()
    effective_argv = sys.argv[1:] if argv is None else argv
    if not effective_argv:
        parser.print_help()
        return 0

    args = parser.parse_args(effective_argv)

    try:
        if args.request:
            print(f"{Colors.HEADER}[*] Parsing Request File: {args.request}{Colors.RESET}")
        recon = JavaScriptRecon(target=build_target(args), config=build_config(args))
        result = recon.run()
        return 2 if result.fatal else 0
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user.{Colors.RESET}")
        return 130
    except (OSError, ValueError) as exc:
        print(f"{Colors.RED}Fatal Error: {exc}{Colors.RESET}")
        return 1
