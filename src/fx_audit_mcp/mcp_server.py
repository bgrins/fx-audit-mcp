"""FastMCP server exposing all fx-audit-mcp execution tools.

Serves browser_evaluator, package_testcase, js_shell_evaluator,
build_firefox, build_nss, and nss_gtest_evaluator over stdio or
streamable HTTP.

Configuration is via environment variables:
  FIREFOX_SOURCE_ROOT     — default Firefox source directory for build tools
  FIREFOX_BINARY          — path to Firefox binary; used to derive build_dir
  FX_AUDIT_TRANSPORT      — default --transport (stdio or http)
  FX_AUDIT_HOST           — default --host for HTTP transport
  FX_AUDIT_PORT           — default --port for HTTP transport
  FX_AUDIT_DISABLED_TOOLS — comma-separated tool names to not register
"""

import os
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
from logging import ERROR, getLogger

from fastmcp import FastMCP

from .browser_evaluator import browser_evaluator, package_testcase
from .build_firefox import build_firefox
from .build_nss import build_nss
from .js_shell_evaluator import js_shell_evaluator
from .nss_gtest_evaluator import nss_gtest_evaluator

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)

_TRANSPORTS = ("stdio", "http")
_TOOL_FUNCTIONS = (
    browser_evaluator,
    package_testcase,
    js_shell_evaluator,
    build_firefox,
    build_nss,
    nss_gtest_evaluator,
)


def _parse_args(argv: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(description="Run the fx-audit MCP server.")
    parser.add_argument(
        "--transport",
        choices=_TRANSPORTS,
        default=os.environ.get("FX_AUDIT_TRANSPORT", "stdio"),
        help="MCP transport (default: $FX_AUDIT_TRANSPORT or stdio)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("FX_AUDIT_HOST", "127.0.0.1"),
        help="bind address for http transport (default: $FX_AUDIT_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        # argparse applies type= to string defaults at parse time, turning a
        # malformed env value into a usage error instead of a traceback
        default=os.environ.get("FX_AUDIT_PORT", "8000"),
        help="port for http transport (default: $FX_AUDIT_PORT or 8000)",
    )
    args = parser.parse_args(argv)
    # choices= is not enforced for defaults, so validate env-provided values
    if args.transport not in _TRANSPORTS:
        parser.error(
            f"invalid FX_AUDIT_TRANSPORT {args.transport!r} "
            f"(choose from {', '.join(_TRANSPORTS)})"
        )
    return args


def create_server() -> FastMCP:
    """Create the fx-audit FastMCP server, registering all tools except
    those named in the FX_AUDIT_DISABLED_TOOLS environment variable
    (comma-separated tool names).

    Raises:
        ValueError: If FX_AUDIT_DISABLED_TOOLS names an unknown tool.
    """
    disabled = {
        name.strip()
        for name in os.environ.get("FX_AUDIT_DISABLED_TOOLS", "").split(",")
        if name.strip()
    }
    unknown = disabled - {fn.__name__ for fn in _TOOL_FUNCTIONS}
    if unknown:
        raise ValueError(
            f"Unknown tool(s) in FX_AUDIT_DISABLED_TOOLS: {', '.join(sorted(unknown))}"
        )
    server = FastMCP("fx-audit")
    for fn in _TOOL_FUNCTIONS:
        if fn.__name__ not in disabled:
            server.tool(fn)
    return server


def main(argv: Sequence[str] | None = None) -> None:
    """Run the fx-audit MCP server over stdio or streamable HTTP."""
    args = _parse_args(argv)
    try:
        server = create_server()
        extra = (
            {"host": args.host, "port": args.port} if args.transport == "http" else {}
        )
        server.run(transport=args.transport, show_banner=False, **extra)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error running MCP server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
