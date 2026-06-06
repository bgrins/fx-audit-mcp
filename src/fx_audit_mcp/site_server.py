"""Built-in cross-origin site server for browser testcases.

Hosts ``http://example.site/``, ``http://victim.site/`` and
``http://attacker.site/`` during a run without modifying ``/etc/hosts``:
Firefox is pointed at a PAC (proxy auto-config) that routes requests for
these hosts to this server, which answers the resulting proxy-form HTTP
requests from a shared static docroot. Every other host keeps routing to a
dead-end proxy, preserving the fuzzing prefs' network isolation.

Besides the static docroot, every site exposes the reserved ``/_output/``
namespace (never served from the docroot) backed by the live browser logs
of the current run:

- ``/_output/lib.js`` — in-page helper library (``FxAudit.awaitMarker``,
  ``FxAudit.awaitLog``) for sequencing multi-step testcases without sleeps.
- ``/_output/markers`` — the marker-pattern-matching stderr/stdout lines
  observed so far, one per line, append-only within a run.
- ``/_output/log?log=stderr&offset=N`` — raw log bytes from *offset*,
  with the next offset returned in ``X-Next-Offset``.
"""

import logging
import mimetypes
import re
import threading
import traceback
from collections.abc import Callable
from functools import cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

logger = logging.getLogger(__name__)

# Reads (log_id, byte offset) and returns the new log bytes from there.
LiveLogReader = Callable[[str, int], bytes]

SITES: tuple[str, ...] = ("example.site", "victim.site", "attacker.site")

# Reserved top-level URL namespace for the live log/marker endpoints.
OUTPUT_PREFIX = "_output"

# Log ids the live endpoints may read.
_LIVE_LOG_IDS: tuple[str, ...] = ("stderr", "stdout")

_LIB_JS_PATH = Path(__file__).parent / "output_lib.js"

# Dead-end proxy used by the prefpicker browser-fuzzing template to blackhole
# non-localhost traffic; hosts other than SITES keep routing here.
_BLACKHOLE_PROXY = "PROXY 127.0.0.1:6"
_HEADERS_SUFFIX = "^headers^"

# Framing/connection response headers the server must own; sidecar values for
# these would emit duplicates and desync the keep-alive connection.
_RESERVED_HEADERS = frozenset({"connection", "content-length", "transfer-encoding"})


class _LiveMarkerScanner:
    """Incrementally collect marker lines from the live browser logs.

    Thread-safe: ``snapshot()`` pulls the new bytes from each log, appends
    the pattern-matching complete lines, and returns all lines collected so
    far. The result is append-only within a run, so in-page cursors over the
    markers endpoint stay valid across polls. A trailing partial line is
    held back until its newline arrives.
    """

    def __init__(self, reader: LiveLogReader, pattern: re.Pattern[str]) -> None:
        self._reader = reader
        self._pattern = pattern
        self._lock = threading.Lock()
        self._offsets = dict.fromkeys(_LIVE_LOG_IDS, 0)
        self._tails = dict.fromkeys(_LIVE_LOG_IDS, b"")
        self._lines: list[str] = []

    def snapshot(self) -> list[str]:
        """Scan for new log lines and return all marker lines so far."""
        with self._lock:
            for log_id in _LIVE_LOG_IDS:
                chunk = self._reader(log_id, self._offsets[log_id])
                if not chunk:
                    continue
                self._offsets[log_id] += len(chunk)
                *complete, self._tails[log_id] = (self._tails[log_id] + chunk).split(
                    b"\n"
                )
                for raw in complete:
                    line = raw.decode("utf-8", "replace")
                    if self._pattern.search(line):
                        self._lines.append(line)
            return list(self._lines)


class _SiteRequestHandler(BaseHTTPRequestHandler):
    """Serve static files for SITES from proxy-form or origin-form requests."""

    protocol_version = "HTTP/1.1"

    def _resolve_host_and_path(self) -> tuple[str | None, str]:
        """Return (hostname, url-path) from the request target.

        Firefox sends proxy-form requests (``GET http://victim.site/x``)
        through the PAC; origin-form requests fall back to the Host header.
        """
        if self.path.startswith(("http://", "https://")):
            split = urlsplit(self.path)
            return split.hostname, split.path
        host = self.headers.get("Host", "")
        return urlsplit(f"//{host}").hostname, urlsplit(self.path).path

    def _resolve_file(self) -> Path | None:
        """Resolve the request target to a docroot file, or send an error.

        Returns:
            The resolved file path, or None after an error response was sent.
        """
        assert isinstance(self.server, _SiteHTTPServer)
        docroot = self.server.docroot
        host, url_path = self._resolve_host_and_path()
        if host not in SITES:
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Unknown host: {host!r}")
            return None
        relative = unquote(url_path).lstrip("/")
        if not relative or relative.endswith("/"):
            relative += "index.html"
        try:
            file_path = (docroot / relative).resolve()
        except (ValueError, OSError):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return None
        if not file_path.is_relative_to(docroot):
            self.send_error(HTTPStatus.FORBIDDEN)
            return None
        if file_path.is_dir():
            file_path = file_path / "index.html"
        if file_path.name.endswith(_HEADERS_SUFFIX) or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        return file_path

    def _send_output_response(
        self,
        body: bytes,
        content_type: str,
        send_body: bool,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Send a 200 response for a ``/_output/`` endpoint.

        Carries permissive CORS and CORP headers: pages load these
        endpoints cross-origin (e.g. from the localhost entry testcase),
        and documents running under COEP ``require-corp`` block no-cors
        subresource loads — such as the documented ``<script src>`` of
        ``lib.js`` — unless the response opts in via
        ``Cross-Origin-Resource-Policy``.
        """
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _serve_output_log(self, send_body: bool) -> None:
        """Serve raw live-log bytes for ``/_output/log``."""
        assert isinstance(self.server, _SiteHTTPServer)
        reader = self.server.log_reader
        if reader is None:
            self.send_error(
                HTTPStatus.NOT_FOUND, "log endpoint requires a live browser run"
            )
            return
        query = parse_qs(urlsplit(self.path).query)
        log_id = query.get("log", ["stderr"])[-1]
        if log_id not in _LIVE_LOG_IDS:
            self.send_error(HTTPStatus.BAD_REQUEST, f"unknown log: {log_id!r}")
            return
        try:
            offset = int(query.get("offset", ["0"])[-1])
        except ValueError:
            offset = -1
        if offset < 0:
            self.send_error(
                HTTPStatus.BAD_REQUEST, "offset must be a non-negative integer"
            )
            return
        chunk = reader(log_id, offset)
        self._send_output_response(
            chunk,
            "text/plain; charset=utf-8",
            send_body,
            extra_headers=(
                ("X-Next-Offset", str(offset + len(chunk))),
                ("Access-Control-Expose-Headers", "X-Next-Offset"),
            ),
        )

    def _maybe_serve_output(self, send_body: bool) -> bool:
        """Serve ``/_output/`` endpoints; return True when handled.

        The namespace is reserved: it is checked before docroot resolution,
        so docroot files can never shadow (or be shadowed into) it.
        """
        assert isinstance(self.server, _SiteHTTPServer)
        host, url_path = self._resolve_host_and_path()
        relative = unquote(url_path).lstrip("/")
        if not relative.startswith(f"{OUTPUT_PREFIX}/"):
            return False
        if host not in SITES:
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Unknown host: {host!r}")
            return True
        endpoint = relative.removeprefix(f"{OUTPUT_PREFIX}/")
        if endpoint == "lib.js":
            self._send_output_response(_lib_js(), "text/javascript", send_body)
        elif endpoint == "markers":
            scanner = self.server.marker_scanner
            if scanner is None:
                self.send_error(
                    HTTPStatus.NOT_FOUND,
                    "markers endpoint requires a marker_regex for this run",
                )
            else:
                body = "\n".join(scanner.snapshot()).encode("utf-8")
                self._send_output_response(body, "text/plain; charset=utf-8", send_body)
        elif endpoint == "log":
            self._serve_output_log(send_body)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)
        return True

    def _serve(self, send_body: bool) -> None:
        """Map the request to an output endpoint or docroot file and respond."""
        if self._maybe_serve_output(send_body):
            return
        file_path = self._resolve_file()
        if file_path is None:
            return
        status, extra_headers = _load_extra_headers(file_path)
        body = file_path.read_bytes()
        # Sidecar-settable 204/304 must carry neither framing nor a body.
        bodyless = status in (204, 304)
        self.send_response(status)
        if not bodyless:
            if not any(name.lower() == "content-type" for name, _ in extra_headers):
                content_type = (
                    mimetypes.guess_type(file_path.name)[0]
                    or "application/octet-stream"
                )
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers:
            if name.lower() in _RESERVED_HEADERS:
                logger.warning(
                    "site-server: ignoring reserved header %r from sidecar", name
                )
                continue
            self.send_header(name, value)
        self.end_headers()
        if send_body and not bodyless:
            self.wfile.write(body)

    def do_GET(self) -> None:
        """Serve a GET request."""
        self._serve(send_body=True)

    def do_HEAD(self) -> None:
        """Serve a HEAD request."""
        self._serve(send_body=False)

    def do_OPTIONS(self) -> None:
        """Answer CORS preflight with the target's sidecar headers, no body.

        ``Access-Control-Allow-Methods``/``-Headers`` are reflected from the
        request unless the sidecar sets them explicitly; the sidecar's status
        override does not apply (preflight requires a 2xx).

        ``/_output/`` endpoints always answer with a permissive preflight.
        """
        _, url_path = self._resolve_host_and_path()
        if unquote(url_path).lstrip("/").startswith(f"{OUTPUT_PREFIX}/"):
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            requested_method = self.headers.get("Access-Control-Request-Method")
            if requested_method:
                self.send_header("Access-Control-Allow-Methods", requested_method)
            requested_headers = self.headers.get("Access-Control-Request-Headers")
            if requested_headers:
                self.send_header("Access-Control-Allow-Headers", requested_headers)
            self.end_headers()
            return
        file_path = self._resolve_file()
        if file_path is None:
            return
        _, extra_headers = _load_extra_headers(file_path)
        sidecar_names = {name.lower() for name, _ in extra_headers}
        self.send_response(HTTPStatus.NO_CONTENT)
        for name, value in extra_headers:
            if name.lower() in _RESERVED_HEADERS:
                continue
            self.send_header(name, value)
        requested_method = self.headers.get("Access-Control-Request-Method")
        if requested_method and "access-control-allow-methods" not in sidecar_names:
            self.send_header("Access-Control-Allow-Methods", requested_method)
        requested_headers = self.headers.get("Access-Control-Request-Headers")
        if requested_headers and "access-control-allow-headers" not in sidecar_names:
            self.send_header("Access-Control-Allow-Headers", requested_headers)
        self.end_headers()

    def do_POST(self) -> None:
        """Serve a POST request (body is drained and ignored)."""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._serve(send_body=True)

    def log_message(self, *args: Any) -> None:
        """Route request logging to the module debug log."""
        if args:
            logger.debug("site-server: %s", args[0] % args[1:])


class _SiteHTTPServer(ThreadingHTTPServer):
    """Loopback HTTP server carrying shared state for request handlers."""

    daemon_threads = True

    def __init__(
        self,
        docroot: Path,
        log_reader: LiveLogReader | None,
        marker_scanner: _LiveMarkerScanner | None,
    ) -> None:
        self.docroot = docroot
        self.log_reader = log_reader
        self.marker_scanner = marker_scanner
        super().__init__(("127.0.0.1", 0), _SiteRequestHandler)

    def handle_error(self, request: object, client_address: object) -> None:
        """Log handler errors (e.g. aborted connections) quietly."""
        logger.debug(
            "site-server: error handling request %s from %s\n%s",
            request,
            client_address,
            traceback.format_exc(),
        )


class SiteServer:
    """Background static file server for the cross-origin SITES.

    Binds 127.0.0.1 on an ephemeral port and serves *docroot* (created if
    missing) on a daemon thread until ``close()`` is called.

    When *log_reader* is given, the ``/_output/log`` endpoint serves the
    live browser logs; with *marker_pattern* also given, ``/_output/markers``
    serves the matching lines seen so far (see the module docstring).
    Endpoints without their backing argument answer 404.
    """

    def __init__(
        self,
        docroot: Path,
        *,
        log_reader: LiveLogReader | None = None,
        marker_pattern: re.Pattern[str] | None = None,
    ) -> None:
        docroot.mkdir(parents=True, exist_ok=True)
        self.docroot = docroot.resolve()
        marker_scanner = (
            _LiveMarkerScanner(log_reader, marker_pattern)
            if log_reader is not None and marker_pattern is not None
            else None
        )
        self._httpd = _SiteHTTPServer(self.docroot, log_reader, marker_scanner)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="site-server", daemon=True
        )
        self._thread.start()

    @property
    def port(self) -> int:
        """The TCP port the server is listening on."""
        return self._httpd.server_address[1]

    @property
    def pac_url(self) -> str:
        """The PAC data: URL that routes SITES to this server."""
        return build_pac_url(self.port)

    def close(self) -> None:
        """Stop the server and wait for the serving thread to exit."""
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@cache
def _lib_js() -> bytes:
    """Load the bundled in-page helper library."""
    return _LIB_JS_PATH.read_bytes()


def _load_extra_headers(file_path: Path) -> tuple[int, list[tuple[str, str]]]:
    """Parse the optional ``<file>^headers^`` sidecar for *file_path*.

    The sidecar contains one ``Name: value`` header per line; an optional
    first line ``HTTP <status-code>`` overrides the response status.

    Returns:
        Tuple of (status code, header name/value pairs).
    """
    status = int(HTTPStatus.OK)
    headers: list[tuple[str, str]] = []
    sidecar = file_path.with_name(file_path.name + _HEADERS_SUFFIX)
    if not sidecar.is_file():
        return status, headers
    for index, line in enumerate(sidecar.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        if index == 0 and line.upper().startswith("HTTP "):
            try:
                status = int(line.split()[1])
            except (IndexError, ValueError):
                logger.warning("site-server: bad status line in %s: %r", sidecar, line)
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
    return status, headers


def build_pac_url(port: int) -> str:
    """Return a ``data:`` PAC URL routing SITES to ``127.0.0.1:port``.

    Keeps ``localhost`` direct (so the testcase server still works) and
    routes every other host to a dead-end proxy, matching the network
    isolation of the default fuzzing PAC.

    Args:
        port: Site server port the PAC should route SITES to.
    """
    sites_check = " || ".join(f"host == '{site}'" for site in SITES)
    return (
        "data:text/plain,function FindProxyForURL(url, host) { "
        "if (host == 'localhost' || host == '127.0.0.1') { return 'DIRECT'; } "
        f"if ({sites_check}) {{ return 'PROXY 127.0.0.1:{port}'; }} "
        f"return '{_BLACKHOLE_PROXY}'; }}"
    )
