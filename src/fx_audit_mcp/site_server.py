"""Built-in cross-origin site server for browser testcases.

Hosts ``http://example.site/``, ``http://victim.site/`` and
``http://attacker.site/`` during a run without modifying ``/etc/hosts``:
Firefox is pointed at a PAC (proxy auto-config) that routes requests for
these hosts to this server, which answers the resulting proxy-form HTTP
requests from a shared static docroot. Every other host keeps routing to a
dead-end proxy, preserving the fuzzing prefs' network isolation.
"""

import logging
import mimetypes
import threading
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

logger = logging.getLogger(__name__)

SITES: tuple[str, ...] = ("example.site", "victim.site", "attacker.site")

# Dead-end proxy used by the prefpicker browser-fuzzing template to blackhole
# non-localhost traffic; hosts other than SITES keep routing here.
_BLACKHOLE_PROXY = "PROXY 127.0.0.1:6"
_HEADERS_SUFFIX = "^headers^"

# Framing/connection response headers the server must own; sidecar values for
# these would emit duplicates and desync the keep-alive connection.
_RESERVED_HEADERS = frozenset({"connection", "content-length", "transfer-encoding"})


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

    def _serve(self, send_body: bool) -> None:
        """Map the request to a docroot file and send the response."""
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
        """
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
    """Loopback HTTP server carrying the docroot for request handlers."""

    daemon_threads = True

    def __init__(self, docroot: Path) -> None:
        self.docroot = docroot
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
    """

    def __init__(self, docroot: Path) -> None:
        docroot.mkdir(parents=True, exist_ok=True)
        self.docroot = docroot.resolve()
        self._httpd = _SiteHTTPServer(self.docroot)
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
