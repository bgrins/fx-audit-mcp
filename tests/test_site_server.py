"""Tests for the built-in cross-origin site server."""

import http.client
from collections.abc import Iterator
from email.message import Message
from pathlib import Path

import pytest

from fx_audit_mcp.site_server import SITES, SiteServer, build_pac_url


@pytest.fixture(name="server")
def server_fixture(tmp_path: Path) -> Iterator[SiteServer]:
    """Run a SiteServer on a temp docroot for the duration of a test."""
    server = SiteServer(tmp_path / "sites")
    yield server
    server.close()


def _request(
    server: SiteServer,
    target: str,
    method: str = "GET",
    host: str | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, Message]:
    """Send a request to *server* and return (status, body, headers)."""
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    try:
        request_headers = dict(headers or {})
        if host:
            request_headers["Host"] = host
        conn.request(method, target, body=body, headers=request_headers)
        response = conn.getresponse()
        return response.status, response.read(), response.headers
    finally:
        conn.close()


@pytest.mark.parametrize("site", SITES)
def test_proxy_form_serves_shared_docroot(server: SiteServer, site: str) -> None:
    """Verify proxy-form requests serve the shared docroot on every site."""
    (server.docroot / "poc.html").write_text("<html>poc</html>", encoding="utf-8")
    status, body, headers = _request(server, f"http://{site}/poc.html")
    assert status == 200
    assert body == b"<html>poc</html>"
    assert headers["Content-Type"] == "text/html"


def test_origin_form_uses_host_header(server: SiteServer) -> None:
    """Verify origin-form requests resolve the site from the Host header."""
    (server.docroot / "page.html").write_text("hi", encoding="utf-8")
    status, body, _ = _request(server, "/page.html", host="victim.site")
    assert status == 200
    assert body == b"hi"


def test_unknown_host_rejected(server: SiteServer) -> None:
    """Ensure requests for hosts outside SITES are refused."""
    (server.docroot / "poc.html").write_text("poc", encoding="utf-8")
    status, _, _ = _request(server, "http://mozilla.org/poc.html")
    assert status == 502


def test_missing_file_returns_404(server: SiteServer) -> None:
    """Verify a request for a nonexistent docroot file returns 404."""
    status, _, _ = _request(server, "http://example.site/nope.html")
    assert status == 404


def test_path_traversal_blocked(server: SiteServer, tmp_path: Path) -> None:
    """Ensure paths escaping the docroot are refused, including encoded dots."""
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    for path in ("/../secret.txt", "/%2e%2e/secret.txt"):
        status, body, _ = _request(server, f"http://victim.site{path}")
        assert status == 403
        assert b"secret" not in body


def test_directory_serves_index_html(server: SiteServer) -> None:
    """Verify directory requests fall back to index.html."""
    subdir = server.docroot / "sub"
    subdir.mkdir()
    (server.docroot / "index.html").write_text("root", encoding="utf-8")
    (subdir / "index.html").write_text("sub", encoding="utf-8")
    assert _request(server, "http://example.site/")[1] == b"root"
    assert _request(server, "http://example.site/sub/")[1] == b"sub"


def test_headers_sidecar_overrides_status_and_headers(server: SiteServer) -> None:
    """Verify a ^headers^ sidecar customizes status and response headers."""
    (server.docroot / "cors.html").write_text("x", encoding="utf-8")
    (server.docroot / "cors.html^headers^").write_text(
        "HTTP 418\nAccess-Control-Allow-Origin: *\n", encoding="utf-8"
    )
    status, _, headers = _request(server, "http://attacker.site/cors.html")
    assert status == 418
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_headers_sidecar_not_served(server: SiteServer) -> None:
    """Ensure the ^headers^ sidecar itself is never served."""
    (server.docroot / "cors.html").write_text("x", encoding="utf-8")
    (server.docroot / "cors.html^headers^").write_text("HTTP 418\n", encoding="utf-8")
    status, _, _ = _request(server, "http://attacker.site/cors.html%5Eheaders%5E")
    assert status == 404


def test_sidecar_framing_headers_ignored(server: SiteServer) -> None:
    """Ensure sidecar framing headers can't emit duplicates and desync."""
    (server.docroot / "framed.html").write_text("hello", encoding="utf-8")
    (server.docroot / "framed.html^headers^").write_text(
        "Content-Length: 9999\nTransfer-Encoding: chunked\n"
        "Connection: close\nX-Ok: 1\n",
        encoding="utf-8",
    )
    status, body, headers = _request(server, "http://victim.site/framed.html")
    assert status == 200
    assert body == b"hello"
    assert headers.get_all("Content-Length") == ["5"]
    assert headers.get_all("Transfer-Encoding") is None
    assert headers["X-Ok"] == "1"


def test_sidecar_content_type_overrides_default(server: SiteServer) -> None:
    """Verify a sidecar Content-Type replaces the guessed one, no duplicate."""
    (server.docroot / "data.html").write_text("x", encoding="utf-8")
    (server.docroot / "data.html^headers^").write_text(
        "Content-Type: application/json\n", encoding="utf-8"
    )
    status, _, headers = _request(server, "http://victim.site/data.html")
    assert status == 200
    assert headers.get_all("Content-Type") == ["application/json"]


def test_sidecar_204_omits_body_and_framing(server: SiteServer) -> None:
    """Verify a sidecar HTTP 204 yields no body and no framing headers."""
    (server.docroot / "nc.html").write_text("ignored", encoding="utf-8")
    (server.docroot / "nc.html^headers^").write_text("HTTP 204\n", encoding="utf-8")
    status, body, headers = _request(server, "http://victim.site/nc.html")
    assert status == 204
    assert body == b""
    assert headers.get_all("Content-Length") is None


def test_directory_without_trailing_slash_serves_index(server: SiteServer) -> None:
    """Verify a bare directory path serves that directory's index.html."""
    subdir = server.docroot / "app"
    subdir.mkdir()
    (subdir / "index.html").write_text("app index", encoding="utf-8")
    status, body, _ = _request(server, "http://example.site/app")
    assert status == 200
    assert body == b"app index"


def test_options_preflight_reflects_cors(server: SiteServer) -> None:
    """Verify OPTIONS preflight returns sidecar + reflected CORS headers."""
    (server.docroot / "api.json").write_text("{}", encoding="utf-8")
    (server.docroot / "api.json^headers^").write_text(
        "Access-Control-Allow-Origin: *\n", encoding="utf-8"
    )
    status, body, headers = _request(
        server,
        "http://victim.site/api.json",
        method="OPTIONS",
        headers={
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "x-custom",
        },
    )
    assert status == 204
    assert body == b""
    assert headers["Access-Control-Allow-Origin"] == "*"
    assert headers["Access-Control-Allow-Methods"] == "PUT"
    assert headers["Access-Control-Allow-Headers"] == "x-custom"


def test_post_serves_file(server: SiteServer) -> None:
    """Verify POST requests drain the body and serve the target file."""
    (server.docroot / "sink.html").write_text("sink", encoding="utf-8")
    status, body, _ = _request(
        server, "http://victim.site/sink.html", method="POST", body=b"payload"
    )
    assert status == 200
    assert body == b"sink"


def test_query_string_ignored(server: SiteServer) -> None:
    """Verify query strings are stripped when mapping to docroot files."""
    (server.docroot / "poc.html").write_text("poc", encoding="utf-8")
    status, body, _ = _request(server, "http://victim.site/poc.html?x=1&y=2")
    assert status == 200
    assert body == b"poc"


def test_docroot_created_if_missing(tmp_path: Path) -> None:
    """Verify the docroot directory is created when it does not exist."""
    docroot = tmp_path / "made" / "up"
    server = SiteServer(docroot)
    try:
        assert docroot.is_dir()
        assert server.docroot == docroot.resolve()
    finally:
        server.close()


def test_pac_url_property_embeds_port(server: SiteServer) -> None:
    """Verify the server's pac_url embeds its own listening port."""
    assert f"PROXY 127.0.0.1:{server.port}" in server.pac_url


def test_build_pac_url_routes_sites_and_blackholes_rest() -> None:
    """Verify the PAC routes SITES to the given port and dead-ends others."""
    pac = build_pac_url(12345)
    assert pac.startswith("data:text/plain,function FindProxyForURL")
    assert "\n" not in pac
    for site in SITES:
        assert f"host == '{site}'" in pac
    assert "PROXY 127.0.0.1:12345" in pac
    assert pac.endswith("return 'PROXY 127.0.0.1:6'; }")
    assert "host == 'localhost'" in pac
