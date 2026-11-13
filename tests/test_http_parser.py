"""Pruebas unitarias para el analizador HTTP/1.1 (server/http_parser.py)."""

from __future__ import annotations

import unittest

from server.http_parser import (
    HTTPParseError,
    parse_http_request_bytes,
    read_http_request,
)


class FakeFragmentedSocket:
    """Simula un socket TCP que entrega los bytes de a fragmentos pequeños."""

    def __init__(self, data: bytes, step: int = 7) -> None:
        self._data = data
        self._pos = 0
        self._step = step

    def recv(self, bufsize: int) -> bytes:
        if self._pos >= len(self._data):
            return b""
        n = min(bufsize, self._step, len(self._data) - self._pos)
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk


class TestHTTPParser(unittest.TestCase):
    """Verifica el cumplimiento del parser frente a casos válidos y defensivos."""

    def test_parse_valid_get_request(self) -> None:
        raw = (
            b"GET /index.html?lang=es HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            b"User-Agent: TestClient/1.0\r\n"
            b"Accept: text/html\r\n"
            b"\r\n"
        )
        req = parse_http_request_bytes(raw)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.target, "/index.html?lang=es")
        self.assertEqual(req.path, "/index.html")
        self.assertEqual(req.query_string, "lang=es")
        self.assertEqual(req.version, "HTTP/1.1")
        self.assertEqual(req.get_header("host"), "localhost:8080")
        self.assertEqual(req.body, b"")

    def test_parse_valid_post_with_body_and_content_length(self) -> None:
        body = b"alumno=Juan+Perez&comision=3K1"
        raw = (
            b"POST /contacto HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        req = parse_http_request_bytes(raw)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.path, "/contacto")
        self.assertEqual(req.body, body)
        self.assertEqual(req.get_header("content-length"), str(len(body)))

    def test_case_insensitive_headers(self) -> None:
        raw = (
            b"GET /about.html HTTP/1.1\r\n"
            b"hOsT: LocalHost:8080\r\n"
            b"cOnTeNt-tYpE: text/plain\r\n"
            b"X-CuStOm-HeAdEr: Valor123\r\n"
            b"\r\n"
        )
        req = parse_http_request_bytes(raw)
        self.assertEqual(req.get_header("HOST"), "LocalHost:8080")
        self.assertEqual(req.get_header("host"), "LocalHost:8080")
        self.assertEqual(req.get_header("Content-Type"), "text/plain")
        self.assertEqual(req.get_header("x-custom-header"), "Valor123")

    def test_fragmented_tcp_stream_reading(self) -> None:
        body = b"campo1=valor1&campo2=valor2_largo"
        raw = (
            b"POST /contacto HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        fake_sock = FakeFragmentedSocket(raw, step=5)
        req = read_http_request(fake_sock, max_request_size=4096)  # type: ignore[arg-type]
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.body, body)

    def test_malformed_request_missing_host_in_http11(self) -> None:
        raw = b"GET /index.html HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
        with self.assertRaises(HTTPParseError) as ctx:
            parse_http_request_bytes(raw)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_malformed_request_line_and_headers(self) -> None:
        # Sin versión HTTP
        with self.assertRaises(HTTPParseError) as ctx1:
            parse_http_request_bytes(b"GET /index.html\r\nHost: localhost\r\n\r\n")
        self.assertEqual(ctx1.exception.status_code, 400)

        # Encabezado sin ':'
        with self.assertRaises(HTTPParseError) as ctx2:
            parse_http_request_bytes(b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n")
        self.assertEqual(ctx2.exception.status_code, 400)

    def test_incomplete_request_or_body(self) -> None:
        # Sin \r\n\r\n final
        with self.assertRaises(HTTPParseError) as ctx1:
            parse_http_request_bytes(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        self.assertEqual(ctx1.exception.status_code, 400)

        # Content-Length mayor que los bytes realmente enviados
        raw_short_body = (
            b"POST /contacto HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 50\r\n\r\n"
            b"solo_12_byte"
        )
        with self.assertRaises(HTTPParseError) as ctx2:
            parse_http_request_bytes(raw_short_body)
        self.assertEqual(ctx2.exception.status_code, 400)

    def test_request_too_large_returns_413(self) -> None:
        large_body = b"A" * 2048
        raw = (
            b"POST /contacto HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(large_body)}\r\n\r\n".encode("ascii")
            + large_body
        )
        with self.assertRaises(HTTPParseError) as ctx:
            parse_http_request_bytes(raw, max_request_size=1024)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_unsupported_method_returns_405_with_allow_header(self) -> None:
        raw = b"DELETE /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
        with self.assertRaises(HTTPParseError) as ctx:
            parse_http_request_bytes(raw)
        self.assertEqual(ctx.exception.status_code, 405)
        self.assertIn("Allow", ctx.exception.headers)

    def test_unsupported_http_version_returns_505(self) -> None:
        raw = b"GET / HTTP/2.0\r\nHost: localhost\r\n\r\n"
        with self.assertRaises(HTTPParseError) as ctx:
            parse_http_request_bytes(raw)
        self.assertEqual(ctx.exception.status_code, 505)

    def test_transfer_encoding_chunked_rejected_with_501(self) -> None:
        raw = (
            b"POST /contacto HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"4\r\ntest\r\n0\r\n\r\n"
        )
        with self.assertRaises(HTTPParseError) as ctx:
            parse_http_request_bytes(raw)
        self.assertEqual(ctx.exception.status_code, 501)


if __name__ == "__main__":
    unittest.main()
