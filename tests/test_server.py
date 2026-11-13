"""Pruebas de integración de extremo a extremo del servidor HTTP y su capa de transporte."""

from __future__ import annotations

import base64
import json
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from server.config import ServerConfig, save_config
from server.logging_setup import ServerLogger
from server.security import hash_password
from server.socket_server import TCPHTTPServer


class InMemoryDuplexSocket:
    """
    Adaptador de socket en memoria para entornos con políticas de red restringidas
    (por ejemplo, contenedores o sandboxes que bloquean connect() con WinError 10013),
    ejecutando exactamente el mismo flujo `_handle_client_connection` del servidor.
    """

    def __init__(self, request_bytes: bytes) -> None:
        self._in_buf = bytearray(request_bytes)
        self._out_buf = bytearray()
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def recv(self, bufsize: int) -> bytes:
        if not self._in_buf:
            return b""
        chunk = bytes(self._in_buf[:bufsize])
        del self._in_buf[:bufsize]
        return chunk

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("Socket cerrado")
        self._out_buf.extend(data)

    def shutdown(self, how: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def get_response_bytes(self) -> bytes:
        return bytes(self._out_buf)


class TestHTTPServerIntegration(unittest.TestCase):
    """Levanta el servidor TCPHTTPServer real en un puerto efímero y prueba todo el flujo."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self._tmpdir.name).resolve()

        # Crear estructura aislada para la prueba
        self.www_dir = self.base_dir / "www"
        self.private_dir = self.www_dir / "private"
        self.admin_dir = self.base_dir / "admin"
        self.config_dir = self.base_dir / "config"
        self.logs_dir = self.base_dir / "logs"

        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.admin_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        # Copiar archivos del panel admin real
        project_root = Path(__file__).resolve().parent.parent
        for item in ("dashboard.html", "style.css", "app.js"):
            src = project_root / "admin" / item
            if src.exists():
                shutil.copy2(src, self.admin_dir / item)

        # Crear recursos estáticos y binarios de prueba
        (self.www_dir / "index.html").write_text(
            "<!DOCTYPE html><html><body><h1>Inicio de Prueba</h1></body></html>",
            encoding="utf-8",
        )
        (self.www_dir / "about.html").write_text(
            "<!DOCTYPE html><html><body><p>Acerca de</p></body></html>",
            encoding="utf-8",
        )
        (self.private_dir / "index.html").write_text(
            "<!DOCTYPE html><html><body><h1>Contenido Privado</h1></body></html>",
            encoding="utf-8",
        )
        self.binary_payload = bytes(range(256)) * 8  # 2048 bytes binarios puros (0x00..0xFF)
        (self.www_dir / "muestra.png").write_bytes(self.binary_payload)

        # Configurar credenciales de prueba
        self.admin_user = "admin"
        self.admin_pass = "SecretoUTN2026"
        self.config_path = self.config_dir / "server.json"

        self.config = ServerConfig(
            host="127.0.0.1",
            port=0,  # Puerto efímero asignado por el SO para pruebas
            document_root="www",
            admin_enabled=True,
            max_request_size=65536,
            socket_timeout=5,
            protected_directories=["/private"],
            admin_username=self.admin_user,
            admin_password_hash=hash_password(self.admin_pass),
        )

        self.logger = ServerLogger(logs_dir=self.logs_dir)
        self.server = TCPHTTPServer(
            config=self.config,
            config_path=self.config_path,
            logger=self.logger,
            base_dir=self.base_dir,
        )
        try:
            host, port = self.server.start_listening()
            self.host = host
            self.port = port
            self._server_thread: threading.Thread | None = threading.Thread(
                target=self.server.serve_forever,
                daemon=True,
            )
            self._server_thread.start()
        except PermissionError:
            # Si el entorno restringe bind(), igual podemos validar el pipeline completo del servidor
            self.host = "127.0.0.1"
            self.port = 8080
            self._server_thread = None

        self.config.port = self.port
        self.server.router._initial_binding["port"] = self.port
        save_config(self.config, self.config_path, base_dir=self.base_dir)

    def tearDown(self) -> None:
        self.server.stop()
        if self._server_thread is not None:
            self._server_thread.join(timeout=3.0)
        self.logger.close()
        self._tmpdir.cleanup()

    def _send_raw_http(self, raw_request: bytes) -> tuple[int, dict[str, str], bytes]:
        """
        Envía bytes crudos por un socket TCP real al servidor.
        Si el entorno de ejecución bloquea `connect()` por políticas de sandbox (WinError 10013),
        invoca `_handle_client_connection` con `InMemoryDuplexSocket` para verificar todo el pipeline.
        """
        full_response: bytes
        try:
            with socket.create_connection((self.host, self.port), timeout=5.0) as sock:
                sock.sendall(raw_request)
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            full_response = b"".join(chunks)
        except PermissionError:
            mem_sock = InMemoryDuplexSocket(raw_request)
            self.server._handle_client_connection(mem_sock, ("127.0.0.1", 50000))  # type: ignore[arg-type]
            full_response = mem_sock.get_response_bytes()

        header_block, body = full_response.split(b"\r\n\r\n", 1)
        lines = header_block.decode("iso-8859-1").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        status_code = int(status_parts[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status_code, headers, body

    def _basic_auth_header(self, user: str, password: str) -> str:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def test_get_root_returns_200_and_required_headers(self) -> None:
        req = f"GET / HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        status, headers, body = self._send_raw_http(req)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertEqual(headers.get("connection"), "close")
        self.assertEqual(int(headers.get("content-length", "-1")), len(body))
        self.assertIn(b"Inicio de Prueba", body)

    def test_get_nonexistent_file_returns_404(self) -> None:
        req = f"GET /no-existe.html HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        status, _, _ = self._send_raw_http(req)
        self.assertEqual(status, 404)

    def test_post_form_processed_correctly(self) -> None:
        form_body = b"alumno=Augusto&comision=Redes+UTN&mensaje=Hola+Servidor"
        req = (
            f"POST /contacto HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form_body)}\r\n\r\n"
        ).encode("ascii") + form_body

        status, headers, body = self._send_raw_http(req)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"Augusto", body)
        self.assertIn(b"Redes UTN", body)
        self.assertIn(b"Hola Servidor", body)

    def test_binary_file_served_without_corruption(self) -> None:
        req = f"GET /muestra.png HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        status, headers, body = self._send_raw_http(req)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-type"), "image/png")
        self.assertEqual(int(headers.get("content-length", "-1")), len(self.binary_payload))
        self.assertEqual(body, self.binary_payload)

    def test_path_traversal_over_socket_returns_403(self) -> None:
        for evil_target in ("/../config/server.json", "/%2e%2e/config/server.json"):
            req = f"GET {evil_target} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
            status, _, body = self._send_raw_http(req)
            self.assertEqual(status, 403)
            self.assertNotIn(b"admin_password_hash", body)

    def test_protected_directory_authentication_flow(self) -> None:
        # 1. Sin credenciales -> 401
        req_no_auth = f"GET /private/index.html HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        status1, headers1, _ = self._send_raw_http(req_no_auth)
        self.assertEqual(status1, 401)
        self.assertIn("basic", headers1.get("www-authenticate", "").lower())

        # 2. Credenciales incorrectas -> 401
        bad_auth = self._basic_auth_header(self.admin_user, "ClaveFalsa")
        req_bad_auth = (
            f"GET /private/index.html HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {bad_auth}\r\n\r\n"
        ).encode("ascii")
        status2, _, _ = self._send_raw_http(req_bad_auth)
        self.assertEqual(status2, 401)

        # 3. Credenciales correctas -> 200
        good_auth = self._basic_auth_header(self.admin_user, self.admin_pass)
        req_good_auth = (
            f"GET /private/index.html HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {good_auth}\r\n\r\n"
        ).encode("ascii")
        status3, _, body3 = self._send_raw_http(req_good_auth)
        self.assertEqual(status3, 200)
        self.assertIn(b"Contenido Privado", body3)

    def test_logs_record_access_and_errors_without_leaking_credentials(self) -> None:
        good_auth = self._basic_auth_header(self.admin_user, self.admin_pass)
        # Petición autenticada exitosa
        req_ok = (
            f"GET /private/index.html HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {good_auth}\r\n\r\n"
        ).encode("ascii")
        self._send_raw_http(req_ok)

        # Petición con error 404
        req_404 = f"GET /archivo-que-no-existe.txt HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        self._send_raw_http(req_404)

        access_content = self.logger.access_log_path.read_text(encoding="utf-8")
        error_content = self.logger.error_log_path.read_text(encoding="utf-8")

        self.assertIn("/private/index.html", access_content)
        self.assertIn("200", access_content)
        self.assertIn("/archivo-que-no-existe.txt", error_content)

        # Verificar que ni la contraseña ni el token Base64 aparezcan en los logs
        b64_secret = good_auth.split(" ")[1]
        for content in (access_content, error_content):
            self.assertNotIn(self.admin_pass, content)
            self.assertNotIn(b64_secret, content)
            self.assertNotIn("Authorization", content)

    def test_admin_endpoints_auth_csrf_validation_and_log_limits(self) -> None:
        # 1. /admin/api/status sin credenciales -> 401
        req_unauth = f"GET /admin/api/status HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
        status_unauth, _, _ = self._send_raw_http(req_unauth)
        self.assertEqual(status_unauth, 401)

        # 2. /admin/api/status con credenciales -> 200 y entrega token CSRF (sin exponer password hash)
        auth_hdr = self._basic_auth_header(self.admin_user, self.admin_pass)
        req_status = (
            f"GET /admin/api/status HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {auth_hdr}\r\n\r\n"
        ).encode("ascii")
        status_ok, _, body_status = self._send_raw_http(req_status)
        self.assertEqual(status_ok, 200)
        status_json = json.loads(body_status.decode("utf-8"))
        self.assertTrue(status_json["ok"])
        self.assertNotIn("admin_password_hash", json.dumps(status_json))
        csrf_token = status_json["csrf_token"]
        self.assertTrue(csrf_token)

        # 3. POST /admin/api/config sin token CSRF -> 403 Forbidden
        no_csrf_payload = json.dumps({"socket_timeout": 20}).encode("utf-8")
        req_no_csrf = (
            f"POST /admin/api/config HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {auth_hdr}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(no_csrf_payload)}\r\n\r\n"
        ).encode("ascii") + no_csrf_payload
        status_no_csrf, _, _ = self._send_raw_http(req_no_csrf)
        self.assertEqual(status_no_csrf, 403)

        # 4. POST /admin/api/config con puerto inválido -> 400 Bad Request
        invalid_payload = json.dumps({"port": 99999, "csrf_token": csrf_token}).encode("utf-8")
        req_bad_cfg = (
            f"POST /admin/api/config HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {auth_hdr}\r\n"
            f"Content-Type: application/json\r\n"
            f"X-CSRF-Token: {csrf_token}\r\n"
            f"Content-Length: {len(invalid_payload)}\r\n\r\n"
        ).encode("ascii") + invalid_payload
        status_bad_cfg, _, _ = self._send_raw_http(req_bad_cfg)
        self.assertEqual(status_bad_cfg, 400)

        # 5. POST /admin/api/config válido -> 200 OK y actualiza timeout en vivo
        valid_payload = json.dumps({"socket_timeout": 15, "csrf_token": csrf_token}).encode("utf-8")
        req_good_cfg = (
            f"POST /admin/api/config HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {auth_hdr}\r\n"
            f"Content-Type: application/json\r\n"
            f"X-CSRF-Token: {csrf_token}\r\n"
            f"Content-Length: {len(valid_payload)}\r\n\r\n"
        ).encode("ascii") + valid_payload
        status_good_cfg, _, body_good_cfg = self._send_raw_http(req_good_cfg)
        self.assertEqual(status_good_cfg, 200)
        updated_json = json.loads(body_good_cfg.decode("utf-8"))
        self.assertEqual(updated_json["config"]["socket_timeout"], 15)

        # 6. GET /admin/api/logs?limit=2 respeta el límite de líneas
        for i in range(5):
            r = f"GET /?iter={i} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode("ascii")
            self._send_raw_http(r)

        req_logs = (
            f"GET /admin/api/logs?limit=2 HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: {auth_hdr}\r\n\r\n"
        ).encode("ascii")
        status_logs, _, body_logs = self._send_raw_http(req_logs)
        self.assertEqual(status_logs, 200)
        logs_json = json.loads(body_logs.decode("utf-8"))
        self.assertLessEqual(len(logs_json["access_log"]), 2)


if __name__ == "__main__":
    unittest.main()
