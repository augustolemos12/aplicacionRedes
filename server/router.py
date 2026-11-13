"""Enrutador de solicitudes HTTP: archivos estáticos, formularios POST y API administrativa."""

from __future__ import annotations

import html
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs

from server.config import (
    RESTART_REQUIRED_FIELDS,
    ConfigValidationError,
    ServerConfig,
    save_config,
)
from server.http_parser import HTTPRequest
from server.logging_setup import ServerLogger
from server.response import (
    HTTPResponse,
    error_response,
    guess_mime_type,
    html_response,
    json_response,
)
from server.security import (
    CSRFTokenManager,
    SecurityViolationError,
    hash_password,
    is_path_protected,
    normalize_url_path,
    resolve_safe_path,
    verify_basic_auth,
)


class HTTPRouter:
    """Enruta cada solicitud HTTP validando permisos, rutas y métodos."""

    def __init__(
        self,
        config: ServerConfig,
        config_path: Path,
        logger: ServerLogger,
        base_dir: Path | None = None,
    ) -> None:
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.config = config
        self.config_path = config_path.resolve()
        self.logger = logger
        self.admin_dir = (self.base_dir / "admin").resolve()
        self.csrf_manager = CSRFTokenManager()
        self._lock = threading.Lock()
        self._start_time = time.time()
        self._request_count = 0

        # Guardamos los valores con los que inició el socket para informar si un cambio requiere reinicio
        self._initial_binding = {
            "host": config.host,
            "port": config.port,
            "document_root": config.document_root,
        }

    @property
    def document_root(self) -> Path:
        """Obtiene el DocumentRoot resuelto actualmente."""
        return self.config.resolve_document_root(self.base_dir)

    def handle_request(self, request: HTTPRequest) -> HTTPResponse:
        """Punto de entrada principal para procesar una solicitud ya parseada."""
        with self._lock:
            self._request_count += 1

        if request.method not in ("GET", "HEAD", "POST"):
            self.logger.log_error(
                "METHOD_NOT_ALLOWED",
                request.client_ip,
                f"Método no permitido: {request.method}",
                request.target,
            )
            return error_response(
                405,
                f"El método {request.method} no está soportado por este recurso.",
                headers={"Allow": "GET, HEAD, POST"},
            )

        # 1. Verificar primero que la ruta no contenga secuencias de escape (Path Traversal)
        try:
            clean_path = normalize_url_path(request.path)
        except SecurityViolationError as exc:
            self.logger.log_error(
                "SECURITY_PATH_TRAVERSAL",
                request.client_ip,
                f"Intento de ruta maliciosa bloqueado: {exc.message}",
                request.target,
            )
            return error_response(403, "Acceso denegado: la ruta solicitada es inválida o insegura.")

        # 2. Enrutar peticiones destinadas al panel y endpoints administrativos (/admin...)
        if clean_path == "/admin" or clean_path.startswith("/admin/"):
            return self._handle_admin_request(request, clean_path)

        # 3. Verificar resolución dentro de DocumentRoot antes de cualquier acceso al disco
        try:
            resolved_path = resolve_safe_path(self.document_root, request.path)
        except SecurityViolationError as exc:
            self.logger.log_error(
                "SECURITY_DOCROOT_ESCAPE",
                request.client_ip,
                f"Bloqueo de acceso fuera de DocumentRoot: {exc.message}",
                request.target,
            )
            return error_response(403, "Acceso prohibido fuera del DocumentRoot del servidor.")

        # 4. Verificar si la ruta pertenece a un directorio protegido por autenticación
        if is_path_protected(clean_path, self.config.protected_directories):
            auth_header = request.get_header("authorization")
            if not verify_basic_auth(
                auth_header,
                self.config.admin_username,
                self.config.admin_password_hash,
            ):
                self.logger.log_error(
                    "AUTH_REQUIRED",
                    request.client_ip,
                    "Acceso no autorizado a directorio protegido (credenciales ausentes o inválidas).",
                    request.target,
                )
                return error_response(
                    401,
                    "Se requiere autenticación válida (HTTP Basic) para acceder a este directorio protegido.",
                    headers={"WWW-Authenticate": 'Basic realm="Area protegida"'},
                )

        # 5. Despachar según método HTTP
        if request.method == "POST":
            return self._handle_public_post(request, clean_path)

        return self._serve_static_resource(request, resolved_path)

    def _serve_static_resource(self, request: HTTPRequest, resolved_path: Path) -> HTTPResponse:
        """Sirve un archivo estático desde el DocumentRoot de forma binaria y segura."""
        doc_root = self.document_root

        target_file = resolved_path
        if target_file.is_dir():
            index_candidate = target_file / "index.html"
            try:
                resolved_index = index_candidate.resolve()
            except OSError:
                return error_response(403, "No se pudo acceder al índice del directorio.")

            if not resolved_index.is_relative_to(doc_root):
                self.logger.log_error(
                    "SECURITY_SYMLINK_ESCAPE",
                    request.client_ip,
                    "El archivo index.html resuelve fuera del DocumentRoot.",
                    request.target,
                )
                return error_response(403, "Acceso denegado: enlace simbólico fuera del DocumentRoot.")

            if not resolved_index.exists() or not resolved_index.is_file():
                self.logger.log_error(
                    "DIRECTORY_LISTING_DENIED",
                    request.client_ip,
                    "Listado de directorio deshabilitado y no existe index.html.",
                    request.target,
                )
                return error_response(403, "El listado de directorios está deshabilitado por seguridad.")
            target_file = resolved_index

        if not target_file.exists() or not target_file.is_file():
            self.logger.log_error(
                "NOT_FOUND",
                request.client_ip,
                "Recurso estático no encontrado en DocumentRoot.",
                request.target,
            )
            return error_response(404, f"El recurso solicitado '{request.path}' no existe en este servidor.")

        try:
            content_bytes = target_file.read_bytes()
        except OSError as exc:
            self.logger.log_error(
                "FILE_READ_ERROR",
                request.client_ip,
                f"Error de E/S al leer archivo estático: {exc}",
                request.target,
            )
            return error_response(500, "No se pudo leer el recurso solicitado.")

        mime_type = guess_mime_type(target_file)
        return HTTPResponse(
            status_code=200,
            body=content_bytes,
            content_type=mime_type,
        )

    def _handle_public_post(self, request: HTTPRequest, clean_path: str) -> HTTPResponse:
        """
        Procesa formularios POST enviados al servidor (demostración académica de POST HTTP).
        Soporta `application/x-www-form-urlencoded`.
        """
        allowed_post_paths = {"/", "/index.html", "/contacto", "/form", "/submit"}
        if clean_path not in allowed_post_paths:
            self.logger.log_error(
                "POST_PATH_NOT_FOUND",
                request.client_ip,
                f"Ruta POST no habilitada: {clean_path}",
                request.target,
            )
            return error_response(404, f"No existe un procesador POST en la ruta '{clean_path}'.")

        content_type = (request.get_header("content-type") or "").lower()
        if content_type and not content_type.startswith("application/x-www-form-urlencoded"):
            self.logger.log_error(
                "UNSUPPORTED_MEDIA_TYPE",
                request.client_ip,
                f"Content-Type no soportado en formulario POST: {content_type}",
                request.target,
            )
            return error_response(
                415,
                "Tipo de contenido no soportado. Para este formulario utilice 'application/x-www-form-urlencoded'.",
            )

        try:
            body_text = request.body.decode("utf-8")
        except UnicodeDecodeError:
            self.logger.log_error(
                "POST_DECODE_ERROR",
                request.client_ip,
                "El cuerpo POST no contiene texto UTF-8 válido.",
                request.target,
            )
            return error_response(400, "El cuerpo del formulario contiene una codificación de caracteres inválida.")

        parsed_fields = parse_qs(body_text, keep_blank_values=True, max_num_fields=50)

        rows_html: list[str] = []
        if not parsed_fields:
            rows_html.append('<tr><td colspan="2"><em>No se enviaron campos en el cuerpo del formulario.</em></td></tr>')
        else:
            for field_name, values in parsed_fields.items():
                safe_key = html.escape(field_name)
                safe_val = html.escape(", ".join(values))
                rows_html.append(f"<tr><th>{safe_key}</th><td>{safe_val}</td></tr>")

        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        joined_rows = "\n          ".join(rows_html)

        response_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>POST PAYLOAD INSPECTOR — Servidor HTTP UTN FRM</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="site-header">
    <div class="sys-topbar">
      <div class="container sys-topbar-flex">
        <div class="telemetry-group">
          <span class="telemetry-item">METHOD: <strong>POST</strong></span>
          <span class="telemetry-item">CONTENT-LENGTH: <strong>{len(request.body)} BYTES</strong></span>
        </div>
        <div class="telemetry-group">
          <span class="status-tag">STATUS: 200 OK</span>
        </div>
      </div>
    </div>
    <div class="container header-flex">
      <div class="brand">
        <img src="/logo.svg" alt="Terminal Icon" class="logo" width="44" height="44">
        <div>
          <h1>Respuesta del Servidor // Transacción POST</h1>
          <p class="subtitle">LECTURA DE FLUJO TCP GOBERNADA POR ENCABEZADO <code>Content-Length</code></p>
        </div>
      </div>
      <nav class="main-nav">
        <a href="/">[01] Inicio</a>
        <a href="/about.html">[02] Manual TCP/HTTP</a>
        <a href="/private/">[03] /private</a>
        <a href="/admin">[04] Consola Admin</a>
      </nav>
    </div>
  </header>
  <main class="container">
    <section class="card">
      <div class="card-header">
        <h2>[DECODED FORM PAYLOAD // application/x-www-form-urlencoded]</h2>
        <span class="card-tag">BYTES: {len(request.body)}</span>
      </div>
      <div class="card-body">
        <p>El servidor leyó exactamente <strong>{len(request.body)} bytes</strong> del socket TCP correspondientes al cuerpo de la petición:</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>PARAMETER KEY</th>
              <th>SANITIZED VALUE</th>
            </tr>
          </thead>
          <tbody>
            {joined_rows}
          </tbody>
        </table>
        <div class="meta-box">
          <p><strong>TARGET ENDPOINT:</strong> <code>{html.escape(clean_path)}</code></p>
          <p><strong>CLIENT ADDRESS:</strong> <code>{html.escape(request.client_ip)}</code></p>
          <p><strong>SERVER TIMESTAMP:</strong> <code>{timestamp_str}</code></p>
        </div>
        <p style="margin-top: 1.5rem;">
          <a href="/" class="btn">&lt; RETURN TO MAIN CONSOLE</a>
        </p>
      </div>
    </section>
  </main>
  <footer class="site-footer">
    <div class="container">
      <span>UTN FACULTAD REGIONAL MENDOZA // REDES DE INFORMACIÓN // POST INSPECTOR</span>
    </div>
  </footer>
</body>
</html>
"""
        return html_response(response_html, status_code=200)

    def _handle_admin_request(self, request: HTTPRequest, clean_path: str) -> HTTPResponse:
        """Gestiona la interfaz administrativa y sus endpoints JSON bajo autenticación obligatoria."""
        is_api = clean_path.startswith("/admin/api/")

        if not self.config.admin_enabled:
            self.logger.log_error(
                "ADMIN_DISABLED",
                request.client_ip,
                "Intento de acceso al panel administrativo estando deshabilitado.",
                request.target,
            )
            return error_response(403, "El panel de administración está deshabilitado en la configuración.", as_json=is_api)

        if not self.config.admin_password_hash:
            self.logger.log_error(
                "ADMIN_NO_PASSWORD_CONFIGURED",
                request.client_ip,
                "Intento de acceso a /admin sin hash de contraseña configurado en server.json.",
                request.target,
            )
            return error_response(
                401,
                "Las credenciales de administrador aún no fueron inicializadas. "
                "Ejecute 'python main.py --set-password' o 'python main.py --init-demo'.",
                headers={"WWW-Authenticate": 'Basic realm="Panel Administrativo"'},
                as_json=is_api,
            )

        auth_header = request.get_header("authorization")
        if not verify_basic_auth(
            auth_header,
            self.config.admin_username,
            self.config.admin_password_hash,
        ):
            self.logger.log_error(
                "ADMIN_AUTH_FAILED",
                request.client_ip,
                "Fallo de autenticación HTTP Basic en ruta administrativa.",
                request.target,
            )
            return error_response(
                401,
                "Autenticación requerida para acceder al panel de administración.",
                headers={"WWW-Authenticate": 'Basic realm="Panel Administrativo"'},
                as_json=is_api,
            )

        # Rutas de archivos estáticos de la interfaz administrativa
        if clean_path in ("/admin", "/admin/", "/admin/dashboard.html"):
            if request.method not in ("GET", "HEAD"):
                return error_response(405, "Método no permitido.", headers={"Allow": "GET, HEAD"})
            return self._serve_admin_asset("dashboard.html")

        if clean_path == "/admin/style.css":
            if request.method not in ("GET", "HEAD"):
                return error_response(405, "Método no permitido.", headers={"Allow": "GET, HEAD"})
            return self._serve_admin_asset("style.css")

        if clean_path == "/admin/app.js":
            if request.method not in ("GET", "HEAD"):
                return error_response(405, "Método no permitido.", headers={"Allow": "GET, HEAD"})
            return self._serve_admin_asset("app.js")

        # Rutas de la API administrativa
        if clean_path == "/admin/api/status":
            if request.method not in ("GET", "HEAD"):
                return error_response(405, "Método no permitido.", headers={"Allow": "GET, HEAD"}, as_json=True)
            return self._admin_api_status()

        if clean_path == "/admin/api/logs":
            if request.method not in ("GET", "HEAD"):
                return error_response(405, "Método no permitido.", headers={"Allow": "GET, HEAD"}, as_json=True)
            return self._admin_api_logs(request)

        if clean_path == "/admin/api/config":
            if request.method != "POST":
                return error_response(405, "Use POST para actualizar la configuración.", headers={"Allow": "POST"}, as_json=True)
            return self._admin_api_update_config(request)

        return error_response(404, "Ruta administrativa inexistente.", as_json=is_api)

    def _serve_admin_asset(self, filename: str) -> HTTPResponse:
        """Sirve un archivo propio del directorio admin/."""
        asset_path = (self.admin_dir / filename).resolve()
        if not asset_path.is_relative_to(self.admin_dir) or not asset_path.is_file():
            return error_response(404, "Archivo del panel administrativo no encontrado.")
        content = asset_path.read_bytes()
        return HTTPResponse(status_code=200, body=content, content_type=guess_mime_type(asset_path))

    def _admin_api_status(self) -> HTTPResponse:
        """Devuelve el estado general del servidor y la configuración activa (sin secretos)."""
        with self._lock:
            uptime = int(time.time() - self._start_time)
            req_count = self._request_count
            cfg_dict = self.config.to_dict(include_sensitive=False)

        pending_restart: list[str] = []
        for field_name in RESTART_REQUIRED_FIELDS:
            if getattr(self.config, field_name) != self._initial_binding[field_name]:
                pending_restart.append(field_name)

        csrf_token = self.csrf_manager.generate_token(self.config.admin_username)
        payload = {
            "ok": True,
            "status": "running",
            "uptime_seconds": uptime,
            "total_requests": req_count,
            "active_binding": dict(self._initial_binding),
            "config": cfg_dict,
            "restart_required_fields": list(RESTART_REQUIRED_FIELDS),
            "pending_restart_fields": pending_restart,
            "csrf_token": csrf_token,
            "security_notice": (
                "Servidor HTTP educativo sin TLS (HTTPS). La autenticación HTTP Basic transmite "
                "credenciales codificadas en Base64; úsese únicamente en entornos locales o LAN de laboratorio."
            ),
        }
        return json_response(payload, status_code=200)

    def _admin_api_logs(self, request: HTTPRequest) -> HTTPResponse:
        """Devuelve las últimas líneas de access.log y error.log respetando el límite máximo."""
        limit = 40
        if request.query_string:
            qs = parse_qs(request.query_string)
            if "limit" in qs and qs["limit"]:
                try:
                    parsed_limit = int(qs["limit"][0])
                    limit = max(1, min(parsed_limit, 100))
                except ValueError:
                    return error_response(400, "El parámetro 'limit' debe ser un número entero.", as_json=True)

        access_lines = self.logger.read_recent_access_logs(limit=limit)
        error_lines = self.logger.read_recent_error_logs(limit=limit)
        return json_response(
            {
                "ok": True,
                "max_lines": limit,
                "access_log": access_lines,
                "error_log": error_lines,
            },
            status_code=200,
        )

    def _admin_api_update_config(self, request: HTTPRequest) -> HTTPResponse:
        """
        Valida y actualiza parámetros permitidos de la configuración.
        Verifica token CSRF y rechaza valores fuera de rango o inseguros.
        """
        content_type = (request.get_header("content-type") or "").lower()
        if "application/json" not in content_type:
            return error_response(415, "Se requiere 'Content-Type: application/json'.", as_json=True)

        try:
            body_data = json.loads(request.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.logger.log_error(
                "ADMIN_INVALID_JSON",
                request.client_ip,
                "Cuerpo JSON mal formado en actualización de configuración.",
                request.target,
            )
            return error_response(400, "El cuerpo de la solicitud no es un JSON válido.", as_json=True)

        if not isinstance(body_data, dict):
            return error_response(400, "Se esperaba un objeto JSON con los parámetros.", as_json=True)

        # Verificación CSRF: encabezado X-CSRF-Token o propiedad csrf_token en el cuerpo
        csrf_token = request.get_header("x-csrf-token") or body_data.get("csrf_token")
        if not self.csrf_manager.validate_token(csrf_token, self.config.admin_username):
            self.logger.log_error(
                "ADMIN_CSRF_REJECTED",
                request.client_ip,
                "Petición POST administrativa rechazada por token CSRF ausente o inválido.",
                request.target,
            )
            return error_response(
                403,
                "Token CSRF inválido o expirado. Recargue el panel administrativo e intente nuevamente.",
                as_json=True,
            )

        # Prohibir la modificación directa del hash de contraseña como texto libre
        if "admin_password_hash" in body_data:
            self.logger.log_error(
                "ADMIN_FORBIDDEN_FIELD",
                request.client_ip,
                "Intento de sobrescribir admin_password_hash directamente desde la API de configuración.",
                request.target,
            )
            return error_response(
                400,
                "No se permite modificar 'admin_password_hash' directamente. Utilice el campo 'new_password' si desea cambiar la clave.",
                as_json=True,
            )

        editable_fields = {
            "host",
            "port",
            "document_root",
            "max_request_size",
            "socket_timeout",
            "protected_directories",
            "new_password",
            "csrf_token",
        }
        unknown_fields = set(body_data.keys()) - editable_fields
        if unknown_fields:
            return error_response(
                400,
                f"Parámetros no permitidos o desconocidos: {', '.join(sorted(unknown_fields))}",
                as_json=True,
            )

        with self._lock:
            candidate_dict = self.config.to_dict(include_sensitive=True)
            for key in ("host", "port", "document_root", "max_request_size", "socket_timeout", "protected_directories"):
                if key in body_data:
                    candidate_dict[key] = body_data[key]

            if "new_password" in body_data and body_data["new_password"]:
                new_pass = body_data["new_password"]
                if not isinstance(new_pass, str) or len(new_pass) < 6:
                    return error_response(
                        400,
                        "La nueva contraseña debe ser una cadena de al menos 6 caracteres.",
                        as_json=True,
                    )
                candidate_dict["admin_password_hash"] = hash_password(new_pass)

            try:
                new_config = ServerConfig.from_dict(candidate_dict, base_dir=self.base_dir)
                save_config(new_config, self.config_path, base_dir=self.base_dir)
            except ConfigValidationError as exc:
                self.logger.log_error(
                    "ADMIN_CONFIG_INVALID",
                    request.client_ip,
                    f"Configuración rechazada por validación: {exc}",
                    request.target,
                )
                return error_response(400, str(exc), as_json=True)
            except OSError as exc:
                self.logger.log_error(
                    "ADMIN_CONFIG_SAVE_ERROR",
                    request.client_ip,
                    f"No se pudo guardar server.json: {exc}",
                    request.target,
                )
                return error_response(500, "No se pudo escribir el archivo de configuración.", as_json=True)

            self.config = new_config

        pending_restart = [
            field_name
            for field_name in RESTART_REQUIRED_FIELDS
            if getattr(self.config, field_name) != self._initial_binding[field_name]
        ]

        return json_response(
            {
                "ok": True,
                "message": "Configuración validada y guardada correctamente.",
                "config": self.config.to_dict(include_sensitive=False),
                "requires_restart": bool(pending_restart),
                "pending_restart_fields": pending_restart,
            },
            status_code=200,
        )
