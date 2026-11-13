"""Construcción y serialización segura de respuestas HTTP/1.1."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path
from typing import Any

SERVER_HEADER = "UTN-FRM-Redes-HTTP/1.0"

STATUS_REASONS: dict[int, str] = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
    501: "Not Implemented",
    505: "HTTP Version Not Supported",
}

MIME_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".pdf": "application/pdf",
}

# Códigos que por especificación HTTP no deben incluir cuerpo de entidad
NO_BODY_STATUS_CODES = frozenset({204, 304})


def guess_mime_type(file_path: Path) -> str:
    """Determina el Content-Type según la extensión del archivo."""
    ext = file_path.suffix.lower()
    return MIME_TYPES.get(ext, "application/octet-stream")


@dataclass
class HTTPResponse:
    """Representa una respuesta HTTP/1.1 lista para serializar a bytes."""

    status_code: int
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.body, (bytes, bytearray)):
            raise TypeError("El cuerpo de HTTPResponse debe ser de tipo bytes.")
        self.body = bytes(self.body)
        if self.reason is None:
            self.reason = STATUS_REASONS.get(self.status_code, "Unknown")

    def to_bytes(self, include_body: bool = True) -> bytes:
        """
        Serializa la línea de estado, encabezados y cuerpo en un flujo de bytes puro.
        Si `include_body` es False (por ejemplo, método HEAD), conserva Content-Length
        pero omite los bytes del cuerpo.
        """
        has_entity = self.status_code not in NO_BODY_STATUS_CODES
        body_bytes = self.body if has_entity else b""

        response_headers: dict[str, str] = {
            "Date": formatdate(usegmt=True),
            "Server": SERVER_HEADER,
            "Connection": "close",
        }

        if has_entity:
            response_headers["Content-Type"] = self.content_type
            response_headers["Content-Length"] = str(len(body_bytes))
        else:
            response_headers["Content-Length"] = "0"

        # Cabeceras de seguridad básicas recomendadas
        response_headers["X-Content-Type-Options"] = "nosniff"

        for key, val in self.headers.items():
            # Sanitizar saltos de línea para evitar CRLF Response Splitting
            safe_key = str(key).replace("\r", "").replace("\n", "")
            safe_val = str(val).replace("\r", "").replace("\n", "")
            response_headers[safe_key] = safe_val

        lines = [f"HTTP/1.1 {self.status_code} {self.reason}"]
        for key, val in response_headers.items():
            lines.append(f"{key}: {val}")

        header_block = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")

        if include_body and has_entity:
            return header_block + body_bytes
        return header_block


def html_response(
    html_text: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTTPResponse:
    """Construye una respuesta HTML codificada en UTF-8."""
    return HTTPResponse(
        status_code=status_code,
        body=html_text.encode("utf-8"),
        content_type="text/html; charset=utf-8",
        headers=headers or {},
    )


def json_response(
    payload: dict[str, Any] | list[Any],
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTTPResponse:
    """Construye una respuesta JSON codificada en UTF-8."""
    raw_json = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return HTTPResponse(
        status_code=status_code,
        body=raw_json,
        content_type="application/json; charset=utf-8",
        headers=headers or {},
    )


def error_response(
    status_code: int,
    detail: str,
    headers: dict[str, str] | None = None,
    as_json: bool = False,
) -> HTTPResponse:
    """
    Construye una respuesta de error coherente sin filtrar trazas internas ni rutas del sistema.
    """
    reason = STATUS_REASONS.get(status_code, "Error")
    if as_json:
        return json_response(
            {"ok": False, "status": status_code, "error": reason, "detail": detail},
            status_code=status_code,
            headers=headers,
        )

    safe_detail = html.escape(detail)
    safe_reason = html.escape(reason)
    page = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HTTP FAULT {status_code} // {safe_reason}</title>
  <style>
    body {{
      font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background-color: #121311;
      color: #e4e3dc;
      margin: 0;
      padding: 3rem 1.25rem;
    }}
    .card {{
      max-width: 680px;
      margin: 0 auto;
      background: #191b18;
      border: 1px solid #343932;
      border-top: 3px solid #d49a35;
    }}
    .card-header {{
      background: #1f221e;
      border-bottom: 1px solid #343932;
      padding: 0.65rem 1.15rem;
      font-family: "IBM Plex Mono", "Consolas", monospace;
      font-size: 0.82rem;
      color: #d49a35;
      display: flex;
      justify-content: space-between;
    }}
    .card-body {{
      padding: 1.5rem 1.25rem;
    }}
    h1 {{
      margin: 0 0 0.75rem;
      font-family: "IBM Plex Mono", "Consolas", monospace;
      color: #c9544d;
      font-size: 1.35rem;
      text-transform: uppercase;
    }}
    p {{
      line-height: 1.6;
      color: #e4e3dc;
      margin: 0.5rem 0 1.25rem;
    }}
    .btn {{
      display: inline-block;
      font-family: "IBM Plex Mono", "Consolas", monospace;
      font-size: 0.82rem;
      font-weight: 600;
      text-transform: uppercase;
      background: #2b5e39;
      color: #e4e3dc;
      border: 1px solid #4da865;
      padding: 0.5rem 0.95rem;
      text-decoration: none;
    }}
    .btn:hover {{
      background: #4da865;
      color: #0c0d0c;
    }}
    .footer {{
      padding: 0.7rem 1.25rem;
      border-top: 1px solid #343932;
      background: #0c0d0c;
      font-family: "IBM Plex Mono", "Consolas", monospace;
      font-size: 0.76rem;
      color: #949990;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <span>[SYSTEM DIAGNOSTIC // HTTP EXCEPTION]</span>
      <span>CODE: {status_code}</span>
    </div>
    <div class="card-body">
      <h1>[{status_code}] {safe_reason}</h1>
      <p>{safe_detail}</p>
      <a href="/" class="btn">&lt; RETURN TO ROOT CONSOLE (/)</a>
    </div>
    <div class="footer">UTN-FRM // SERVIDOR HTTP/1.1 PROPIO EN PYTHON &mdash; REDES DE INFORMACIÓN</div>
  </div>
</body>
</html>
"""
    return html_response(page, status_code=status_code, headers=headers)
