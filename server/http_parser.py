"""Analizador (parser) defensivo para el subconjunto implementado de HTTP/1.1."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

HEADER_TERMINATOR = b"\r\n\r\n"
LINE_SEPARATOR = "\r\n"
MAX_HEADER_BYTES = 65536  # 64 KB máximo para la sección de encabezados
SUPPORTED_METHODS = frozenset({"GET", "HEAD", "POST"})
SUPPORTED_VERSIONS = frozenset({"HTTP/1.1", "HTTP/1.0"})
TOKEN_RE = re.compile(r"^[A-Z]+$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HTTP_VERSION_RE = re.compile(r"^HTTP/\d+\.\d+$")


class HTTPParseError(Exception):
    """Excepción que representa un error al analizar la solicitud HTTP con su código de estado."""

    def __init__(
        self,
        status_code: int,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.headers = headers or {}


@dataclass
class HTTPRequest:
    """Representación estructurada de una solicitud HTTP analizada."""

    method: str
    target: str
    path: str
    query_string: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client_ip: str = "127.0.0.1"

    def get_header(self, name: str, default: str | None = None) -> str | None:
        """Obtiene un encabezado sin distinguir mayúsculas/minúsculas."""
        return self.headers.get(name.lower(), default)


def parse_headers_section(raw_header_bytes: bytes) -> tuple[str, str, str, str, str, dict[str, str]]:
    """
    Analiza los bytes correspondientes a la línea de petición y los encabezados HTTP.
    Devuelve: (method, target, path, query_string, version, headers_dict).
    """
    if not raw_header_bytes:
        raise HTTPParseError(400, "Solicitud HTTP vacía.")

    # El estándar HTTP define ISO-8859-1 / ASCII para encabezados
    try:
        header_text = raw_header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise HTTPParseError(400, "Codificación inválida en encabezados HTTP.") from exc

    # Verificar que se use CRLF (\r\n) y no únicamente LF (\n) sueltos
    lines = header_text.split(LINE_SEPARATOR)
    if not lines or not lines[0]:
        raise HTTPParseError(400, "Línea de petición HTTP ausente o vacía.")

    # Si había saltos \n sin \r en la línea de petición, es malformada respecto de CRLF
    request_line = lines[0]
    if "\n" in request_line or "\r" in request_line:
        raise HTTPParseError(400, "Separador de línea inválido; HTTP requiere CRLF (\\r\\n).")

    parts = request_line.split(" ")
    if len(parts) != 3:
        raise HTTPParseError(400, "La línea de petición debe contener exactamente: MÉTODO RUTA VERSIÓN.")

    method, target, version = parts

    if not method or not TOKEN_RE.match(method) or len(method) > 16:
        raise HTTPParseError(400, "Método HTTP mal formado.")

    if not target or not target.startswith("/"):
        raise HTTPParseError(400, "El target de la solicitud debe comenzar con '/'.")

    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in target):
        raise HTTPParseError(400, "El target contiene caracteres de control o espacios no codificados.")

    if not HTTP_VERSION_RE.match(version):
        raise HTTPParseError(400, "Formato de versión HTTP inválido.")

    if version not in SUPPORTED_VERSIONS:
        raise HTTPParseError(505, f"Versión HTTP no soportada: {version}.")

    if method not in SUPPORTED_METHODS:
        raise HTTPParseError(
            405,
            f"El método {method} no está permitido en este servidor.",
            headers={"Allow": "GET, HEAD, POST"},
        )

    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        if raw_line == "":
            continue
        if "\n" in raw_line or "\r" in raw_line:
            raise HTTPParseError(400, "Encabezado con salto de línea inválido (se requiere CRLF).")
        if ":" not in raw_line:
            raise HTTPParseError(400, f"Encabezado mal formado (falta ':'): {raw_line[:40]}")

        name, value = raw_line.split(":", 1)
        if not name or not HEADER_NAME_RE.match(name):
            raise HTTPParseError(400, f"Nombre de encabezado inválido: {name[:40]}")

        norm_name = name.lower()
        clean_value = value.strip(" \t")
        if any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in clean_value):
            raise HTTPParseError(400, f"Valor de encabezado contiene caracteres de control: {norm_name}")

        # Prevenir ambigüedad de Content-Length duplicado con distinto valor (HTTP Request Smuggling)
        if norm_name == "content-length" and norm_name in headers and headers[norm_name] != clean_value:
            raise HTTPParseError(400, "Múltiples encabezados Content-Length contradictorios.")

        headers[norm_name] = clean_value

    # En HTTP/1.1 el encabezado Host es obligatorio (RFC 9112)
    if version == "HTTP/1.1" and "host" not in headers:
        raise HTTPParseError(400, "Falta el encabezado obligatorio 'Host' en solicitud HTTP/1.1.")

    # Rechazar explícitamente Transfer-Encoding: chunked u otros (fuera del alcance del subconjunto)
    if "transfer-encoding" in headers:
        te_value = headers["transfer-encoding"].lower()
        raise HTTPParseError(
            501,
            f"Transfer-Encoding ({te_value}) no está implementado. Use Content-Length.",
        )

    if "?" in target:
        path, query_string = target.split("?", 1)
    else:
        path, query_string = target, ""

    return method, target, path, query_string, version, headers


def extract_content_length(headers: dict[str, str], max_body_size: int) -> int:
    """Extrae y valida el valor de Content-Length si está presente."""
    if "content-length" not in headers:
        return 0
    raw_len = headers["content-length"].strip()
    if not raw_len.isdigit():
        raise HTTPParseError(400, "El encabezado Content-Length debe ser un entero no negativo.")
    content_length = int(raw_len)
    if content_length < 0:
        raise HTTPParseError(400, "Content-Length no puede ser negativo.")
    if content_length > max_body_size:
        raise HTTPParseError(
            413,
            f"El cuerpo anunciado ({content_length} bytes) supera el máximo permitido ({max_body_size} bytes).",
        )
    return content_length


def parse_http_request_bytes(
    raw_bytes: bytes,
    max_request_size: int = 1048576,
    client_ip: str = "127.0.0.1",
) -> HTTPRequest:
    """
    Analiza una solicitud HTTP completa contenida en un bloque de bytes.
    Útil para pruebas unitarias y validación determinista.
    """
    if not raw_bytes:
        raise HTTPParseError(400, "Solicitud vacía.")

    if len(raw_bytes) > max_request_size:
        raise HTTPParseError(413, "El tamaño total de la solicitud supera el límite máximo configurado.")

    sep_idx = raw_bytes.find(HEADER_TERMINATOR)
    if sep_idx == -1:
        if len(raw_bytes) > MAX_HEADER_BYTES:
            raise HTTPParseError(413, "Encabezados HTTP demasiado grandes.")
        raise HTTPParseError(400, "Solicitud HTTP incompleta: no se encontró el final de encabezados (\\r\\n\\r\\n).")

    header_bytes = raw_bytes[:sep_idx]
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise HTTPParseError(413, "Encabezados HTTP superan el tamaño máximo permitido.")

    body_bytes = raw_bytes[sep_idx + len(HEADER_TERMINATOR) :]

    method, target, path, query_string, version, headers = parse_headers_section(header_bytes)

    max_body = max(0, max_request_size - len(header_bytes) - len(HEADER_TERMINATOR))
    content_length = extract_content_length(headers, max_body_size=max_body)

    if method == "POST" and "content-length" not in headers and len(body_bytes) > 0:
        raise HTTPParseError(400, "Solicitud POST con cuerpo requiere encabezado Content-Length.")

    if len(body_bytes) < content_length:
        raise HTTPParseError(
            400,
            f"Cuerpo HTTP incompleto: se recibieron {len(body_bytes)} de {content_length} bytes declarados.",
        )

    body = body_bytes[:content_length]
    return HTTPRequest(
        method=method,
        target=target,
        path=path,
        query_string=query_string,
        version=version,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )


def read_http_request(
    sock: socket.socket,
    max_request_size: int = 1048576,
    client_ip: str = "127.0.0.1",
    recv_chunk_size: int = 4096,
) -> HTTPRequest:
    """
    Lee del flujo TCP de un socket hasta completar los encabezados y el cuerpo según Content-Length.
    No asume que una única llamada a recv() entregue el mensaje completo.
    """
    buffer = bytearray()
    header_limit = min(MAX_HEADER_BYTES, max_request_size)

    # 1. Acumular bytes hasta encontrar el delimitador de fin de encabezados (\r\n\r\n)
    while HEADER_TERMINATOR not in buffer:
        if len(buffer) >= header_limit:
            raise HTTPParseError(413, "Encabezados HTTP exceden el límite permitido.")
        chunk = sock.recv(min(recv_chunk_size, header_limit - len(buffer) + 4))
        if not chunk:
            if not buffer:
                raise HTTPParseError(400, "El cliente cerró la conexión sin enviar datos.")
            raise HTTPParseError(400, "Conexión cerrada antes de completar los encabezados HTTP.")
        buffer.extend(chunk)

    sep_idx = buffer.find(HEADER_TERMINATOR)
    header_bytes = bytes(buffer[:sep_idx])
    remaining = bytearray(buffer[sep_idx + len(HEADER_TERMINATOR) :])

    method, target, path, query_string, version, headers = parse_headers_section(header_bytes)

    max_body = max(0, max_request_size - len(header_bytes) - len(HEADER_TERMINATOR))
    content_length = extract_content_length(headers, max_body_size=max_body)

    # 2. Si hay Content-Length > 0, continuar leyendo hasta completar el cuerpo prometido
    while len(remaining) < content_length:
        needed = content_length - len(remaining)
        chunk = sock.recv(min(recv_chunk_size, needed))
        if not chunk:
            raise HTTPParseError(
                400,
                f"Conexión cerrada prematuramente al leer el cuerpo ({len(remaining)}/{content_length} bytes).",
            )
        remaining.extend(chunk)

    body = bytes(remaining[:content_length])

    return HTTPRequest(
        method=method,
        target=target,
        path=path,
        query_string=query_string,
        version=version,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )
