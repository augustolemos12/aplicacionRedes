"""Controles de seguridad: prevención de Path Traversal, HTTP Basic Auth y protección CSRF."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from pathlib import Path
from urllib.parse import unquote

PBKDF2_ITERATIONS = 200_000


class SecurityViolationError(Exception):
    """Excepción lanzada cuando se detecta un intento de violación de seguridad (ej. Path Traversal)."""

    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def normalize_url_path(raw_url_path: str) -> str:
    """
    Decodifica y valida preliminarmente la ruta URL solicitada.
    Rechaza bytes nulos, barras invertidas, rutas codificadas con '..' o escapes sospechosos.
    """
    if not raw_url_path or not raw_url_path.startswith("/"):
        raise SecurityViolationError("La ruta solicitada no comienza con '/'.")

    # Quitar query string o fragmento si estuvieran presentes
    path_only = raw_url_path.split("?", 1)[0].split("#", 1)[0]

    if "\x00" in path_only or "%00" in path_only.lower():
        raise SecurityViolationError("Se detectó byte nulo en la ruta solicitada.")

    # Realizar decodificación iterativa (hasta 2 pasadas) para detectar doble codificación (%252e%252e)
    decoded_once = unquote(path_only)
    decoded_twice = unquote(decoded_once)

    for candidate in (path_only, decoded_once, decoded_twice):
        if "\x00" in candidate:
            raise SecurityViolationError("Se detectó byte nulo tras decodificar la URL.")
        # Tratar barras invertidas de Windows como separadores sospechosos de traversal
        normalized_slashes = candidate.replace("\\", "/")
        segments = [seg for seg in normalized_slashes.split("/") if seg != ""]
        for seg in segments:
            if seg in (".", ".."):
                raise SecurityViolationError("Intento de Path Traversal detectado (segmento '..' o '.').")
            if ":" in seg:
                raise SecurityViolationError("Intento de usar identificador de unidad o esquema en la ruta.")

    # Si había barras invertidas en la ruta decodificada, bloquear explícitamente
    if "\\" in decoded_once or "\\" in decoded_twice:
        raise SecurityViolationError("Uso de separador de ruta inválido ('\\\\') en URL.")

    # Construir ruta URL canónica limpia (ej. "/private/index.html" o "/")
    clean_segments = [seg for seg in decoded_once.split("/") if seg != ""]
    if not clean_segments:
        return "/"
    return "/" + "/".join(clean_segments)


def resolve_safe_path(document_root: Path, raw_url_path: str) -> Path:
    """
    Resuelve de forma canónica una ruta URL dentro del `document_root`.
    Verifica:
    1. Que no contenga secuencias `../`, barras invertidas ni codificaciones maliciosas.
    2. Que la ruta final resuelta con `Path.resolve()` (incluyendo symlinks) permanezca
       estrictamente dentro del `document_root.resolve()` usando `is_relative_to`.
    """
    canonical_doc_root = document_root.resolve()
    clean_url_path = normalize_url_path(raw_url_path)

    relative_parts = [part for part in clean_url_path.lstrip("/").split("/") if part]
    candidate_path = canonical_doc_root.joinpath(*relative_parts)

    try:
        resolved_target = candidate_path.resolve()
    except OSError as exc:
        raise SecurityViolationError(f"No se pudo resolver la ruta de forma segura: {exc}") from exc

    if not resolved_target.is_relative_to(canonical_doc_root):
        raise SecurityViolationError(
            "El recurso solicitado resuelve fuera del DocumentRoot permitido (Path Traversal o Symlink externo)."
        )

    return resolved_target


def is_path_protected(raw_url_path: str, protected_directories: list[str]) -> bool:
    """
    Determina si la ruta URL cae bajo alguno de los directorios protegidos configurados.
    Evalúa la ruta normalizada para evitar evasión mediante `//private` o `/private/`.
    """
    clean_path = normalize_url_path(raw_url_path)
    for raw_dir in protected_directories:
        norm_dir = "/" + "/".join(seg for seg in raw_dir.replace("\\", "/").split("/") if seg)
        if norm_dir == "/":
            return True
        if clean_path == norm_dir or clean_path.startswith(norm_dir + "/"):
            return True
    return False


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """
    Genera un hash PBKDF2-HMAC-SHA256 con sal criptográfica aleatoria de 16 bytes.
    Formato devuelto: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifica una contraseña contra su hash PBKDF2-HMAC-SHA256 usando comparación en tiempo constante.
    """
    if not password or not stored_hash:
        return False
    parts = stored_hash.strip().split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_digest = bytes.fromhex(parts[3])
    except ValueError:
        return False

    if iterations < 1000 or not salt or not expected_digest:
        return False

    computed_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(computed_digest, expected_digest)


def verify_basic_auth(
    authorization_header: str | None,
    expected_username: str,
    stored_password_hash: str,
) -> bool:
    """
    Valida el encabezado HTTP `Authorization: Basic <base64>` de forma segura.
    Nunca registra ni expone la contraseña recibida.
    """
    if not authorization_header or not stored_password_hash or not expected_username:
        return False

    parts = authorization_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return False

    b64_token = parts[1].strip()
    try:
        decoded_bytes = base64.b64decode(b64_token, validate=True)
        decoded_str = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False

    if ":" not in decoded_str:
        return False

    username, password = decoded_str.split(":", 1)
    user_ok = hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
    pass_ok = verify_password(password, stored_password_hash)
    return user_ok and pass_ok


class CSRFTokenManager:
    """
    Gestiona tokens CSRF firmados con HMAC-SHA256 para proteger las operaciones POST
    del panel administrativo contra ataques Cross-Site Request Forgery.
    """

    def __init__(self, ttl_seconds: int = 7200) -> None:
        self._secret = secrets.token_bytes(32)
        self._ttl_seconds = ttl_seconds

    def generate_token(self, username: str) -> str:
        """Genera un token firmado vinculado al usuario autenticado y al instante actual."""
        issued_at = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{username}:{issued_at}:{nonce}"
        signature = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{issued_at}.{nonce}.{signature}"

    def validate_token(self, token: str | None, username: str) -> bool:
        """Verifica la firma y vigencia temporal del token CSRF."""
        if not token or not isinstance(token, str):
            return False
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False
        issued_at_str, nonce, signature = parts
        if not issued_at_str.isdigit():
            return False

        issued_at = int(issued_at_str)
        now = int(time.time())
        if now - issued_at > self._ttl_seconds or issued_at > now + 60:
            return False

        payload = f"{username}:{issued_at_str}:{nonce}"
        expected_sig = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_sig)
