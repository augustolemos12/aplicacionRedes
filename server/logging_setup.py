"""Configuración de logging separado para accesos y errores con sanitización."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path


def sanitize_log_field(value: object, max_length: int = 512) -> str:
    """
    Sanitiza un valor antes de escribirlo en los logs para prevenir Log Injection.
    Reemplaza saltos de línea y caracteres de control por representaciones seguras.
    """
    text = str(value) if value is not None else "-"
    escaped_chars: list[str] = []
    for ch in text:
        if ch == "\r":
            escaped_chars.append("\\r")
        elif ch == "\n":
            escaped_chars.append("\\n")
        elif ch == "\t":
            escaped_chars.append("\\t")
        elif ord(ch) < 32 or ord(ch) == 127:
            escaped_chars.append(f"\\x{ord(ch):02x}")
        else:
            escaped_chars.append(ch)
    sanitized = "".join(escaped_chars)
    if len(sanitized) > max_length:
        return sanitized[:max_length] + "...[truncated]"
    return sanitized


class ServerLogger:
    """Encapsula los loggers de acceso y de error del servidor HTTP."""

    def __init__(self, logs_dir: Path) -> None:
        self.logs_dir = logs_dir.resolve()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.access_log_path = self.logs_dir / "access.log"
        self.error_log_path = self.logs_dir / "error.log"

        # Tocamos los archivos para asegurar que existan desde el inicio
        self.access_log_path.touch(exist_ok=True)
        self.error_log_path.touch(exist_ok=True)

        instance_id = id(self)
        self._access_logger = logging.getLogger(f"http_server.access.{instance_id}")
        self._error_logger = logging.getLogger(f"http_server.error.{instance_id}")

        self._configure_logger(self._access_logger, self.access_log_path)
        self._configure_logger(self._error_logger, self.error_log_path)

    @staticmethod
    def _configure_logger(logger: logging.Logger, file_path: Path) -> None:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        formatter = logging.Formatter("%(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def log_access(
        self,
        client_ip: str,
        method: str,
        target: str,
        version: str,
        status_code: int,
        bytes_sent: int,
    ) -> None:
        """Registra una entrada en access.log sin incluir credenciales ni datos privados."""
        timestamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        safe_ip = sanitize_log_field(client_ip, 64)
        safe_method = sanitize_log_field(method, 32)
        safe_target = sanitize_log_field(target, 256)
        safe_version = sanitize_log_field(version, 32)
        entry = (
            f"[{timestamp}] {safe_ip} \"{safe_method} {safe_target} {safe_version}\" "
            f"{int(status_code)} {int(bytes_sent)}"
        )
        self._access_logger.info(entry)

    def log_error(
        self,
        level: str,
        client_ip: str,
        message: str,
        target: str = "-",
    ) -> None:
        """Registra un evento de error o seguridad en error.log."""
        timestamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        safe_level = sanitize_log_field(level.upper(), 16)
        safe_ip = sanitize_log_field(client_ip, 64)
        safe_target = sanitize_log_field(target, 256)
        safe_msg = sanitize_log_field(message, 512)
        entry = f"[{timestamp}] [{safe_level}] [client {safe_ip}] [target {safe_target}] {safe_msg}"
        self._error_logger.error(entry)

    def read_recent_access_logs(self, limit: int = 50) -> list[str]:
        """Devuelve las últimas líneas de access.log con límite estricto."""
        return read_last_lines(self.access_log_path, limit=limit)

    def read_recent_error_logs(self, limit: int = 50) -> list[str]:
        """Devuelve las últimas líneas de error.log con límite estricto."""
        return read_last_lines(self.error_log_path, limit=limit)

    def close(self) -> None:
        """Cierra los descriptores de archivo de los loggers."""
        for logger in (self._access_logger, self._error_logger):
            for handler in list(logger.handlers):
                handler.close()
                logger.removeHandler(handler)


def read_last_lines(file_path: Path, limit: int = 50) -> list[str]:
    """Lee de forma segura hasta `limit` líneas finales de un archivo de log."""
    safe_limit = max(1, min(int(limit), 200))
    if not file_path.exists():
        return []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-safe_limit:]
    except OSError:
        return []
