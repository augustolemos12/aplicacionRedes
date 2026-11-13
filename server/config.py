"""Carga, validación y persistencia de la configuración del servidor HTTP."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigValidationError(ValueError):
    """Error lanzado cuando la configuración del servidor es inválida."""


# Parámetros que requieren reiniciar el proceso para surtir efecto en el socket principal
RESTART_REQUIRED_FIELDS = ("host", "port", "document_root")


@dataclass
class ServerConfig:
    """Estructura validada de configuración del servidor."""

    host: str = "0.0.0.0"
    port: int = 8080
    document_root: str = "www"
    admin_enabled: bool = True
    max_request_size: int = 1048576
    socket_timeout: int = 10
    protected_directories: list[str] = field(default_factory=lambda: ["/private"])
    admin_username: str = "admin"
    admin_password_hash: str = ""

    def validate(self, base_dir: Path | None = None) -> None:
        """Valida tipos, rangos y coherencia de todos los parámetros."""
        if not isinstance(self.host, str) or not self.host.strip():
            raise ConfigValidationError("El campo 'host' debe ser una cadena no vacía.")
        self.host = self.host.strip()
        if any(ch.isspace() for ch in self.host):
            raise ConfigValidationError("El campo 'host' no puede contener espacios.")

        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ConfigValidationError("El campo 'port' debe ser un número entero.")
        if not (1 <= self.port <= 65535):
            raise ConfigValidationError("El campo 'port' debe estar entre 1 y 65535.")

        if not isinstance(self.document_root, str) or not self.document_root.strip():
            raise ConfigValidationError("El campo 'document_root' debe ser una cadena no vacía.")
        self.document_root = self.document_root.strip()
        if "\x00" in self.document_root:
            raise ConfigValidationError("El campo 'document_root' contiene caracteres inválidos.")

        # Validar que document_root sea seguro y esté dentro del proyecto (o sea un directorio válido no raíz)
        root_base = (base_dir or Path.cwd()).resolve()
        candidate_doc_root = (root_base / self.document_root).resolve() if not Path(self.document_root).is_absolute() else Path(self.document_root).resolve()
        if candidate_doc_root == candidate_doc_root.anchor or str(candidate_doc_root) == candidate_doc_root.anchor:
            raise ConfigValidationError("El 'document_root' no puede ser la raíz del sistema de archivos.")
        if base_dir is not None and not candidate_doc_root.is_relative_to(root_base):
            raise ConfigValidationError("Por seguridad, 'document_root' debe encontrarse dentro del directorio del proyecto.")
        if candidate_doc_root.exists() and not candidate_doc_root.is_dir():
            raise ConfigValidationError("La ruta indicada en 'document_root' existe pero no es un directorio.")

        if not isinstance(self.admin_enabled, bool):
            raise ConfigValidationError("El campo 'admin_enabled' debe ser booleano (true/false).")

        if isinstance(self.max_request_size, bool) or not isinstance(self.max_request_size, int):
            raise ConfigValidationError("El campo 'max_request_size' debe ser un entero.")
        if not (1024 <= self.max_request_size <= 50 * 1024 * 1024):
            raise ConfigValidationError("El campo 'max_request_size' debe estar entre 1024 bytes (1 KB) y 52428800 bytes (50 MB).")

        if isinstance(self.socket_timeout, bool) or not isinstance(self.socket_timeout, (int, float)):
            raise ConfigValidationError("El campo 'socket_timeout' debe ser numérico.")
        if not (1 <= self.socket_timeout <= 300):
            raise ConfigValidationError("El campo 'socket_timeout' debe estar entre 1 y 300 segundos.")

        if not isinstance(self.protected_directories, list):
            raise ConfigValidationError("El campo 'protected_directories' debe ser una lista de rutas.")
        normalized_dirs: list[str] = []
        for item in self.protected_directories:
            if not isinstance(item, str) or not item.strip():
                raise ConfigValidationError("Cada directorio protegido debe ser una cadena no vacía.")
            clean = item.strip().replace("\\", "/")
            if not clean.startswith("/"):
                raise ConfigValidationError(f"El directorio protegido '{item}' debe comenzar con '/'.")
            if ".." in clean.split("/"):
                raise ConfigValidationError(f"El directorio protegido '{item}' no puede contener '..'.")
            if clean != "/" and clean.endswith("/"):
                clean = clean.rstrip("/")
            if clean in ("/admin", "/admin/api"):
                raise ConfigValidationError("Las rutas '/admin' se gestionan de forma separada.")
            if clean not in normalized_dirs:
                normalized_dirs.append(clean)
        self.protected_directories = normalized_dirs

        if not isinstance(self.admin_username, str) or not self.admin_username.strip():
            raise ConfigValidationError("El campo 'admin_username' debe ser una cadena no vacía.")
        if ":" in self.admin_username:
            raise ConfigValidationError("El campo 'admin_username' no puede contener ':' ( incompatible con HTTP Basic Auth).")
        self.admin_username = self.admin_username.strip()

        if not isinstance(self.admin_password_hash, str):
            raise ConfigValidationError("El campo 'admin_password_hash' debe ser una cadena.")
        self.admin_password_hash = self.admin_password_hash.strip()
        if self.admin_password_hash and not self.admin_password_hash.startswith("pbkdf2_sha256$"):
            raise ConfigValidationError(
                "El campo 'admin_password_hash' no tiene un formato hash válido (pbkdf2_sha256$...). "
                "Nunca almacene contraseñas en texto plano."
            )

    def resolve_document_root(self, base_dir: Path | None = None) -> Path:
        """Devuelve la ruta absoluta y canónica del DocumentRoot."""
        root_base = (base_dir or Path.cwd()).resolve()
        doc_path = Path(self.document_root)
        if not doc_path.is_absolute():
            doc_path = root_base / doc_path
        return doc_path.resolve()

    def to_dict(self, include_sensitive: bool = True) -> dict[str, Any]:
        """Convierte la configuración a diccionario serializable."""
        data: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "document_root": self.document_root,
            "admin_enabled": self.admin_enabled,
            "max_request_size": self.max_request_size,
            "socket_timeout": self.socket_timeout,
            "protected_directories": list(self.protected_directories),
            "admin_username": self.admin_username,
        }
        if include_sensitive:
            data["admin_password_hash"] = self.admin_password_hash
        else:
            data["password_configured"] = bool(self.admin_password_hash)
            data["restart_required_fields"] = list(RESTART_REQUIRED_FIELDS)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_dir: Path | None = None) -> "ServerConfig":
        """Construye y valida un ServerConfig a partir de un diccionario."""
        if not isinstance(data, dict):
            raise ConfigValidationError("El archivo de configuración debe contener un objeto JSON.")

        allowed_keys = {
            "host",
            "port",
            "document_root",
            "admin_enabled",
            "max_request_size",
            "socket_timeout",
            "protected_directories",
            "admin_username",
            "admin_password_hash",
        }
        unknown_keys = set(data.keys()) - allowed_keys
        if unknown_keys:
            raise ConfigValidationError(f"Campos desconocidos en la configuración: {', '.join(sorted(unknown_keys))}")

        cfg = cls(
            host=data.get("host", "0.0.0.0"),
            port=data.get("port", 8080),
            document_root=data.get("document_root", "www"),
            admin_enabled=data.get("admin_enabled", True),
            max_request_size=data.get("max_request_size", 1048576),
            socket_timeout=data.get("socket_timeout", 10),
            protected_directories=data.get("protected_directories", ["/private"]),
            admin_username=data.get("admin_username", "admin"),
            admin_password_hash=data.get("admin_password_hash", ""),
        )
        cfg.validate(base_dir=base_dir)
        return cfg


def load_config(config_path: Path, base_dir: Path | None = None) -> ServerConfig:
    """Lee y valida el archivo JSON de configuración."""
    if not config_path.exists():
        raise ConfigValidationError(f"No existe el archivo de configuración: {config_path}")
    try:
        raw_text = config_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ConfigValidationError(f"JSON inválido en {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigValidationError(f"No se pudo leer {config_path}: {exc}") from exc

    return ServerConfig.from_dict(data, base_dir=base_dir)


def save_config(config: ServerConfig, config_path: Path, base_dir: Path | None = None) -> None:
    """Valida y guarda la configuración en formato JSON legible."""
    config.validate(base_dir=base_dir)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(config.to_dict(include_sensitive=True), indent=2, ensure_ascii=False) + "\n"
    config_path.write_text(content, encoding="utf-8")
