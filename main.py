"""
Punto de entrada principal del Servidor HTTP Propio en Python.
Asignatura: Redes de Información - Ingeniería en Sistemas de Información (UTN FRM).
"""

from __future__ import annotations

import argparse
import getpass
import socket
import sys
from pathlib import Path

from server.config import ConfigValidationError, ServerConfig, load_config, save_config
from server.logging_setup import ServerLogger
from server.security import hash_password
from server.socket_server import TCPHTTPServer


def detect_lan_ip() -> str:
    """Intenta detectar la dirección IPv4 de la interfaz de red local (LAN) para mostrar en consola."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_sock:
            temp_sock.connect(("10.255.255.255", 1))
            return str(temp_sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Define y analiza los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Servidor HTTP/1.1 educativo implementado sobre sockets TCP (UTN FRM)."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/server.json"),
        help="Ruta al archivo de configuración JSON (por defecto: config/server.json).",
    )
    parser.add_argument(
        "--set-password",
        nargs="?",
        const="__PROMPT__",
        metavar="PASSWORD",
        help="Configura la contraseña del administrador guardando su hash PBKDF2-SHA256 en server.json.",
    )
    parser.add_argument(
        "--username",
        type=str,
        default=None,
        help="Nombre de usuario administrador (opcional, al usar --set-password).",
    )
    parser.add_argument(
        "--init-demo",
        action="store_true",
        help="Inicializa credenciales locales de demostración para laboratorio (usuario: admin).",
    )
    return parser.parse_args(argv)


def handle_credential_setup(
    config: ServerConfig,
    config_path: Path,
    base_dir: Path,
    args: argparse.Namespace,
) -> bool:
    """
    Procesa los comandos --set-password o --init-demo.
    Devuelve True si solo se ejecutó configuración de credenciales y el programa debe terminar,
    o False si debe continuar iniciando el servidor.
    """
    if args.set_password is not None:
        if args.set_password == "__PROMPT__":
            try:
                pwd1 = getpass.getpass("Ingrese la nueva contraseña de administrador (mín. 6 caracteres): ")
                pwd2 = getpass.getpass("Confirme la nueva contraseña: ")
            except (EOFError, KeyboardInterrupt):
                print("\nOperación cancelada.")
                sys.exit(1)
            if pwd1 != pwd2:
                print("[ERROR] Las contraseñas no coinciden.", file=sys.stderr)
                sys.exit(1)
            password = pwd1
        else:
            password = args.set_password

        if len(password) < 6:
            print("[ERROR] La contraseña debe tener al menos 6 caracteres.", file=sys.stderr)
            sys.exit(1)

        if args.username:
            config.admin_username = args.username.strip()

        config.admin_password_hash = hash_password(password)
        save_config(config, config_path, base_dir=base_dir)
        print(f"[OK] Credenciales actualizadas en '{config_path}' para el usuario '{config.admin_username}'.")
        print("     La contraseña se almacenó como hash PBKDF2-HMAC-SHA256 con sal aleatoria.")
        return True

    if args.init_demo:
        demo_password = "admin123"
        config.admin_username = args.username.strip() if args.username else "admin"
        config.admin_password_hash = hash_password(demo_password)
        save_config(config, config_path, base_dir=base_dir)
        print("=" * 72)
        print("[MODO DEMOSTRACIÓN DE LABORATORIO INICIALIZADO]")
        print(f"  Usuario configurado : {config.admin_username}")
        print(f"  Contraseña de prueba: {demo_password}")
        print(f"  Archivo actualizado : {config_path}")
        print("  Nota: En el archivo JSON solo se guardó el hash PBKDF2-HMAC-SHA256.")
        print("=" * 72)
        return False

    return False


def main(argv: list[str] | None = None) -> int:
    """Función principal de arranque y cierre ordenado del servidor."""
    args = parse_args(argv)
    base_dir = Path.cwd().resolve()
    config_path = args.config if args.config.is_absolute() else (base_dir / args.config).resolve()

    try:
        config = load_config(config_path, base_dir=base_dir)
    except ConfigValidationError as exc:
        print(f"[ERROR DE CONFIGURACIÓN] {exc}", file=sys.stderr)
        return 1

    if handle_credential_setup(config, config_path, base_dir, args):
        return 0

    # Asegurar que el DocumentRoot exista
    doc_root_path = config.resolve_document_root(base_dir=base_dir)
    doc_root_path.mkdir(parents=True, exist_ok=True)

    logs_dir = base_dir / "logs"
    logger = ServerLogger(logs_dir=logs_dir)

    server = TCPHTTPServer(
        config=config,
        config_path=config_path,
        logger=logger,
        base_dir=base_dir,
    )

    try:
        bound_host, bound_port = server.start_listening()
    except OSError as exc:
        logger.log_error("STARTUP_ERROR", "local", f"No se pudo abrir el socket en {config.host}:{config.port}: {exc}")
        logger.close()
        print(f"[ERROR] No se pudo iniciar el servidor en {config.host}:{config.port} -> {exc}", file=sys.stderr)
        return 1

    lan_ip = detect_lan_ip()
    print("=" * 72)
    print("  SERVIDOR HTTP PROPIO EN PYTHON - REDES DE INFORMACIÓN (UTN FRM)")
    print("=" * 72)
    print(f"  Escuchando en socket TCP : {bound_host}:{bound_port}")
    print(f"  Acceso local ( esta PC ) : http://localhost:{bound_port}/")
    if bound_host == "0.0.0.0":
        print(f"  Acceso en red LAN        : http://{lan_ip}:{bound_port}/")
        print("  [Nota LAN] Si otro equipo no logra conectarse, verifique que el Firewall")
        print(f"             del sistema permita tráfico TCP entrante en el puerto {bound_port}.")
    print(f"  Panel administrativo     : http://localhost:{bound_port}/admin")
    print(f"  Directorio protegido     : http://localhost:{bound_port}/private/")
    print(f"  DocumentRoot resuelto    : {doc_root_path}")
    print(f"  Logs de acceso / error   : {logger.access_log_path.name} / {logger.error_log_path.name}")

    if not config.admin_password_hash:
        print("-" * 72)
        print("  [AVISO DE SEGURIDAD] No hay contraseña de administrador configurada.")
        print("  Las rutas '/admin' y '/private' rechazarán el acceso hasta inicializarla.")
        print("  Para configurar una contraseña ejecute:")
        print("      python main.py --set-password")
        print("  O para iniciar con credenciales de demostración de laboratorio:")
        print("      python main.py --init-demo")
    print("-" * 72)
    print("  Presione Ctrl+C para detener el servidor de forma ordenada.")
    print("=" * 72)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Señal de interrupción recibida (Ctrl+C). Cerrando servidor y conexiones...")
    finally:
        server.stop()
        logger.close()
        print("[OK] Servidor detenido correctamente.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
