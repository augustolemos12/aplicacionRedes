"""Servidor TCP concurrente que implementa el ciclo de transporte para HTTP/1.1."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

from server.config import ServerConfig
from server.http_parser import HTTPParseError, read_http_request
from server.logging_setup import ServerLogger
from server.response import HTTPResponse, error_response
from server.router import HTTPRouter


class TCPHTTPServer:
    """
    Servidor HTTP construido directamente sobre `socket` TCP (IPv4) y `threading`.
    Procesa una solicitud HTTP por conexión TCP y cierra explícitamente (`Connection: close`).
    """

    def __init__(
        self,
        config: ServerConfig,
        config_path: Path,
        logger: ServerLogger,
        base_dir: Path | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.logger = logger
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.router = HTTPRouter(
            config=config,
            config_path=config_path,
            logger=logger,
            base_dir=self.base_dir,
        )

        self._server_socket: socket.socket | None = None
        self._running = threading.Event()
        self._active_threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        self.bound_address: tuple[str, int] = (config.host, config.port)

    def start_listening(self) -> tuple[str, int]:
        """Crea el socket TCP IPv4, configura SO_REUSEADDR, ejecuta bind() y listen()."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(128)
        # Timeout corto en el socket aceptador para permitir interrupción limpia con Ctrl+C
        sock.settimeout(0.5)

        self._server_socket = sock
        actual_host, actual_port = sock.getsockname()[:2]
        self.bound_address = (str(actual_host), int(actual_port))
        self._running.set()
        return self.bound_address

    def serve_forever(self) -> None:
        """
        Bucle principal de aceptación de conexiones TCP.
        Si `start_listening()` aún no fue invocado, lo llama automáticamente.
        """
        if self._server_socket is None:
            self.start_listening()

        assert self._server_socket is not None

        try:
            while self._running.is_set():
                try:
                    client_sock, client_addr = self._server_socket.accept()
                except TimeoutError:
                    continue
                except OSError:
                    # El socket fue cerrado durante el apagado
                    if not self._running.is_set():
                        break
                    continue

                worker = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                with self._threads_lock:
                    self._active_threads.add(worker)
                worker.start()
        finally:
            self.stop()

    def _handle_client_connection(
        self,
        client_sock: socket.socket,
        client_addr: tuple[str, int],
    ) -> None:
        """Atiende una conexión TCP individual de principio a fin y la cierra al terminar."""
        client_ip = client_addr[0] if client_addr else "unknown"
        method = "-"
        target = "-"
        version = "HTTP/1.1"
        include_body = True
        response: HTTPResponse

        try:
            client_sock.settimeout(float(self.router.config.socket_timeout))
            request = read_http_request(
                sock=client_sock,
                max_request_size=int(self.router.config.max_request_size),
                client_ip=client_ip,
            )
            method = request.method
            target = request.target
            version = request.version
            include_body = method != "HEAD"

            response = self.router.handle_request(request)

        except HTTPParseError as exc:
            self.logger.log_error(
                "HTTP_PARSE_ERROR",
                client_ip,
                f"Código {exc.status_code}: {exc.message}",
                target,
            )
            response = error_response(exc.status_code, exc.message, headers=exc.headers)

        except TimeoutError:
            self.logger.log_error(
                "SOCKET_TIMEOUT",
                client_ip,
                "Tiempo de espera agotado (timeout) leyendo la solicitud del cliente.",
                target,
            )
            response = error_response(400, "Tiempo de espera de lectura agotado (Socket Timeout).")

        except OSError as exc:
            self.logger.log_error(
                "SOCKET_ERROR",
                client_ip,
                f"Error de socket con el cliente: {exc}",
                target,
            )
            return

        except Exception as exc:  # noqa: BLE001
            self.logger.log_error(
                "INTERNAL_SERVER_ERROR",
                client_ip,
                f"Excepción interna no controlada ({type(exc).__name__}): {exc}",
                target,
            )
            response = error_response(500, "Ocurrió un error interno al procesar la solicitud.")

        try:
            raw_response = response.to_bytes(include_body=include_body)
            client_sock.sendall(raw_response)
            bytes_sent = len(raw_response)
            self.logger.log_access(
                client_ip=client_ip,
                method=method,
                target=target,
                version=version,
                status_code=response.status_code,
                bytes_sent=bytes_sent,
            )
        except OSError as exc:
            self.logger.log_error(
                "SEND_ERROR",
                client_ip,
                f"No se pudo enviar la respuesta completa al cliente: {exc}",
                target,
            )
        finally:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client_sock.close()
            except OSError:
                pass
            with self._threads_lock:
                self._active_threads.discard(threading.current_thread())

    def stop(self) -> None:
        """Detiene el servidor de forma ordenada, cierra el socket de escucha y espera hilos activos."""
        self._running.clear()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

        with self._threads_lock:
            threads_snapshot = list(self._active_threads)

        for thread in threads_snapshot:
            if thread is not threading.current_thread() and thread.is_alive():
                thread.join(timeout=2.0)
