from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort
from core.output_handler import (
    print_success, print_status, print_error,
    print_info, print_warning
)

import socket
import time
import sys


class TCPServerSocket:
    def __init__(self, host: str, port: int, timeout: int = 10, backlog: int = 5, keepalive: bool = True, keepidle: int = 60, keepintvl: int = 10, keepcnt: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.backlog = backlog

        self.keepalive = keepalive
        self.keepidle = keepidle
        self.keepintvl = keepintvl
        self.keepcnt = keepcnt

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(self.timeout)

        # Keep-alive aussi sur le socket d'écoute (pas toujours utile, mais ok)
        if self.keepalive:
            self._set_keepalive(self.server_socket)

        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.backlog)

        # Connexion active (mode "single client")
        self.client_socket = None  # type: socket.socket | None
        self.client_address = None

        print_success(f"TCP server started on {self.host}:{self.port} (keepalive={self.keepalive})")

    def _set_keepalive(self, sock: socket.socket):
        """
        Active TCP keep-alive. Les paramètres fins dépendent de l'OS.
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # Options fines: Linux / certains Unix
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, int(self.keepidle))
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, int(self.keepintvl))
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, int(self.keepcnt))

            # macOS / BSD utilisent souvent TCP_KEEPALIVE (idle)
            if hasattr(socket, "TCP_KEEPALIVE") and not hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, int(self.keepidle))

        except Exception as e:
            # Keepalive "best effort" (selon OS / permissions)
            print_warning(f"Could not set keep-alive options -> {e}")

    # ---------- Single-client style API (comme tu utilises actuellement) ----------

    def accept(self):
        """
        Attend un client et le stocke comme connexion active.
        """
        try:
            client_socket, address = self.server_socket.accept()
            client_socket.settimeout(self.timeout)

            if self.keepalive:
                self._set_keepalive(client_socket)

            self.client_socket = client_socket
            self.client_address = address

            print_success(f"Connection received from {address[0]}:{address[1]}")
            return client_socket, address

        except socket.timeout:
            print_warning("Accept timeout (no incoming connection)")
            return None, None
        except Exception as e:
            print_error(f"Accept failed -> {e}")
            raise

    def _require_client(self):
        if not self.client_socket:
            raise RuntimeError("No active client. Call accept() first.")

    def send(self, data: bytes):
        self._require_client()
        try:
            self.client_socket.sendall(data)
            print_info(f"Sent {len(data)} bytes to {self.client_address[0]}:{self.client_address[1]}")
        except Exception as e:
            print_error(f"Send failed -> {e}")
            raise

    def recv(self, size: int = 4096) -> bytes:
        self._require_client()
        try:
            data = self.client_socket.recv(size)
            if not data:
                print_warning("Client disconnected")
                self.close_client()
            return data
        except socket.timeout:
            return b""
        except Exception as e:
            print_error(f"Recv failed -> {e}")
            raise

    def recv_until(self, delimiter: bytes, chunk_size: int = 4096, max_bytes: int = 2_000_000) -> bytes:
        self._require_client()
        if not isinstance(delimiter, (bytes, bytearray)) or len(delimiter) == 0:
            raise ValueError("delimiter must be non-empty bytes")

        data = b""
        try:
            while delimiter not in data:
                chunk = self.client_socket.recv(chunk_size)
                if not chunk:
                    print_warning("Client disconnected (before delimiter)")
                    self.close_client()
                    break
                data += chunk
                if len(data) >= max_bytes:
                    print_warning("recv_until reached max_bytes limit")
                    break
            return data
        except socket.timeout:
            return data
        except Exception as e:
            print_error(f"recv_until failed -> {e}")
            raise

    def recv_all(self, idle_timeout: float = 0.6, chunk_size: int = 4096, max_bytes: int = 5_000_000) -> bytes:
        self._require_client()
        data = b""
        last = time.time()

        try:
            while True:
                try:
                    chunk = self.client_socket.recv(chunk_size)
                    if chunk:
                        data += chunk
                        last = time.time()
                        if len(data) >= max_bytes:
                            print_warning("recv_all reached max_bytes limit")
                            break
                    else:
                        print_warning("Client disconnected")
                        self.close_client()
                        break
                except socket.timeout:
                    if (time.time() - last) >= idle_timeout:
                        break
        except Exception as e:
            print_error(f"recv_all failed -> {e}")
            raise

        return data

    def close_client(self):
        try:
            if self.client_socket:
                try:
                    self.client_socket.close()
                except Exception:
                    pass
            self.client_socket = None
            self.client_address = None
            print_status("Client connection closed")
        except Exception as e:
            print_warning(f"close_client failed -> {e}")

    # ---------- Multi-client helpers (serve_forever / handle_client) ----------

    def serve_forever(self, handle_client, sleep_on_timeout: float = 0.1):
        """
        Boucle serveur: accepte des clients, appelle handle_client(server, client_socket, address).
        Par défaut: séquentiel (un client à la fois). Tu peux le threader si besoin.
        """
        if not callable(handle_client):
            raise ValueError("handle_client must be callable")

        print_status("Server entering serve_forever loop")
        try:
            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                except socket.timeout:
                    time.sleep(sleep_on_timeout)
                    continue

                client_socket.settimeout(self.timeout)
                if self.keepalive:
                    self._set_keepalive(client_socket)

                print_success(f"Connection received from {address[0]}:{address[1]}")

                try:
                    handle_client(self, client_socket, address)
                except Exception as e:
                    print_error(f"handle_client raised -> {e}")
                finally:
                    try:
                        client_socket.close()
                    except Exception:
                        pass

        except KeyboardInterrupt:
            print_warning("Server interrupted (KeyboardInterrupt)")
        finally:
            self.close()

    def close(self):
        """
        Ferme client actif + socket serveur.
        """
        self.close_client()
        try:
            self.server_socket.close()
            print_success(f"TCP server closed on {self.host}:{self.port}")
        except Exception as e:
            print_warning(f"Server close failed -> {e}")


class Tcp_server(BaseModule):
    tcp_host = OptString("0.0.0.0", "Bind IP / interface", True)
    tcp_port = OptPort(4444, "Bind port", True)

    def __init__(self, framework=None):
        super().__init__(framework)

    def start_tcp_server(self, host: str = None, port: int = None, timeout: int = 10, keepalive: bool = True, keepidle: int = 60, keepintvl: int = 10, keepcnt: int = 5) -> TCPServerSocket:
        tcp_host = host if host else self.tcp_host.value
        tcp_port = port if port else self.tcp_port.value
        return TCPServerSocket(tcp_host, tcp_port, timeout, keepalive, keepidle, keepintvl, keepcnt)
