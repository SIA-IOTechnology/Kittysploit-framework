from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort
from core.output_handler import (
    print_success, print_status, print_error,
    print_info, print_warning
)
import socket


class TCPSocket:
    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.connected = False

        try:
            self.socket.connect((self.host, self.port))
            self.connected = True
            print_success(f"TCP connection established to {self.host}:{self.port}")
        except Exception as e:
            self.connected = False
            print_error(f"Failed to connect to {self.host}:{self.port} -> {e}")
            raise

    def send(self, data: bytes):
        if not self.connected:
            raise ConnectionError("Socket is not connected")

        try:
            self.socket.sendall(data)
            print_info(f"Sent {len(data)} bytes to {self.host}:{self.port}")
        except Exception as e:
            print_error(f"Send failed -> {e}")
            raise

    def recv(self, size: int = 4096) -> bytes:
        """
        Receive up to `size` bytes (single recv call).
        """
        if not self.connected:
            raise ConnectionError("Socket is not connected")

        try:
            data = self.socket.recv(size)
            if not data:
                self.connected = False
                print_warning("Connection closed by remote host")
            return data
        except socket.timeout:
            print_warning("Receive timeout")
            return b""
        except Exception as e:
            print_error(f"Receive failed -> {e}")
            raise

    def recv_until(self, delimiter: bytes, chunk_size: int = 4096) -> bytes:
        """
        Receive data until delimiter is found.
        Example delimiter: b"\\r\\n\\r\\n"
        """
        if not self.connected:
            raise ConnectionError("Socket is not connected")

        if not isinstance(delimiter, (bytes, bytearray)) or len(delimiter) == 0:
            raise ValueError("delimiter must be non-empty bytes")

        data = b""
        try:
            while delimiter not in data:
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    self.connected = False
                    print_warning("Connection closed by remote host (before delimiter)")
                    break
                data += chunk
            return data
        except socket.timeout:
            print_warning("Receive timeout (before delimiter)")
            return data
        except Exception as e:
            print_error(f"recv_until failed -> {e}")
            raise

    def recv_all(self, chunk_size: int = 4096) -> bytes:
        """
        Receive everything until socket closes or timeout happens.
        Useful for banners or short responses.
        """
        if not self.connected:
            raise ConnectionError("Socket is not connected")

        data = b""
        try:
            while True:
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    self.connected = False
                    break
                data += chunk
        except socket.timeout:
            # Timeout means "no more data right now" (common behavior)
            pass
        except Exception as e:
            print_error(f"recv_all failed -> {e}")
            raise

        return data

    def close(self):
        try:
            self.socket.close()
            self.connected = False
            print_status(f"TCP connection closed ({self.host}:{self.port})")
        except Exception as e:
            print_warning(f"Close failed -> {e}")


class Tcp_client(BaseModule):
    tcp_host = OptString("", "Target IP or hostname", True)
    tcp_port = OptPort(80, "Target port", True)

    def __init__(self, framework=None):
        super().__init__(framework)

    def open_tcp_connection(self, host: str = None, port: int = None, timeout: int = 10) -> TCPSocket:
        tcp_host = host if host else self.tcp_host.value
        tcp_port = port if port else self.tcp_port.value
        return TCPSocket(tcp_host, tcp_port, timeout)
