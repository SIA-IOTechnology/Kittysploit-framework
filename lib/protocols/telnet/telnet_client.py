"""Minimal telnet client compatible with Python 3.13+ (stdlib telnetlib removed)."""

from __future__ import annotations

import socket
from typing import Any, Union

from core.output_handler import print_error, print_info

Buffer = Union[bytes, bytearray, memoryview]


def open_framework_shell(handler: Any, host: str, port: int, timeout: float = 10, **meta: Any) -> bool:
    """Connect over TCP and register a telnet shell session with the framework."""
    try:
        sock = socket.create_connection((host, int(port)), timeout=float(timeout))
    except OSError as exc:
        print_error(f"Connection failed: {exc}")
        return False

    session_id = handler.handler_tcp(
        connection=sock,
        host=str(host),
        port=int(port),
        additional_data={"protocol": "telnet", "connection_type": "telnet", **meta},
    )
    if not session_id:
        sock.close()
        return False

    sm = getattr(getattr(handler, "framework", None), "session_manager", None)
    if sm:
        session = sm.get_session(session_id)
        if session:
            session.data["socket"] = sock
            session.data["connection"] = sock

    print_info(f"Use: sessions -i {session_id}")
    return True


class Telnet:
    def __init__(self, host: str, port: int = 23, timeout: float = 10):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def read_until(self, match: Buffer, timeout: float | None = None) -> bytes:
        if isinstance(match, str):
            match = match.encode()
        deadline = None if timeout is None else (socket.getdefaulttimeout() or 0) + timeout
        data = b""
        old_timeout = self.sock.gettimeout()
        try:
            if timeout is not None:
                self.sock.settimeout(timeout)
            while match not in data:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            self.sock.settimeout(old_timeout)
        return data

    def write(self, buffer: Buffer) -> None:
        if isinstance(buffer, str):
            buffer = buffer.encode()
        self.sock.sendall(buffer)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
