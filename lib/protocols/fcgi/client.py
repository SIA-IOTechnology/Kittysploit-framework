#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic FastCGI wire protocol client and module mixin."""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Dict, Optional

from core.framework.base_module import BaseModule

FCGI_VERSION_1 = 1
FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_END_REQUEST = 3
FCGI_RESPONDER = 1


class FastcgiClient:
    """Blocking FastCGI responder session over TCP."""

    def __init__(self, host: str, port: int = 9000, timeout: float = 15.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @staticmethod
    def tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def header(rtype: int, req_id: int, content_len: int, padding: int = 0) -> bytes:
        return struct.pack(">BBHHBB", FCGI_VERSION_1, rtype, req_id, content_len, padding, 0)

    @classmethod
    def encode_length(cls, n: int) -> bytes:
        if n < 128:
            return bytes([n])
        return struct.pack(">I", n | 0x80000000)

    @classmethod
    def encode_name_value(cls, name: bytes, value: bytes) -> bytes:
        return cls.encode_length(len(name)) + cls.encode_length(len(value)) + name + value

    @classmethod
    def pack_begin_request(cls, req_id: int, role: int = FCGI_RESPONDER, flags: int = 0) -> bytes:
        hdr = cls.header(FCGI_BEGIN_REQUEST, req_id, 8)
        body = struct.pack(">HB5x", role, flags)
        return hdr + body

    @classmethod
    def pack_params(cls, req_id: int, params: Dict[str, str]) -> bytes:
        body = b""
        for key, val in params.items():
            body += cls.encode_name_value(key.encode(), str(val).encode())
        return cls.header(FCGI_PARAMS, req_id, len(body)) + body

    @classmethod
    def pack_params_end(cls, req_id: int) -> bytes:
        return cls.header(FCGI_PARAMS, req_id, 0)

    @classmethod
    def pack_stdin_end(cls, req_id: int) -> bytes:
        return cls.header(FCGI_STDIN, req_id, 0)

    @classmethod
    def pack_responder_request(cls, params: Dict[str, str], req_id: int = 1) -> bytes:
        return (
            cls.pack_begin_request(req_id)
            + cls.pack_params(req_id, params)
            + cls.pack_params_end(req_id)
            + cls.pack_stdin_end(req_id)
        )

    def sendall(self, data: bytes) -> None:
        if not self._sock:
            raise OSError("FastCGI not connected")
        self._sock.sendall(data)

    def read_stdout(self) -> str:
        if not self._sock:
            raise OSError("FastCGI not connected")
        self._sock.settimeout(self.timeout)
        output = b""
        try:
            while True:
                hdr = self._sock.recv(8)
                if len(hdr) < 8:
                    break
                rtype = hdr[1]
                clen = struct.unpack(">H", hdr[4:6])[0]
                plen = hdr[6]
                body = b""
                while len(body) < clen:
                    chunk = self._sock.recv(clen - len(body))
                    if not chunk:
                        break
                    body += chunk
                if plen:
                    self._sock.recv(plen)
                if rtype == FCGI_STDOUT:
                    output += body
                elif rtype == FCGI_END_REQUEST:
                    break
        except (socket.timeout, OSError):
            pass
        return output.decode("utf-8", errors="replace")

    def responder(self, params: Dict[str, str], req_id: int = 1) -> str:
        self.sendall(self.pack_responder_request(params, req_id))
        return self.read_stdout()

    @classmethod
    def one_shot_responder(
        cls,
        host: str,
        port: int,
        params: Dict[str, str],
        timeout: float = 15.0,
        req_id: int = 1,
    ) -> Optional[str]:
        client = cls(host, port, timeout)
        try:
            client.connect()
            out = client.responder(params, req_id)
            return out or None
        except OSError:
            return None
        finally:
            client.close()


class Fastcgi(BaseModule):
    """FastCGI mixin: TCP reachability and responder helpers for exploit modules."""

    def fcgi_target_host(self) -> str:
        explicit = ""
        if hasattr(self, "fpm_host"):
            explicit = str(getattr(self.fpm_host, "value", self.fpm_host) or "").strip()
        if explicit:
            return explicit.split(":")[0]
        raw = str(getattr(self, "target", None) or getattr(self, "rhost", "") or "")
        return raw.split("://")[-1].split("/")[0].split(":")[0]

    def fcgi_target_port(self) -> int:
        port = getattr(self, "fpm_port", 9000)
        if hasattr(port, "value"):
            port = port.value
        return int(port or 9000)

    def fcgi_timeout(self) -> float:
        for name in ("http_timeout", "timeout"):
            if hasattr(self, name):
                val = getattr(self, name)
                if hasattr(val, "value"):
                    val = val.value
                if val:
                    return float(val)
        return 15.0

    def fcgi_tcp_open(self, host: Optional[str] = None, port: Optional[int] = None) -> bool:
        host = host or self.fcgi_target_host()
        port = port if port is not None else self.fcgi_target_port()
        return FastcgiClient.tcp_reachable(host, port, timeout=min(self.fcgi_timeout(), 5.0))

    def fcgi_client(self, host: Optional[str] = None, port: Optional[int] = None) -> FastcgiClient:
        host = host or self.fcgi_target_host()
        port = port if port is not None else self.fcgi_target_port()
        return FastcgiClient(host, port, timeout=self.fcgi_timeout())

    def fcgi_responder(self, params: Dict[str, str], host: Optional[str] = None, port: Optional[int] = None) -> Optional[str]:
        host = host or self.fcgi_target_host()
        port = port if port is not None else self.fcgi_target_port()
        return FastcgiClient.one_shot_responder(host, port, params, timeout=self.fcgi_timeout())

    @staticmethod
    def fcgi_open_http_socket(host: str, port: int, tls: bool, timeout: float) -> socket.socket:
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        if not tls:
            return raw
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)

    @staticmethod
    def fcgi_read_http(sock: socket.socket, timeout: float) -> str:
        sock.settimeout(timeout)
        chunks: list[bytes] = []
        try:
            while True:
                block = sock.recv(65536)
                if not block:
                    break
                chunks.append(block)
                joined = b"".join(chunks)
                if b"\r\n\r\n" in joined and len(joined) > 512:
                    if b"transfer-encoding: chunked" not in joined[:512].lower():
                        break
        except (socket.timeout, OSError):
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")