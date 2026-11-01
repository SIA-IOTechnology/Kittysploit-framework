#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FortiSIEM gRPC surface (CVE-2026-106173)."""

from kittysploit import *
from lib.protocols.http2.http2_client import Http2_client
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client, Http2_client):
    __info__ = {
        "name": "FortiSIEM gRPC HTTP/2 Probe (CVE-2026-106173)",
        "description": (
            "Probes FortiSIEM gRPC (TCP 27918): TLS with ALPN h2 or plaintext HTTP/2."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-106173"],
        "tags": ["scanner", "tcp", "fortinet", "fortisiem", "grpc", "http2"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/tcp/fortisiem_cve_2026_106173_rce",
                    "auxiliary/admin/tcp/fortisiem_cve_2026_106173_file_write",
                    "scanner/http/fortisiem_detect",
                ],
            },
        },
    }

    DEFAULT_GRPC_PORT = 27918

    port = OptPort(DEFAULT_GRPC_PORT, "FortiSIEM gRPC port", required=True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = int(self.port or self.DEFAULT_GRPC_PORT)
        ok, reason = self.probe_http2(host, port)
        if ok:
            self.set_info(
                severity="high",
                reason=f"FortiSIEM gRPC HTTP/2 on {host}:{port} ({reason})",
                path=f"{host}:{port}",
            )
            return True
        if self.is_tcp_open(host, port):
            self.set_info(
                severity="medium",
                reason=f"TCP {port} open on {host}; HTTP/2 probe: {reason}",
                path=f"{host}:{port}",
            )
            return True
        return False
