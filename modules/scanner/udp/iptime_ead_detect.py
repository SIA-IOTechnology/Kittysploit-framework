#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect ipTIME EAD UDP service (port 56026) associated with pre-auth RCE."""

from __future__ import annotations

import re
import socket

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client

EAD_DEFAULT_PORT = 56026


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "ipTIME EAD UDP Service Detection (56026)",
        "description": (
            "Detects ipTIME routers exposing the EAD UDP service on port 56026. "
            "On affected firmware (e.g. A3004T 14.19.0), this endpoint is reachable "
            "without authentication and is associated with pre-auth command injection."
        ),
        "author": ["Paccaron", "KittySploit Team"],
        "severity": "high",
        "tags": ["iptime", "router", "ead", "udp", "rce", "scanner", "zero-day"],
        "references": [
            "https://www.iptime.com/",
            "https://www.iptime.com/iptime/?page_id=147&pid=34",
        ],
        "modules": [
            "exploits/linux/router/iptime_a3004t_ead_rce",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 0.8,
            "noise": 0.3,
            "value": 0.9,
            "requires": {
                "tech_hints_any": ["iptime", "router"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_surface", "from_detail": "iptime_ead_udp"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/router/iptime_a3004t_ead_rce",
                ],
            },
        },
    }

    port = OptPort(EAD_DEFAULT_PORT, "EAD UDP port", required=True)
    http_port = OptPort(80, "HTTP port for ipTIME panel fingerprint", required=False, advanced=True)

    def _probe_iptime_http(self) -> bool:
        host = self._host()
        if not host:
            return False
        http_port = int(getattr(self.http_port, "value", None) or self.http_port or 80)
        url = f"http://{host}:{http_port}/sess-bin/login_session.cgi"
        try:
            import requests

            response = requests.get(url, timeout=self._timeout(), verify=False)
        except Exception:
            return False
        if int(response.status_code or 0) != 200:
            return False
        body = response.text or ""
        return bool(re.search(r"<TITLE>ipTIME\s+[A-Z0-9_-]+</TITLE>", body, re.I))

    def _udp_reachable(self) -> bool:
        host = self._host()
        if not host:
            return False
        port = int(self._port() or EAD_DEFAULT_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self._timeout())
        try:
            sock.sendto(b"\x00\x00\x00\x0a" + (b"\x00" * 60) + b";true\x00", (host, port))
            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                return True
        except OSError:
            return False
        finally:
            sock.close()

    def run(self):
        host = self._host()
        if not host:
            return False

        if not self._udp_reachable():
            return False

        iptime = self._probe_iptime_http()
        reason = (
            f"EAD UDP service reachable on {host}:{int(self._port() or EAD_DEFAULT_PORT)}"
            + ("; ipTIME login panel confirmed" if iptime else "")
        )
        self.set_info(
            severity="high" if iptime else "medium",
            reason=reason,
            path=f"udp/{int(self._port() or EAD_DEFAULT_PORT)}",
            iptime_panel=iptime,
        )
        return True
