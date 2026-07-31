#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open SOCKS4/5 proxy check (NSE socks-open-proxy)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.socks.detectors import probe_socks_open_proxy


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SOCKS Open Proxy",
        "description": (
            "Tests whether a SOCKS4/5 service allows unauthenticated CONNECT to an "
            "external host (NSE socks-open-proxy)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://nmap.org/nsedoc/scripts/socks-open-proxy.html"],
        "tags": ["socks", "proxy", "scanner", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1080, "SOCKS port", True)
    dest_host = OptString("1.1.1.1", "External host used for CONNECT test", False, advanced=True)
    dest_port = OptPort(80, "External port used for CONNECT test", False, advanced=True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_socks_open_proxy(
            host=host,
            port=port,
            timeout=self._timeout(),
            dest_host=str(self.dest_host or "1.1.1.1"),
            dest_port=int(self.dest_port or 80),
        )
        if not info.get("open_proxy"):
            return False
        self.set_info(
            severity="high",
            reason="Open SOCKS proxy (CONNECT granted)",
            socks5=bool(info.get("socks5")),
            socks4=bool(info.get("socks4")),
        )
        return True
