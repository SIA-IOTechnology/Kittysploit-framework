#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect VNC/RFB remote desktop services."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.vnc.detectors import probe_vnc


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "VNC Service Detection",
        "description": "Detects VNC servers via RFB protocol version banner.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "vnc", "vendor": "realvnc"},
        "tags": ["vnc", "network", "scanner", "remote-desktop", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(5900, "Target VNC port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_vnc(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        version = str(info.get("version") or "")
        self.set_info(
            severity="info",
            reason=f"VNC service detected (RFB {version})".strip(),
            version=version,
        )
        return True
