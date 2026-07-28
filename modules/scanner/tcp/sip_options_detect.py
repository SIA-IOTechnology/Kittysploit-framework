#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SIP services via OPTIONS probe (TCP then UDP)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.sip.detectors import probe_sip_tcp, probe_sip_udp


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SIP OPTIONS Detection",
        "description": (
            "Sends a SIP OPTIONS request over TCP (then UDP fallback) to fingerprint "
            "PBX / VoIP endpoints on port 5060."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["sip", "voip", "pbx", "scanner", "discovery", "telecom"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(5060, "SIP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            return False

        info = None
        if self.is_tcp_open(host=host, port=port):
            info = probe_sip_tcp(host=host, port=port, timeout=self._timeout())
        if not info or not info.get("detected"):
            info = probe_sip_udp(host=host, port=port, timeout=self._timeout())
        if not info or not info.get("detected"):
            return False

        server = str(info.get("server") or info.get("user_agent") or "")
        self.set_info(
            severity="info",
            reason=f"SIP service detected ({info.get('transport')})",
            status_line=str(info.get("status_line") or ""),
            server=server,
            allow=str(info.get("allow") or ""),
            transport=str(info.get("transport") or ""),
        )
        return True
