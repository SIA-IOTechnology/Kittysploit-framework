#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Output Messenger Server XMPP / file-listener exposure (CVE-2026-75289)."""

import socket

from kittysploit import *


class Module(Scanner):
    __info__ = {
        "name": "Output Messenger Unauthenticated Zip-Slip Surface Detection",
        "description": (
            "Checks for open TCP 14121 (XMPP) and 14135 (SOCKS5 file listener) used by "
            "Output Messenger Server 2.0.x pre-auth zip-slip RCE (CVE-2026-75289)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-75289"],
        "tags": ["output-messenger", "xmpp", "tcp", "rce", "unauth", "kev"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/tcp/output_messenger_unauth_zipslip_rce",
                ],
            },
        },
        "references": [
            "https://0day-rubbish.com/blog/output-messenger-unauth-zipslip-plugin-rce",
        ],
    }

    xmpp_port = OptPort(14121, "XMPP port", required=False)
    socks_port = OptPort(14135, "SOCKS5 file port", required=False)

    def _open(self, host: str, port: int) -> bool:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            return True
        except OSError:
            return False

    def run(self):
        host = str(self.rhost or self.target or "").strip()
        if not host:
            return False
        xmpp = int(self.xmpp_port or 14121)
        socks = int(self.socks_port or 14135)
        x_ok = self._open(host, xmpp)
        s_ok = self._open(host, socks)
        if x_ok and s_ok:
            self.set_info(
                severity="critical",
                reason="Output Messenger XMPP and SOCKS file ports exposed",
                xmpp_port=xmpp,
                socks_port=socks,
            )
            return True
        if x_ok:
            self.set_info(
                severity="high",
                reason="Output Messenger XMPP port open (file listener closed)",
                xmpp_port=xmpp,
            )
            return True
        return False
