#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP EHLO capability enum (NSE smtp-commands)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.smtp.detectors import probe_smtp_commands


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SMTP Commands",
        "description": (
            "Issues EHLO and lists advertised SMTP capabilities "
            "(NSE smtp-commands)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/smtp-commands.html"],
        "tags": ["smtp", "mail", "ehlo", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(25, "SMTP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_smtp_commands(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        caps = info.get("capabilities") or []
        interesting = [c for c in caps if any(
            x in c.upper() for x in ("AUTH", "STARTTLS", "VRFY", "EXPN", "PIPELINING")
        )]
        self.set_info(
            severity="info",
            reason=f"SMTP EHLO capabilities ({len(caps)})",
            banner=str(info.get("banner") or "")[:160],
            capabilities=list(caps)[:40],
            interesting=interesting[:15],
        )
        return True
