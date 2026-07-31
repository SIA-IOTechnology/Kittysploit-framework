#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP open relay check (NSE smtp-open-relay)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.smtp.detectors import probe_smtp_open_relay


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SMTP Open Relay",
        "description": (
            "Tests whether an SMTP server accepts third-party relay (MAIL FROM / RCPT TO "
            "to external domains) without completing DATA (NSE smtp-open-relay)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://nmap.org/nsedoc/scripts/smtp-open-relay.html"],
        "tags": ["smtp", "mail", "relay", "scanner", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(25, "SMTP port", True)
    mail_from = OptString("relaytest@example.com", "MAIL FROM address", False, advanced=True)
    rcpt_to = OptString("relaytest@example.org", "RCPT TO address", False, advanced=True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_smtp_open_relay(
            host=host,
            port=port,
            timeout=max(self._timeout(), 8.0),
            mail_from=str(self.mail_from or "relaytest@example.com"),
            rcpt_to=str(self.rcpt_to or "relaytest@example.org"),
        )
        if not info.get("vulnerable"):
            return False
        self.set_info(
            severity="high",
            reason="SMTP server accepted third-party RCPT TO (possible open relay)",
            mail_from_code=str(info.get("mail_from_code") or ""),
            rcpt_to_code=str(info.get("rcpt_to_code") or ""),
        )
        return True
