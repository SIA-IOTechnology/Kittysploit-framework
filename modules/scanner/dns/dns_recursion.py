#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS recursion check (NSE dns-recursion)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_recursion


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS Recursion Available",
        "description": (
            "Checks whether a DNS server answers recursive queries for third-party names "
            "(open resolver risk — NSE dns-recursion)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/dns-recursion.html"],
        "tags": ["dns", "recursion", "open-resolver", "scanner", "misconfig", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(53, "DNS port", True)
    qname = OptString("example.com", "Third-party name to resolve", False)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_dns_recursion(
            host=host,
            port=self._port(),
            timeout=self._timeout(),
            qname=str(self.qname or "example.com"),
        )
        if not info.get("recursion_available"):
            return False
        self.set_info(
            severity="medium",
            reason="DNS recursion available (open resolver)",
            answers=list(info.get("answers") or [])[:5],
            qname=str(self.qname or "example.com"),
        )
        return True
