#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauthenticated DNS dynamic update (NSE dns-update)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_update


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS Dynamic Update",
        "description": (
            "Attempts an unauthenticated DNS UPDATE (add+delete probe A record) "
            "(NSE dns-update)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://nmap.org/nsedoc/scripts/dns-update.html"],
        "tags": ["dns", "update", "misconfig", "scanner", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(53, "DNS port", True)
    domain = OptString("", "Zone / domain to update (required)", True)
    record_name = OptString("kittysploit-probe", "Relative name for probe A record", False)
    record_ip = OptString("127.0.0.1", "IP used in probe A record", False, advanced=True)

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip()
        if not host or not domain:
            print_error("target and domain are required")
            return False
        info = probe_dns_update(
            host=host,
            domain=domain,
            name=str(self.record_name or "kittysploit-probe"),
            ip=str(self.record_ip or "127.0.0.1"),
            port=self._port(),
            timeout=self._timeout(),
        )
        if not info.get("vulnerable"):
            return False
        self.set_info(
            severity="high",
            reason=f"Unauthenticated DNS UPDATE accepted for zone {domain}",
            rcode=str(info.get("rcode") or ""),
            domain=domain,
        )
        return True
