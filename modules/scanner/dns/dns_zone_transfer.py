#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS AXFR zone transfer check (NSE dns-zone-transfer)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_zone_transfer


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS Zone Transfer (AXFR)",
        "description": (
            "Attempts an unauthenticated DNS zone transfer (AXFR) against the target "
            "nameserver for a given domain (NSE dns-zone-transfer)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": ["https://nmap.org/nsedoc/scripts/dns-zone-transfer.html"],
        "tags": ["dns", "axfr", "zone-transfer", "scanner", "misconfig", "udp"],
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
    domain = OptString("", "Domain / zone to transfer (required)", True)

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip()
        if not host or not domain:
            print_error("target and domain are required")
            return False
        info = probe_dns_zone_transfer(
            host=host, domain=domain, port=self._port(), timeout=self._timeout()
        )
        if not info.get("vulnerable"):
            return False
        records = info.get("records") or []
        self.set_info(
            severity="high",
            reason=f"AXFR allowed for {domain} ({len(records)} names sampled)",
            domain=domain,
            records=list(records)[:20],
        )
        return True
