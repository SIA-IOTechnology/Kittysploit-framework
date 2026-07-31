#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS SRV record enumeration (NSE dns-srv-enum)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_srv_enum


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS SRV Enumeration",
        "description": (
            "Enumerates common SRV records (LDAP, Kerberos, SIP, XMPP, Autodiscover) "
            "for a domain via a target nameserver (NSE dns-srv-enum)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/dns-srv-enum.html"],
        "tags": ["dns", "srv", "ad", "kerberos", "scanner", "discovery", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(53, "DNS port", True)
    domain = OptString("", "Domain to enumerate SRV records for (required)", True)

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip()
        if not host or not domain:
            print_error("target and domain are required")
            return False
        info = probe_dns_srv_enum(
            host=host, domain=domain, port=self._port(), timeout=self._timeout()
        )
        if not info.get("found"):
            return False
        records = info.get("records") or []
        self.set_info(
            severity="info",
            reason=f"Found {len(records)} SRV records for {domain}",
            domain=domain,
            records=records[:30],
        )
        return True
