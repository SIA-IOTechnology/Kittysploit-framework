#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS subdomain brute (NSE dns-brute)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_brute


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS Subdomain Brute",
        "description": (
            "Brute-forces common subdomain labels against a target nameserver "
            "(NSE dns-brute)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/dns-brute.html"],
        "tags": ["dns", "brute", "subdomain", "scanner", "discovery", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 30,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(53, "DNS port", True)
    domain = OptString("", "Base domain to brute (required)", True)

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip()
        if not host or not domain:
            print_error("target and domain are required")
            return False
        info = probe_dns_brute(
            host=host, domain=domain, port=self._port(), timeout=self._timeout()
        )
        if not info.get("found"):
            return False
        hosts = info.get("hosts") or []
        self.set_info(
            severity="info",
            reason=f"Found {len(hosts)} subdomains for {domain}",
            domain=domain,
            hosts=hosts[:40],
        )
        return True
