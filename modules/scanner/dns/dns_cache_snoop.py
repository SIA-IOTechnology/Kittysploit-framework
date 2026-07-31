#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS cache snooping (NSE dns-cache-snoop)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_cache_snoop


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS Cache Snoop",
        "description": (
            "Sends non-recursive queries for popular names; answers imply the resolver "
            "has them cached (NSE dns-cache-snoop)."
        ),
        "author": ["KittySploit Team"],
        "severity": "low",
        "references": ["https://nmap.org/nsedoc/scripts/dns-cache-snoop.html"],
        "tags": ["dns", "cache", "snoop", "scanner", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(53, "DNS port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_dns_cache_snoop(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("snoopable"):
            return False
        cached = info.get("cached") or []
        self.set_info(
            severity="low",
            reason=f"DNS cache snoop hit ({len(cached)} names)",
            cached=list(cached)[:20],
            checked=int(info.get("checked") or 0),
        )
        return True
