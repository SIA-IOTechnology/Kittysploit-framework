#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS NSID / CHAOS version probe (NSE dns-nsid)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.dns.detectors import probe_dns_nsid


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "DNS NSID / BIND Version",
        "description": (
            "Queries CHAOS TXT id.server / version.bind and EDNS NSID to fingerprint "
            "a nameserver (NSE dns-nsid)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/dns-nsid.html"],
        "tags": ["dns", "nsid", "bind", "fingerprint", "scanner", "udp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
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
        info = probe_dns_nsid(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="DNS nameserver identity disclosed",
            id_server=str(info.get("id_server") or ""),
            version_bind=str(info.get("version_bind") or ""),
            nsid=str(info.get("nsid") or ""),
        )
        return True
