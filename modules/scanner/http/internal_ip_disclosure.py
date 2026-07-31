#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal IP disclosure in HTTP responses (NSE http-internal-ip-disclosure)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.bigip_put import find_internal_ips


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP Internal IP Disclosure",
        "description": (
            "Looks for private RFC1918 / link-local addresses in HTTP headers and body "
            "(NSE http-internal-ip-disclosure)."
        ),
        "author": ["KittySploit Team"],
        "severity": "low",
        "references": ["https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html"],
        "tags": ["http", "disclosure", "internal-ip", "scanner"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        chunks = []
        for key, val in r.headers.items():
            chunks.append(f"{key}: {val}")
        try:
            chunks.append(r.text[:50000])
        except Exception:
            pass
        blob = "\n".join(chunks)
        ips = find_internal_ips(blob)
        if not ips:
            return False
        self.set_info(
            severity="low",
            reason=f"Internal IP address(es) disclosed ({len(ips)})",
            addresses=ips[:20],
        )
        return True
