#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F5 BIG-IP cookie decode (NSE http-bigip-cookie)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.bigip_put import probe_bigip_cookie


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP BIG-IP Cookie",
        "description": (
            "Detects F5 BIGipServer cookies and decodes classic pool-member IP:port "
            "(NSE http-bigip-cookie)."
        ),
        "author": ["KittySploit Team"],
        "severity": "low",
        "references": ["https://nmap.org/nsedoc/scripts/http-bigip-cookie.html"],
        "tags": ["http", "f5", "bigip", "cookie", "scanner", "disclosure"],
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
        headers = {k: v for k, v in r.headers.items()}
        # requests may merge Set-Cookie; also check raw
        set_cookie = r.headers.get("Set-Cookie") or ""
        info = probe_bigip_cookie(headers, set_cookie=set_cookie)
        if not info.get("detected"):
            return False
        decoded = info.get("decoded") or []
        severity = "medium" if decoded else "low"
        self.set_info(
            severity=severity,
            reason="F5 BIG-IP cookie detected",
            cookies=list(info.get("cookies") or [])[:5],
            decoded=decoded[:5],
        )
        return True
