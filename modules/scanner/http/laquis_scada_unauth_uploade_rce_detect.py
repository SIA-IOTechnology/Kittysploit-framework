#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for LCDS Laquis SCADA — Unauthenticated `/uploade.html` File Write + Startup `CMDEXT*.DLL` Autoload = Pr"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LCDS Laquis SCADA \u2014 Unauthenticated `/uploade.html` File Write + Startup `CMDEXT \u2014 Detect",
        "description": "Fingerprint / reachability check for The web/HMI component of LCDS Laquis SCADA, `mili.exe` (PE32 Delphi console, 1129984 bytes, listening on `0.0.0.0:11234` per `var.ini [MODE] PORT=11234`, plus Modbus TCP on `0.0.0.0:502`), routes roug",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "lcds"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/laquis_scada_unauth_uploade_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["lcds", "unauth"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches lcds advisory surface",
                confidence="medium",
            )
            return True
        code = int(getattr(resp, "status_code", 0) or 0)
        if code and code < 500:
            self.set_info(
                severity="medium",
                reason="HTTP service reachable — run matching exploit module for validation",
                confidence="low",
            )
            return True
        return False
