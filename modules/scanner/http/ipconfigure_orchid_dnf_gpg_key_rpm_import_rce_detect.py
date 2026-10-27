#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection for IPConfigure Orchid VMS — Authenticated Command Injection in the DNF Repository GPG-Key Import Path ("""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "IPConfigure Orchid VMS \u2014 Authenticated Command Injection in the DNF Repository G \u2014 Detect",
        "description": "Fingerprint / reachability check for IPConfigure Orchid VMS \u2014 Authenticated Command Injection in the DNF Repository GPG-Key Import Path (root RCE)",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["scanner", "web", "ipconfigure"],
        "references": [],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/ipconfigure_orchid_dnf_gpg_key_rpm_import_rce"],
            },
        },
    }

    port = OptPort(443, "Service port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", allow_redirects=True)
        if not resp:
            return False
        body = (resp.text or "").lower()
        hints = ["ipconfigure", "dnf"]
        if any(h and h.lower() in body for h in hints if isinstance(h, str)):
            self.set_info(
                severity="high",
                reason="Target fingerprint matches ipconfigure advisory surface",
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
