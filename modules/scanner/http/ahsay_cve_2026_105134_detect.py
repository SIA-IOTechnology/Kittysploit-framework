#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Ahsay CBS-style UpdateReceivers endpoint (CVE-2026-105134 pattern)."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_ENDPOINT = "/rps/api/json/UpdateReceivers.do"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ahsay CBS CVE-2026-105134 UpdateReceivers detect",
        "description": (
            "Detects POST /rps/api/json/UpdateReceivers.do used in CVE-2026-105134 "
            "(OS command injection via unsanitized random parameter)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-105134"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-105134",
            "https://github.com/RayanAlmulhim/CVE-2026-105134-lab",
        ],
        "tags": ["scanner", "ahsay", "command-injection", "cve-2026-105134"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/ahsay_cve_2026_105134_update_receivers_rce",
                ],
            },
        },
    }

    port = OptPort(443, "Target HTTP port", required=False)
    ssl = OptBool(True, "Use HTTPS", required=False, advanced=True)

    def run(self):
        benign = self.http_request(
            method="POST",
            path=_ENDPOINT,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"receiver_id": "kittysploit_probe", "random": "abc123"}),
            allow_redirects=False,
        )
        if not benign:
            return False
        status = int(benign.status_code or 0)
        if status not in (200, 400, 500):
            return False
        body = benign.text or ""
        if "receiver" in body.lower() or "status" in body.lower():
            try:
                json.loads(body)
            except json.JSONDecodeError:
                if status != 200:
                    return False
            self.set_info(
                severity="critical",
                reason="UpdateReceivers JSON API responding",
                path=_ENDPOINT,
            )
            return True
        return False
