#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FortiSandbox CVE-2026-39808 tracer-behavior injection surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_TRACER_PATH = "/fortisandbox/job-detail/tracer-behavior"
_OUTPUT_WEB_PATH = "/ng/test.txt"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Fortinet FortiSandbox CVE-2026-39808 Detect",
        "description": (
            "Fingerprints FortiSandbox web UI and the tracer-behavior endpoint associated "
            "with CVE-2026-39808 (jid parameter command injection)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-39808"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-39808",
        ],
        "tags": ["scanner", "fortinet", "fortisandbox", "cve-2026-39808"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/fortinet_fortisandbox_cve_2026_39808_rce",
                ],
            },
        },
    }

    port = OptPort(443, "HTTPS port", required=True)
    ssl = OptBool(True, "Use HTTPS", required=False, advanced=True)

    def run(self):
        hit = False
        for path in (_TRACER_PATH, _OUTPUT_WEB_PATH, "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            blob = f"{response.status_code} {(response.text or '')[:400]}"
            if "fortisandbox" in blob.lower() or "fortinet" in blob.lower():
                hit = True
                break
        if not hit:
            return False
        self.set_info(
            severity="critical",
            reason="FortiSandbox UI / tracer-behavior surface exposed",
            path=_TRACER_PATH,
        )
        return True
