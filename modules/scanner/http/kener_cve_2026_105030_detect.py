#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Kener CVE-2026-105030 monitor API exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_PROBE_TAGS = ("admin", "api", "internal", "monitor", "health")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Kener CVE-2026-105030 status monitor detect",
        "description": (
            "Detects Kener status dashboard (4.0.0–4.1.5) public monitor-bar API used in "
            "CVE-2026-105030 hidden monitor disclosure."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "cve": ["CVE-2026-105030"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-105030",
            "https://github.com/asvorg/CVE-2026-105030-poc",
        ],
        "tags": ["scanner", "kener", "exposure", "cve-2026-105030"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/kener_cve_2026_105030_monitor_enum",
                ],
            },
        },
    }

    port = OptPort(3000, "Kener HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)

    def run(self):
        for tag in _PROBE_TAGS:
            path = f"/dashboard-apis/monitor-bar?tag={tag}&days=1"
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            if int(response.status_code or 0) not in (200, 404):
                continue
            body = response.text or ""
            ctype = str(response.headers.get("Content-Type") or "")
            if "monitor" in body.lower() or ctype.startswith("application/json"):
                self.set_info(
                    severity="medium",
                    reason="Kener monitor-bar API responding",
                    path=path,
                )
                return True
        return False
