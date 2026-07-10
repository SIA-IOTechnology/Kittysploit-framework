#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import run_nextjs_version_scan


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js WebSocket upgrade SSRF (CVE-2026-44578) detection",
        "description": (
            "Fingerprints Next.js and flags versions < 16.2.5 affected by CVE-2026-44578 "
            "(router-server WebSocket upgrade SSRF)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-44578",
        "references": ["https://github.com/advisories/GHSA-c4j6-fc7j-m34r"],
        "modules": [
            "auxiliary/scanner/http/nextjs_cve_2026_44578_websocket_upgrade_ssrf",
        ],
        "tags": ["scanner", "nextjs", "ssrf", "websocket", "cve-2026-44578"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
    }

    def run(self):
        return run_nextjs_version_scan(
            self,
            cve="CVE-2026-44578",
            patched_version="16.2.5",
            issue_label="CVE-2026-44578 WebSocket upgrade SSRF",
            severity="critical",
        )
