#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import run_nextjs_version_scan


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js RSC server-action DoS (CVE-2026-23870) detection",
        "description": (
            "Fingerprints Next.js and flags versions < 16.2.5 affected by CVE-2026-23870 "
            "(expensive cyclic RSC server-action parsing)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-23870",
        "references": ["https://github.com/advisories/GHSA-8h8q-6873-q5fj"],
        "tags": ["scanner", "http", "nextjs", "dos", "rsc", "cve-2026-23870"],
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
            cve="CVE-2026-23870",
            patched_version="16.2.5",
            issue_label="CVE-2026-23870 RSC server-action DoS",
            severity="high",
        )
