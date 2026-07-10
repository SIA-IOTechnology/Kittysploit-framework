#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import run_nextjs_version_scan


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js Next-Resume DoS (GHSA-mg66) detection",
        "description": (
            "Fingerprints Next.js and flags versions < 16.2.5 potentially affected by "
            "GHSA-mg66-mrh9-m8jx (Next-Resume DoS)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "advisory": "GHSA-mg66-mrh9-m8jx",
        "references": ["https://github.com/advisories/GHSA-mg66-mrh9-m8jx"],
        "tags": ["scanner", "http", "nextjs", "dos", "ppr", "ghsa-mg66"],
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
            advisory="GHSA-mg66-mrh9-m8jx",
            patched_version="16.2.5",
            issue_label="GHSA-mg66 Next-Resume DoS",
            severity="high",
        )
