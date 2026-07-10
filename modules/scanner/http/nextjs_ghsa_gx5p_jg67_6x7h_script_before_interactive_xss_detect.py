#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import run_nextjs_version_scan


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js next/script beforeInteractive XSS (GHSA-gx5p) detection",
        "description": (
            "Fingerprints Next.js and flags versions < 16.2.5 affected by GHSA-gx5p-jg67-6x7h "
            "(next/script beforeInteractive XSS)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "advisory": "GHSA-gx5p-jg67-6x7h",
        "references": ["https://github.com/advisories/GHSA-gx5p-jg67-6x7h"],
        "modules": [
            "auxiliary/scanner/http/nextjs_ghsa_gx5p_jg67_6x7h_script_before_interactive_xss",
        ],
        "tags": ["scanner", "nextjs", "xss", "ghsa-gx5p"],
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
            advisory="GHSA-gx5p-jg67-6x7h",
            patched_version="16.2.5",
            issue_label="GHSA-gx5p next/script beforeInteractive XSS",
            severity="high",
        )
