#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Arista VeloCloud Orchestrator CVE-2026-93952 certificate auth bypass surface."""

import re
from typing import Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Arista VeloCloud CVE-2026-93952 Detect",
        "description": (
            "Detects on-prem VeloCloud Orchestrator (VCO) exposure to CVE-2026-93952 "
            "before fixed releases 5.2.3.16 / 6.4.2.8. The flaw allows unauthenticated "
            "access to privileged internal functionality when certificate-based Edge "
            "authentication is enabled. Fingerprints the VCO portal and parses version "
            "markers without sending certificate forgery payloads."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-93952"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-93952",
            "https://www.arista.com/en/support/advisories-notices/security-advisory/24765-security-advisory-0183",
        ],
        "tags": [
            "web",
            "scanner",
            "arista",
            "velocloud",
            "vco",
            "sd-wan",
            "auth-bypass",
            "cve-2026-93952",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.1,
            "requires": {
                "tech_hints_any": ["velocloud", "arista", "vco", "sd-wan"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass_surface", "from_detail": "Edge cert auth"},
                ],
                "suggested_followups": [],
            },
        },
    }

    _VERSION_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+)")

    @staticmethod
    def _likely_affected(version: str) -> Optional[bool]:
        if not version:
            return None
        parts = [int(x) for x in re.findall(r"\d+", version)[:4]]
        while len(parts) < 4:
            parts.append(0)
        major, minor, patch, build = parts[:4]
        if (major, minor, patch, build) <= (5, 2, 3, 15):
            return True
        if major == 6 and (minor, patch, build) <= (4, 2, 7):
            return True
        if major == 7 and (minor, patch, build) <= (0, 0, 2):
            return True
        if major >= 6:
            return False
        return None

    def run(self):
        hit_path = ""
        body_blob = ""
        for path in ("/login/login.html", "/portal/", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            lowered = body.lower()
            if any(token in lowered for token in ("velocloud", "orchestrator", "vmware sd-wan", "vco")):
                hit_path = path
                body_blob = body[:12000]
                break
        if not hit_path:
            return False
        version_match = self._VERSION_RE.search(body_blob)
        version = version_match.group(1) if version_match else ""
        affected = self._likely_affected(version)
        severity = "critical" if affected is not False else "high"
        self.set_info(
            severity=severity,
            cve="CVE-2026-93952",
            reason=(
                f"VCO version {version} appears pre-fix"
                if affected
                else "VeloCloud Orchestrator portal exposed (version unknown)"
            ),
            version=version or "unknown",
            path=hit_path,
        )
        return True
