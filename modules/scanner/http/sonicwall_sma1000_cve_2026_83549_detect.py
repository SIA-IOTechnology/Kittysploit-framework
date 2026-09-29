#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SonicWall SMA1000 CVE-2026-83549 SNMP trap command injection chain surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SonicWall SMA1000 CVE-2026-83549 RCE Chain Detect",
        "description": (
            "Detects SMA1000 firmware branches vulnerable to CVE-2026-83549 when chained "
            "with CVE-2026-83548. Fingerprints WorkPlace/AMC build headers and flags "
            "pre-hotfix platform versions (12.4.3 before 03526, 12.5.0 before 02952). "
            "Does not invoke sysCtrl or inject SNMP trap commands."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-83549"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-83549",
            "https://www.sonicwall.com/support/notices/product-notice-sma-1000-series-affected-by-multiple-vulnerabilities-snwlid-2026-0016/kA1VN000002AXmQ0AW",
        ],
        "modules": [
            "scanner/http/sonicwall_sma1000_cve_2026_83548_detect",
        ],
        "tags": [
            "web",
            "scanner",
            "sonicwall",
            "sma1000",
            "command-injection",
            "cve-2026-83549",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["sonicwall", "sma"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "cmsSnmpTrap injection"},
                ],
                "suggested_followups": [
                    "scanner/http/sonicwall_sma1000_cve_2026_83548_detect",
                ],
            },
        },
    }

    port = OptPort(443, "SMA1000 HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    _BUILD_RE = re.compile(r"(12\.(?:4\.3|5\.0))[-_](\d{5})", re.IGNORECASE)

    @staticmethod
    def _affected(branch: str, hotfix: int) -> bool:
        branch = branch.strip()
        if branch == "12.4.3" and hotfix < 3526:
            return True
        if branch == "12.5.0" and hotfix < 2952:
            return True
        return False

    def _collect_build(self) -> str:
        markers = ""
        for path in ("/workplace/home.action", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items())
            body = response.text or ""
            markers = f"{headers}\n{body[:8000]}"
            if "SonicWall" in markers or "SMA/" in headers:
                break
        return markers

    def run(self):
        blob = self._collect_build()
        if not blob or "SonicWall" not in blob:
            return False
        match = self._BUILD_RE.search(blob)
        if not match:
            self.set_info(
                severity="medium",
                cve="CVE-2026-83549",
                reason="SMA1000 detected; firmware hotfix unknown — verify against 12.4.3-03526 / 12.5.0-02952",
            )
            return True
        branch, hotfix_raw = match.group(1), int(match.group(2))
        if self._affected(branch, hotfix_raw):
            self.set_info(
                severity="critical",
                cve="CVE-2026-83549",
                reason=f"SMA1000 {branch}-{hotfix_raw:05d} is before fixed hotfix (chain with CVE-2026-83548)",
                build=f"{branch}-{hotfix_raw:05d}",
            )
            return True
        return False
