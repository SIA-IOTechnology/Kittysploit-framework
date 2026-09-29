#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Check Point CVE-2026-85102 VPN certificate validation RCE surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Check Point CVE-2026-85102 VPN Detect",
        "description": (
            "Detects Check Point Security Gateway / Spark firewall exposure to "
            "CVE-2026-85102: improper certificate validation during Site-to-Site or "
            "Remote Access VPN negotiation (sk1000117). Fingerprints SSL VPN / Mobile "
            "Access login surfaces and flags builds before fixed JHF takes."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-85102"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-85102",
            "https://support.checkpoint.com/results/sk/sk1000117",
        ],
        "modules": [
            "scanner/http/checkpoint_detect",
        ],
        "tags": [
            "web",
            "scanner",
            "checkpoint",
            "vpn",
            "sslvpn",
            "certificate",
            "cve-2026-85102",
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
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["checkpoint"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "VPN cert negotiation"},
                ],
                "suggested_followups": [
                    "scanner/http/checkpoint_mobile_detect",
                ],
            },
        },
    }

    port = OptPort(443, "Check Point HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    _BUILD_RE = re.compile(r"(R8[12](?:\.\d+)?(?:\.\d+)?)", re.IGNORECASE)

    def run(self):
        hit_path = ""
        build = ""
        for path in ("/sslvpn/Login/Login", "/Login/Login", "/clients/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) not in (200, 302):
                continue
            body = response.text or ""
            headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items())
            blob = f"{headers}\n{body}"
            markers = (
                "Check Point Software Technologies Ltd. All rights reserved.",
                "/Login/images/CompanyLogo.png",
                "Mobile Access",
                "Connectra",
            )
            if any(marker in blob for marker in markers):
                hit_path = path
                match = self._BUILD_RE.search(blob)
                build = match.group(1) if match else ""
                break
        if not hit_path:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-85102",
            reason=(
                "Check Point VPN / Mobile Access portal exposed — "
                "validate JHF take against sk1000117"
            ),
            path=hit_path,
            build=build or "unknown",
        )
        return True
