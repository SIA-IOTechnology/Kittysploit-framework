#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect N-able N-central CVE-2026-86218 pre-auth RCE exposure indicators."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "N-able N-central CVE-2026-86218 Detect",
        "description": (
            "Detects N-able N-central builds before 2026.3.1.14 (Hotfix 4) that expose "
            "the pre-authentication /remoteControlAction.do?method=getPierDetails "
            "reconnaissance endpoint associated with CVE-2026-86218 static code injection."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-86218"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-86218",
            "https://status.n-able.com/2026/09/06/n-central-2026-3-hotfix-4-cve-2026-86218/",
        ],
        "tags": [
            "web",
            "scanner",
            "n-able",
            "ncentral",
            "rmm",
            "pre-auth",
            "rce",
            "cve-2026-86218",
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
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["n-central", "ncentral", "n-able"],
                "endpoint_pattern_any": ["/login"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_surface", "from_detail": "N-central login"},
                ],
                "suggested_followups": [
                    "scanner/http/ncentral_detect",
                ],
            },
        },
    }

    probe_path = OptString(
        "/remoteControlAction.do?method=getPierDetails",
        "Pre-exploitation endpoint seen in CVE-2026-86218 activity",
        False,
        advanced=True,
    )

    _BUILD_RE = re.compile(r"2026\.\d+\.\d+\.\d+|build\s*[:=]\s*[\d.]+", re.IGNORECASE)

    @staticmethod
    def _parse_build(text: str) -> str:
        match = Module._BUILD_RE.search(text or "")
        return match.group(0) if match else ""

    @staticmethod
    def _build_affected(build: str) -> bool | None:
        if not build:
            return None
        digits = re.findall(r"\d+", build)
        if len(digits) < 4:
            return None
        major, minor, patch, hotfix = (int(x) for x in digits[:4])
        if major > 2026:
            return False
        if major < 2026:
            return True
        if minor > 3:
            return False
        if minor < 3:
            return True
        if patch > 1:
            return False
        if patch < 1:
            return True
        return hotfix < 14

    def run(self):
        login = self.http_request(method="GET", path="/login", allow_redirects=False)
        if not login or int(login.status_code or 0) != 200:
            return False
        body = login.text or ""
        if 'class="ncentral"' not in body and "n-central" not in body.lower():
            return False

        build = self._parse_build(body)
        probe = self.http_request(
            method="GET",
            path=str(self.probe_path or "/remoteControlAction.do?method=getPierDetails"),
            allow_redirects=False,
        )
        if not probe:
            return False
        probe_code = int(probe.status_code or 0)
        probe_body = probe.text or ""
        probe_location = str(probe.headers.get("Location") or "")

        if "login" in probe_location.lower():
            return False

        affected = self._build_affected(build)
        exposed = probe_code in (200, 400, 500) or (
            probe_code not in (401, 403, 404) and probe_body.strip()
        )

        if affected is False:
            return False
        if exposed and affected is not False:
            self.set_info(
                severity="critical",
                cve="CVE-2026-86218",
                reason=(
                    "N-central exposes getPierDetails without login redirect "
                    f"(HTTP {probe_code})"
                ),
                build=build or "unknown",
            )
            return True
        if affected is True:
            self.set_info(
                severity="critical",
                cve="CVE-2026-86218",
                reason="N-central build appears before 2026.3.1.14",
                build=build or "unknown",
            )
            return True
        return False
