#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Ivanti Neurons for ITSM CVE-2026-12645–12650 exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ivanti Neurons ITSM CVE-2026-12645 Detect",
        "description": (
            "Detects Ivanti Neurons for ITSM (formerly HEAT Service Management) "
            "instances likely affected by CVE-2026-12645/12646/12647 (missing "
            "authorization RCE) and CVE-2026-12650 (deserialization RCE). "
            "Fingerprints Login.aspx / AutomationService.svc surfaces and flags "
            "releases before 2026.2 when version metadata is exposed."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": [
            "CVE-2026-12645",
            "CVE-2026-12646",
            "CVE-2026-12647",
            "CVE-2026-12650",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12645",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12650",
            "https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Neurons-for-ITSM-Multiple-CVEs",
        ],
        "tags": [
            "web",
            "scanner",
            "ivanti",
            "itsm",
            "heat",
            "deserialization",
            "missing-authorization",
            "cve-2026-12645",
            "cve-2026-12650",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["ivanti", "heat", "itsm"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "AutomationService.svc"},
                ],
            },
        },
    }

    _VERSION_RE = re.compile(
        r"(?:neurons|itsm|heat|service manager)[^\d]{0,24}(20\d{2}\.\d+)",
        re.IGNORECASE,
    )

    @staticmethod
    def _version_affected(version: str) -> bool | None:
        match = re.search(r"(20\d{2})\.(\d+)", version or "")
        if not match:
            return None
        year = int(match.group(1))
        minor = int(match.group(2))
        if year > 2026:
            return False
        if year == 2026 and minor >= 2:
            return False
        if year < 2026:
            return True
        return True

    def _itsm_present(self) -> tuple[bool, str, str]:
        for path in ("/Login.aspx", "/saaslogin.aspx", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) not in (200, 302):
                continue
            body = response.text or ""
            blob = body.lower()
            if any(
                token in blob
                for token in (
                    "ivanti",
                    "neurons for itsm",
                    "neurons for it service",
                    "heat software",
                    "service manager",
                    "saaslogin.aspx",
                )
            ):
                return True, body, path
        return False, "", ""

    def _automation_surface(self) -> bool:
        for path in (
            "/Services/AutomationService.svc",
            "/Services/AutomationService.svc?wsdl",
            "/HEAT/Services/AutomationService.svc",
        ):
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            code = int(response.status_code or 0)
            body = (response.text or "").lower()
            if code in (200, 401, 403, 405) and (
                "automation" in body or "wsdl" in body or "service" in body or code == 200
            ):
                return True
        return False

    def run(self):
        present, body, hit_path = self._itsm_present()
        if not present:
            return False

        version = ""
        match = self._VERSION_RE.search(body)
        if match:
            version = match.group(1)

        affected = self._version_affected(version) if version else None
        if affected is False:
            return False

        automation = self._automation_surface()

        reason = "Ivanti Neurons for ITSM detected"
        if version and affected:
            reason += f" (release {version} appears pre-2026.2)"
        elif version:
            reason += f" (release {version}; verify patch level)"
        if automation:
            reason += "; AutomationService.svc integration surface reachable"
        reason += "; exploitation requires authenticated low-privilege access"

        self.set_info(
            severity="critical" if (affected or automation) else "high",
            cve="CVE-2026-12645",
            reason=reason,
            version=version or "unknown",
            path=hit_path,
            automation_service=automation,
        )
        return True
