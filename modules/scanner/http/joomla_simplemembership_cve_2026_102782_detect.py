#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Joomla Simple Membership CVE-2026-102782."""

import re
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import Joomla

_MANIFEST_PATHS = (
    "/administrator/components/com_simplemembership/simplemembership.xml",
    "/administrator/components/com_simplemembership/com_simplemembership.xml",
)


class Module(Scanner, Http_client, Joomla):
    __info__ = {
        "name": "Joomla Simple Membership CVE-2026-102782 Detect",
        "description": (
            "Detects OrdaSoft com_simplemembership < 7.4.0 and reachable checkLoginPass task."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-102782"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102782"],
        "tags": ["scanner", "joomla", "sqli", "cve-2026-102782"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/http/joomla_simplemembership_cve_2026_102782_sqli",
                ],
            },
        },
    }

    @staticmethod
    def _checklogin_path(login_value: str) -> str:
        return "/index.php?" + urlencode(
            {
                "option": "com_simplemembership",
                "task": "checkLoginPass",
                "login": login_value,
                "format": "raw",
            }
        )

    @staticmethod
    def _version_from_manifest(text: str):
        match = re.search(r"<version>\s*([^<]+)\s*</version>", text or "", re.I)
        if not match:
            return None
        parts = []
        for token in match.group(1).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        return tuple(parts) if parts else None

    def run(self):
        version_str = ""
        for manifest in _MANIFEST_PATHS:
            response = self.joomla_http_get(manifest, timeout=10)
            if not response or int(response.status_code or 0) != 200:
                continue
            version = self._version_from_manifest(response.text or "")
            if version:
                version_str = ".".join(str(x) for x in version)
                if version >= (7, 4, 0):
                    return False
                break

        probe = self.joomla_http_get(self._checklogin_path("pocbit_probe"), timeout=10)
        if not probe or int(probe.status_code or 0) == 404:
            return False
        if "404 Component not found" in (probe.text or ""):
            return False

        self.set_info(
            severity="critical",
            reason="Simple Membership checkLoginPass reachable",
            version=version_str or "unknown",
            path=self._checklogin_path("probe"),
        )
        return True
