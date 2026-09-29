#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Froxlor CVE-2026-100717 CRLF config injection exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Froxlor CVE-2026-100717 CRLF Detect",
        "description": (
            "Detects Froxlor server administration panels affected by "
            "CVE-2026-100717 (Validate::validateUrl CRLF in userinfo). Versions "
            "2.3.10 and earlier allow authenticated customers with subdomain "
            "rights to inject nginx/Apache directives via redirect URLs. "
            "Fingerprints Froxlor and compares reported version against 2.3.12."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-100717"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-100717",
            "https://github.com/froxlor/froxlor/security/advisories/GHSA-gxx3-hwjc-h2gp",
            "https://github.com/froxlor/froxlor/security/advisories/GHSA-c3p2-mj7v-5mrc",
        ],
        "tags": [
            "web",
            "scanner",
            "froxlor",
            "hosting",
            "crlf",
            "config-injection",
            "cve-2026-100717",
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
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["froxlor", "hosting", "panel"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "config_injection", "from_detail": "subdomain redirect URL"},
                ],
            },
        },
    }

    _FIXED = (2, 3, 12)
    _VERSION_RE = re.compile(
        r"(?:froxlor[^0-9]{0,20}|version[^0-9]{0,12})(\d+\.\d+\.\d+)",
        re.IGNORECASE,
    )

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, ...]:
        parts = re.findall(r"\d+", version or "")
        return tuple(int(p) for p in parts[:3])

    @staticmethod
    def _affected(version: str) -> bool | None:
        parsed = Module._version_tuple(version)
        if len(parsed) < 3:
            return None
        return parsed < Module._FIXED

    def _parse_version(self, text: str) -> str:
        for pattern in (self._VERSION_RE, re.compile(r"(\d+\.\d+\.\d+)")):
            match = pattern.search(text or "")
            if match:
                return match.group(1)
        return ""

    def run(self):
        hit_path = ""
        body = ""
        for path in ("/", "/index.php", "/admin/index.php"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) not in (200, 302):
                continue
            body = response.text or ""
            blob = body.lower()
            if "froxlor" in blob or "froxlor.org" in blob:
                hit_path = path
                break

        if not hit_path:
            api_probe = self.http_request(method="GET", path="/api.php", allow_redirects=False)
            if api_probe and int(api_probe.status_code or 0) in (200, 405):
                body = api_probe.text or ""
                if "froxlor" in body.lower() or "jsonrpc" in body.lower():
                    hit_path = "/api.php"

        if not hit_path:
            return False

        version = self._parse_version(body)
        affected = self._affected(version) if version else None
        if affected is False:
            return False

        reason = "Froxlor hosting panel detected"
        if version and affected:
            reason += f" (version {version} appears pre-2.3.12 CRLF fix)"
        elif version:
            reason += f" (version {version}; verify against 2.3.12 manually)"
        else:
            reason += " (version unknown — verify patch level manually)"
        reason += "; exploitation requires authenticated subdomain-create rights"

        self.set_info(
            severity="critical" if affected else "high",
            cve="CVE-2026-100717",
            reason=reason,
            version=version or "unknown",
            path=hit_path,
        )
        return True
