#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Roundcube versions vulnerable to CVE-2025-49113."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.roundcube import Roundcube


class Module(Scanner, Http_client, Roundcube):

    __info__ = {
        "name": "Roundcube CVE-2025-49113 Detection",
        "description": (
            "Fingerprints Roundcube via rcversion and flags builds before 1.5.10 / "
            "1.6.x before 1.6.11 as vulnerable to post-auth PHP deserialization RCE."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-49113",
        "modules": ["exploits/multi/http/roundcube_cve_2025_49113_rce"],
        "tags": [
            "web", "scanner", "cve", "cve2025", "roundcube", "rce",
            "deserialization", "kev", "vkev", "vuln",
        ],
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
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/roundcube_cve_2025_49113_rce",
                ],
            },
        },
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-49113",
            "https://fearsoff.org/research/roundcube",
        ],
    }

    targeturi = OptString("/", "Roundcube base URI", required=False)

    def run(self):
        bases = [
            self.targeturi or "/",
            "/roundcube/",
            "/webmail/",
            "/mail/",
        ]
        seen = set()
        for base in bases:
            key = self.rc_normalize_base(base)
            if key in seen:
                continue
            seen.add(key)
            path = self.rc_join(base, "_task=login")
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if not self.rc_looks_like_roundcube(body):
                continue
            rcversion = self.rc_extract_version(body)
            if rcversion is None or not self.rc_version_vulnerable(rcversion):
                continue
            version = self.rc_parse_version(rcversion)
            self.set_info(
                severity="critical",
                reason=f"Roundcube {version} vulnerable to CVE-2025-49113",
                path=path,
                version=version,
                evidence=f"rcversion={rcversion}",
            )
            return True
        return False
