#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Aimy Captcha-Less Form Guard (CVE-2026-65883 surface)."""

from __future__ import annotations

from typing import Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import AIMY_PATCHED_VERSION, Joomla


class Module(Scanner, Http_client, Joomla):
    __info__ = {
        "name": "Joomla Aimy Captcha-Less Form Guard CVE-2026-65883 Detect",
        "description": (
            "Detects the Aimy Captcha-Less Form Guard plugin (clfgd field) on "
            "Joomla forms. Versions 18.0–20.0 are affected by CVE-2026-65883 "
            "(unauthenticated PHP object injection via XOR'd clfgd → unserialize). "
            "Patched in 20.1. Detection only — no gadget upload."
        ),
        "author": ["Valentin Lobstein", "VulnCheck", "shinthink", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-65883"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-65883",
            "https://www.cve.org/CVERecord?id=CVE-2026-65883",
        ],
        "tags": [
            "joomla",
            "aimy",
            "captcha",
            "deserialization",
            "unserialize",
            "rce",
            "cve",
            "cve-2026-65883",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["rce"],
                "suggested_followups": [
                    "exploits/http/joomla_aimy_cve_2026_65883_rce",
                ],
            },
        },
        "module": "exploits/http/joomla_aimy_cve_2026_65883_rce",
        "modules": ["exploits/http/joomla_aimy_cve_2026_65883_rce"],
    }

    def run(self):
        found = self.aimy_find_form(timeout=int(self.timeout or 15))
        if not found:
            return False

        path = found["path"]
        version = found.get("version") or ""
        vulnerable = self.aimy_version_vulnerable(version)
        if vulnerable is True:
            severity = "critical"
            reason = (
                f"Aimy Captcha-Less Form Guard {version} on {path} "
                f"(CVE-2026-65883, < {AIMY_PATCHED_VERSION})"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"Aimy clfgd on {path} version={version or 'unknown'} "
                f"(outside 18.0–20.0 / patched)"
            )
        else:
            severity = "high"
            reason = (
                f"Aimy clfgd field on {path} (version unknown; "
                f"CVE-2026-65883 if 18.0–20.0)"
            )

        print_status(f"clfgd at {path} version={version or 'unknown'} vuln={vulnerable}")
        self.set_info(
            severity=severity,
            reason=reason,
            path=path,
            version=version or "unknown",
            vulnerable=vulnerable,
            cve="CVE-2026-65883",
        )
        return True
