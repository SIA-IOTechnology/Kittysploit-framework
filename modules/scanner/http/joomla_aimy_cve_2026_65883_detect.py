#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Aimy Captcha-Less Form Guard (CVE-2026-65883 surface)."""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import Joomla

# Plugin versions 18.0–20.0 affected; 20.1 patched
_AIMY_FIRST = "18.0"
_AIMY_PATCHED = "20.1"

_FORM_PATHS = (
    "/index.php?option=com_users&view=registration",
    "/index.php?option=com_users&view=login",
    "/index.php?option=com_users&view=reset",
    "/index.php?option=com_users&view=remind",
    "/index.php?option=com_contact&view=contact",
    "/index.php?option=com_content&view=article&id=1",
    "/index.php",
    "/",
)

_VERSION_RES = (
    re.compile(r"aimy[^\"']{0,40}ver[=:\s]+([0-9]+(?:\.[0-9]+)*)", re.I),
    re.compile(r"captcha-less[^\"']{0,40}([0-9]+(?:\.[0-9]+)*)", re.I),
    re.compile(r"/plugins/system/aimy[^\"']*?/([0-9]+(?:\.[0-9]+)*)/", re.I),
)


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

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": str(self.user_agent or "KittySploit")}

    def _get(self, path: str):
        return self.http_request(
            method="GET",
            path=path,
            headers=self._headers(),
            allow_redirects=True,
            timeout=int(self.timeout or 15),
        )

    @staticmethod
    def _extract_version(html: str) -> str:
        for rx in _VERSION_RES:
            match = rx.search(html or "")
            if match:
                return match.group(1)
        return ""

    def _version_vulnerable(self, version: str) -> Optional[bool]:
        if not version:
            return None
        # vulnerable if >= 18.0 and < 20.1
        if self.version_less_than(version, _AIMY_FIRST):
            return False
        if not self.version_less_than(version, _AIMY_PATCHED):
            return False
        return True

    def _find_clfgd(self) -> Tuple[Optional[str], str, str]:
        """Return (path, version, snippet_hint) when clfgd is present."""
        for path in _FORM_PATHS:
            try:
                resp = self._get(path)
            except Exception:
                continue
            if not resp or int(resp.status_code or 0) != 200:
                continue
            body = resp.text or ""
            if 'name="clfgd"' not in body and "name='clfgd'" not in body:
                if "clfgd" not in body.lower():
                    continue
            version = self._extract_version(body)
            return path, version, "clfgd"
        return None, "", ""

    def run(self):
        path, version, _ = self._find_clfgd()
        if not path:
            return False

        vulnerable = self._version_vulnerable(version)
        if vulnerable is True:
            severity = "critical"
            reason = (
                f"Aimy Captcha-Less Form Guard {version} on {path} "
                f"(CVE-2026-65883, < {_AIMY_PATCHED})"
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
