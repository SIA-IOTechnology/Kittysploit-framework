#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Joomla SP Page Builder CVE-2026-48908 upload surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import Joomla
_UPLOAD_PATH = "/index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon"


class Module(Scanner, Http_client, Joomla):
    __info__ = {
        "name": "Joomla SP Page Builder CVE-2026-48908 Detect",
        "description": (
            "Detects SP Page Builder (com_sppagebuilder) and the uploadCustomIcon task "
            "linked to CVE-2026-48908."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-48908"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-48908"],
        "tags": ["scanner", "joomla", "sppagebuilder", "cve-2026-48908"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/http/joomla_sppagebuilder_cve_2026_48908_rce",
                ],
            },
        },
    }

    def run(self):
        for hint in ("/components/com_sppagebuilder/", "/media/com_sppagebuilder/"):
            response = self.joomla_http_get(hint, timeout=10)
            if response and int(response.status_code or 0) in (200, 403, 401):
                self.set_info(
                    severity="critical",
                    reason="SP Page Builder component present",
                    path=_UPLOAD_PATH,
                )
                return True
        response = self.joomla_http_get("/", timeout=10)
        if response and "com_sppagebuilder" in (response.text or ""):
            self.set_info(
                severity="critical",
                reason="SP Page Builder referenced on site",
                path=_UPLOAD_PATH,
            )
            return True
        return False
