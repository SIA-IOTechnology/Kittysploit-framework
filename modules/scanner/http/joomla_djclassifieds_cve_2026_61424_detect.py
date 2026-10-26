#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Joomla DJ-Classifieds CVE-2026-61424 imageupload exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import Joomla

_UPLOAD_QUERY = "index.php?option=com_djclassifieds&task=imageupload"


class Module(Scanner, Http_client, Joomla):
    __info__ = {
        "name": "Joomla DJ-Classifieds CVE-2026-61424 detect",
        "description": (
            "Detects com_djclassifieds imageupload task (CVE-2026-61424): unauthenticated "
            "file write to tmp/djupload/ in DJ-Classifieds < 3.9.5."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-61424"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-61424",
            "https://github.com/theendofabbys/CVE-2026-61424",
        ],
        "tags": ["joomla", "dj-classifieds", "file-upload", "scanner", "cve-2026-61424"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/joomla_djclassifieds_cve_2026_61424_upload",
                ],
            },
        },
    }

    def run(self):
        joomla = self.probe_joomla()
        if not joomla.get("found"):
            return False

        response = self.http_request(
            method="GET",
            path=f"/{_UPLOAD_QUERY}",
            allow_redirects=False,
        )
        if not response:
            return False
        status = int(response.status_code or 0)
        if status not in (200, 400, 405, 500):
            return False

        self.set_info(
            severity="critical",
            reason="DJ-Classifieds imageupload route reachable",
            path=f"/{_UPLOAD_QUERY}",
        )
        return True
