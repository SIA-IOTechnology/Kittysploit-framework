#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Phproject issue tracker (CVE-2026-104991 REST BOLA context)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_PHP_RE = re.compile(r"phproject|powered by phproject", re.I)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Phproject CVE-2026-104991 detect",
        "description": (
            "Detects self-hosted Phproject (<= 1.8.6) REST issue API used in "
            "CVE-2026-104991 missing allowAccess() on read/comment endpoints when "
            "security.restrict_access is enabled."
        ),
        "author": ["Alisher Qarshibayev", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-104991"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-104991",
            "https://github.com/wvllxe/CVE-2026-104991",
            "https://github.com/Alanaktion/phproject",
        ],
        "tags": ["scanner", "phproject", "idor", "api", "cve-2026-104991"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/phproject_cve_2026_104991_issue_idor",
                ],
            },
        },
    }

    port = OptPort(80, "Phproject HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)

    def run(self):
        for path in ("/", "/login", "/issues"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) not in (200, 302):
                continue
            if _PHP_RE.search(response.text or ""):
                self.set_info(
                    severity="high",
                    reason="Phproject UI fingerprint",
                    path=path,
                )
                return True

        probe = self.http_request(method="GET", path="/issues/1.json", allow_redirects=False)
        if probe and int(probe.status_code or 0) in (401, 403, 404, 200):
            body = probe.text or ""
            if "issue" in body.lower() or probe.headers.get("Content-Type", "").startswith("application/json"):
                self.set_info(
                    severity="high",
                    reason="Phproject-style /issues/@id.json REST route",
                    path="/issues/1.json",
                )
                return True
        return False
