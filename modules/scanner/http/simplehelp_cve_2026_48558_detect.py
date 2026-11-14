#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SimpleHelp OIDC auth bypass surface (CVE-2026-48558)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.simplehelp_client import SimpleHelp


class Module(Scanner, Http_client, SimpleHelp):
    __info__ = {
        "name": "SimpleHelp CVE-2026-48558 detect",
        "description": (
            "Checks SimpleHelp 5.5.0–5.5.15 / vulnerable 6.0 pre-releases with "
            "enabled OIDC provider exposed via auth/v1/account/login_options."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-48558"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-48558",
            "https://guides.simple-help.com/kb---security-vulnerabilities-05-2026",
        ],
        "tags": ["simplehelp", "oidc", "auth-bypass", "cve-2026-48558"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/simplehelp_cve_2026_48558_oidc_rce",
                ],
            },
        },
    }

    ssl = OptBool(True, "Use HTTPS", True)

    def run(self):
        ok, version, reason = self.simplehelp_scan()
        if not ok:
            if version:
                self.set_info(severity="info", reason=reason, version=version)
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-48558",
            reason=reason,
            version=version,
        )
        return True