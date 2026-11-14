#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cPanel/WHM CRLF session injection surface (CVE-2026-41940)."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.cpanel_whm import Cpanel_whm
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Cpanel_whm):
    __info__ = {
        "name": "cPanel CVE-2026-41940 WHM detect",
        "description": (
            "Safe check: mints whostmgrsession and probes CRLF injection with expired=1 "
            "(non-destructive marker msg_code:[expired_session])."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-41940"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-41940"],
        "tags": ["cpanel", "whm", "auth-bypass", "cve-2026-41940"],
        "agent": {
            "chain": {
                "suggested_followups": ["exploits/multi/http/cpanel_cve_2026_41940_whm_auth_bypass_rce"],
            },
        },
    }

    port = OptPort(2087, "WHM SSL port", True)
    ssl = OptBool(True, "HTTPS", True)

    def run(self):
        try:
            ok, reason = self.cpanel_safe_check()
        except Exception as exc:
            return False
        if ok:
            self.set_info(
                severity="critical",
                cve="CVE-2026-41940",
                reason=reason,
            )
            return True
        return False