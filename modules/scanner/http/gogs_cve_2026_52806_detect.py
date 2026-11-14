#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gogs git rebase --exec argument injection (CVE-2026-52806)."""

from kittysploit import *
from lib.protocols.http.gogs_client import Gogs
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Gogs):
    __info__ = {
        "name": "Gogs CVE-2026-52806 rebase RCE detect",
        "description": "Fingerprints Gogs < 0.14.3 via gogs.min.css commit hash (rebase merge RCE).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-52806"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-52806"],
        "tags": ["gogs", "git", "rebase", "cve-2026-52806"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/gogs_cve_2026_52806_rebase_rce",
                    "exploits/linux/http/gogs_cve_2025_8110_rce",
                ],
            },
        },
    }

    def run(self):
        response = self.http_request(method="GET", path="/", allow_redirects=True)
        body = (response.text or "") if response else ""
        vulnerable, version, commit = self.rebase_merge_vulnerable(body)
        if not vulnerable and not version and not commit:
            return False
        if vulnerable:
            self.set_info(
                severity="critical",
                cve="CVE-2026-52806",
                reason=f"Gogs {version or commit} < 0.14.3",
                version=version,
            )
            return True
        if version:
            self.set_info(severity="info", reason=f"Gogs {version} patched", version=version)
        return bool(version)