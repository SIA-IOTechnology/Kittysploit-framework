#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133113 — Gogs protected branch bypass."""

from kittysploit import *
from lib.protocols.http.gogs_client import Gogs
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Gogs):
    __info__ = {
        "name": "Gogs CVE-2026-133113 detect",
        "description": "Fingerprints Gogs <= 0.14.4 vulnerable to PR merge branch bypass.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-133113"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133113"],
        "tags": ["gogs", "git", "cve-2026-133113"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/gogs_cve_2026_133113_branch_bypass",
                ],
            },
        },
    }

    port = OptPort(3000, "Gogs HTTP port", required=False)

    def run(self):
        resp = self.http_request("GET", "/", timeout=12)
        if not resp:
            return False
        vuln, version, commit = self.rebase_merge_vulnerable(resp.text or "")
        if not self.is_gogs_page(resp.text or ""):
            return False
        if vuln:
            reason = f"Gogs {version or commit} — merge API branch bypass likely"
        else:
            reason = f"Gogs {version or commit} at or above 0.14.3 patched hash"
        self.set_info(
            severity="high",
            cve="CVE-2026-133113",
            reason=reason,
            version=version or "unknown",
            commit=commit,
            potentially_vulnerable=vuln,
        )
        return vuln or bool(version) or bool(commit)