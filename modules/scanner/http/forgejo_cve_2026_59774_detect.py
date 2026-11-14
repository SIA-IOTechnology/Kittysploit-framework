#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-59774 — Forgejo/Gitea Org-mode markup include."""

from kittysploit import *
from lib.protocols.http.gitea_probe import Gitea
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Gitea):
    __info__ = {
        "name": "Forgejo CVE-2026-59774 detect",
        "description": "Flags Forgejo/Gitea versions before 15.0.6 / 16.0.2 (markup #+INCLUDE).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-59774"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-59774",
            "https://github.com/go-gitea/gitea/security/advisories/GHSA-6v53-hr58-556r",
        ],
        "tags": ["forgejo", "gitea", "lfi", "cve-2026-59774"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/gitea_cve_2026_59774_unauth_file_read",
                    "exploits/linux/http/gitea_cve_2026_59774_unauth_markup_rce",
                    "auxiliary/admin/http/forgejo_cve_2026_59774_file_read",
                    "exploits/linux/http/gitea_cve_2026_60004_diffpatch_rce",
                ],
            },
        },
    }

    def run(self):
        raw, ver = self.gitea_fetch_version()
        if not ver:
            probe = self.probe_gitea()
            if not probe.get("found"):
                return False
            ver = str(probe.get("version") or "")
            raw = str(probe.get("version_raw") or ver)
        probe = self.probe_gitea()
        forge = str(probe.get("forge") or "")
        vuln = self.markup_vulnerable_59774(ver, forge)
        if vuln is not True:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-59774",
            version=raw or ver,
            reason="Org-mode #+INCLUDE file read via markup API",
        )
        return True