#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-73571 — SaveDraft delegated send impersonation."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zimbra CVE-2026-73571 detect",
        "description": "Flags ZCS before 10.1.17 (delegated SaveDraft send-as bypass).",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-73571"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-73571"],
        "tags": ["zimbra", "mail", "impersonation", "cve-2026-73571"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/zimbra_cve_2026_73571_impersonation",
                ],
            },
        },
    }

    _VERSION_RE = re.compile(r"Zimbra\s+(\d+\.\d+\.\d+)", re.I)

    def _vulnerable(self, version: str) -> bool:
        parts = [int(x) for x in version.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return parts[0] == 10 and parts[1] == 1 and parts[2] < 17

    def run(self):
        r = self.http_request(
            method="GET",
            path="/js/zimbraMail/share/model/ZmSettings.js",
            allow_redirects=False,
        )
        if not r or int(r.status_code) != 200:
            return False
        ver = self._VERSION_RE.search(r.text or "")
        if not ver:
            return False
        version = ver.group(1)
        if not self._vulnerable(version):
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-73571",
            reason=f"ZCS {version} — SaveDraft delegation impersonation",
            version=version,
        )
        return True