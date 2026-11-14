#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-25856 — OpenBullet2 API bypass detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.openbullet2 import Openbullet2


class Module(Scanner, Http_client, Openbullet2):
    __info__ = {
        "name": "OpenBullet2 CVE-2026-25856 detect",
        "description": "Confirms OpenBullet2 >= 0.2.5 accepts empty X-Api-Key on /api/v1/info/update.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-25856"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-25856"],
        "tags": ["openbullet2", "scanner", "cve-2026-25856"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/openbullet2_cve_2026_25856_rce",
                    "scanner/http/openbullet2_cve_2026_39908_detect",
                ],
            },
        },
    }

    def run(self):
        r = self.http_request(method="GET", path=self._ob_join("/"), allow_redirects=True)
        body = (r.text or "") if r else ""
        if "OpenBullet2" not in body and "Openbullet2WebClient" not in body:
            return False
        ver = self.ob_version()
        if not ver:
            return False
        parts = [int(x) for x in ver.split(".")[:3] if x.isdigit()]
        while len(parts) < 3:
            parts.append(0)
        if tuple(parts) < (0, 2, 5):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-25856",
            reason=f"OpenBullet2 {ver} — unauthenticated API (empty X-Api-Key)",
            version=ver,
        )
        return True