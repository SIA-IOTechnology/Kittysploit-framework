#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-39908 — OpenBullet2 Windows NTLM coercion surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.openbullet2 import Openbullet2


class Module(Scanner, Http_client, Openbullet2):
    __info__ = {
        "name": "OpenBullet2 CVE-2026-39908 detect",
        "description": (
            "Flags vulnerable OpenBullet2 on Windows where proxy file sources "
            "accept UNC paths (NTLM relay / hash capture)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-39908"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-39908"],
        "tags": ["openbullet2", "windows", "ntlm", "cve-2026-39908"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/openbullet2_cve_2026_39908_unc_coerce",
                    "exploits/multi/http/openbullet2_cve_2026_25856_rce",
                ],
            },
        },
    }

    def run(self):
        ver = self.ob_version()
        if not ver:
            return False
        os_name = self.ob_server_os()
        if "windows" not in (os_name or "").lower():
            return False
        parts = [int(x) for x in ver.split(".")[:3] if x.isdigit()]
        while len(parts) < 3:
            parts.append(0)
        if tuple(parts) < (0, 2, 5):
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-39908",
            reason=f"OpenBullet2 {ver} on {os_name} — UNC proxy coercion risk",
            version=ver,
        )
        return True