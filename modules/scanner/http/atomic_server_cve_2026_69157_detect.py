#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-69157 — atomic-server unauthenticated /setup invite."""

from kittysploit import *
from lib.protocols.http.atomic_server import Atomic_server
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Atomic_server):
    __info__ = {
        "name": "atomic-server CVE-2026-69157 detect",
        "description": "Unauthenticated /setup exposes admin invite (fixed 0.39.0).",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-69157"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-69157"],
        "tags": ["atomic-server", "unauth", "cve-2026-69157"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/atomic_server_cve_2026_69157_setup_takeover",
                ],
            },
        },
    }

    port = OptPort(9883, "atomic-server port", required=False)
    _PATCHED = "0.39.0"

    def run(self):
        fp = self.as_fingerprint()
        if not fp.get("reachable"):
            return False
        ver = str(fp.get("version") or "")
        if ver and not self.version_less_than(ver, self._PATCHED):
            return False
        invite = self.as_setup_invite()
        if not invite:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-69157",
            reason="Unauthenticated /setup invite disclosed",
            invite=invite[:120],
            version=ver or "unknown",
        )
        return True