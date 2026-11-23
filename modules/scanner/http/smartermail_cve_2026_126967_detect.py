#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-126967 — SmarterMail File Storage traversal (build < 9735)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.smartermail import Smartermail


class Module(Scanner, Http_client, Smartermail):
    __info__ = {
        "name": "SmarterMail CVE-2026-126967 detect",
        "description": "Fingerprints SmarterMail build; traversal RCE needs auth.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-126967"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-126967"],
        "tags": ["smartermail", "traversal", "cve-2026-126967"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/smartermail_cve_2026_126967_filestorage_rce",
                ],
            },
        },
    }

    port = OptPort(443, "SmarterMail HTTPS port", required=False)
    _PATCH_BUILD = 9735

    def run(self):
        code, build = self.sm_fingerprint()
        resp = self.http_request("GET", "/interface/root")
        if (code == 0 and not resp) or (resp and "SmarterMail" not in (resp.text or "")):
            return False
        build_n = int(build) if str(build).isdigit() else 0
        if build_n >= self._PATCH_BUILD:
            return False
        reason = f"SmarterMail build {build or 'unknown'} (< {self._PATCH_BUILD})"
        self.set_info(
            severity="critical",
            cve="CVE-2026-126967",
            reason=reason,
            build=build or "unknown",
        )
        return True