#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-119258 — Swipe WordPress plugin auth bypass."""

from __future__ import annotations

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Swipe WordPress CVE-2026-119258 detect",
        "description": "Swipe <= 1.4 — wp_ajax_nopriv_swipe_check_app without nonce check.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-119258"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-119258"],
        "tags": ["wordpress", "swipe", "auth-bypass", "cve-2026-119258"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/swipe_cve_2026_119258_auth_bypass",
                ],
            },
        },
    }

    def _fingerprint(self) -> dict:
        found = {"installed": False, "version": "", "nonce_checked": None}
        r = self.http_request("GET", "/wp-content/plugins/swipe/readme.txt")
        if r and int(r.status_code or 0) == 200 and "=== Swipe ===" in (r.text or ""):
            found["installed"] = True
            match = re.search(r"Stable tag:\s*([\w.\-]+)", r.text or "")
            if match:
                found["version"] = match.group(1)
        r2 = self.http_request("GET", "/wp-content/plugins/swipe/controller.php")
        if r2 and int(r2.status_code or 0) == 200 and "swipe_check_app_callback" in (r2.text or ""):
            found["installed"] = True
            found["nonce_checked"] = not bool(re.search(r"//\s*wp_verify_nonce\s*\(", r2.text or ""))
        return found

    def run(self):
        fp = self._fingerprint()
        if not fp["installed"]:
            return False
        if fp["nonce_checked"] is False:
            reason = f"Swipe {fp['version'] or '?'} nonce check disabled"
        else:
            reason = f"Swipe {fp['version'] or '?'} installed"
        self.set_info(
            severity="critical",
            cve="CVE-2026-119258",
            reason=reason,
            version=fp["version"] or "unknown",
        )
        return True