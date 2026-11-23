#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-115560 — PHP session upload progress mismatch."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.php_session_upload import Php_session_upload


class Module(Scanner, Http_client, Php_session_upload):
    __info__ = {
        "name": "PHP session upload CVE-2026-115560 detect",
        "description": "Heuristics for session.upload_progress + PHPSESSID use.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-115560"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-115560"],
        "tags": ["php", "deserialization", "cve-2026-115560"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/php_session_upload_cve_2026_115560_preconditions",
                ],
            },
        },
    }

    probe_path = OptString("/", "URL that starts sessions", required=False)

    def run(self):
        path = str(self.probe_path or "/")
        pre = self.php_session_preconditions(path)
        if not pre.get("reachable"):
            return False
        likely = bool(pre.get("handler_mismatch_likely") or pre.get("phpinfo_found"))
        self.set_info(
            severity="critical",
            cve="CVE-2026-115560",
            reason="PHP session upload preconditions",
            **pre,
        )
        return likely or bool(pre.get("reachable"))