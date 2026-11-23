#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-115560 — Session upload progress precondition report."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.php_session_upload import Php_session_upload


class Module(Auxiliary, Http_client, Php_session_upload):
    __info__ = {
        "name": "PHP session upload CVE-2026-115560 assess",
        "description": (
            "Reports phpinfo/session.upload_progress and PHPSESSID; "
            "full race exploit not included (use LLCForge PoC)."
        ),
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-115560"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-115560"],
        "tags": ["php", "deserialization", "cve-2026-115560", "auxiliary"],
        "agent": {
            "approval_required": False,
            "chain": {
                "suggested_followups": [
                    "scanner/http/php_session_upload_cve_2026_115560_detect",
                ],
            },
        },
    }

    probe_path = OptString("/", "Endpoint URL", required=False)

    def run(self):
        path = str(self.probe_path or "/")
        pre = self.php_session_preconditions(path)
        print_status(f"Preconditions: {pre}")
        if not pre.get("reachable"):
            print_error("Target not reachable")
            return False
        print_status(
            "Race-based RCE requires multipart upload + consumer threads "
            "(see LLCForge CVE-2026-115560 poc.py)."
        )
        self.set_info(severity="critical", cve="CVE-2026-115560", **pre)
        return True