#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenCATS installer PHP injection (CVE-2026-27760)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OpenCATS CVE-2026-27760 installer detect",
        "description": "Unfinished OpenCATS install exposes ajax.php databaseConnectivity injection.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-27760"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-27760"],
        "tags": ["opencats", "installer", "cve-2026-27760"],
        "agent": {
            "chain": {
                "suggested_followups": ["exploits/multi/http/opencats_cve_2026_27760_installer_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request(
            method="GET",
            path=(self.path or "/").rstrip("/") + "/ajax.php",
            params={"f": "install:ui", "a": "databaseConnectivity"},
        )
        body = (r.text or "") if r else ""
        if "installLocked" in body:
            return False
        if "setActiveStep" in body:
            self.set_info(severity="critical", cve="CVE-2026-27760", reason="Open install wizard")
            return True
        return False