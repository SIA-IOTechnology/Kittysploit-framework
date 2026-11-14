#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-10631 — Zimbra EWS cross-mailbox FindItem surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zimbra CVE-2026-10631 EWS detect",
        "description": "Detects exposed Zimbra EWS endpoints (FindItem IDOR before 10.1.20).",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "cve": ["CVE-2026-10631"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-10631"],
        "tags": ["zimbra", "ews", "idor", "cve-2026-10631"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/zimbra_cve_2026_10631_ews_read",
                ],
            },
        },
    }

    def run(self):
        for path in ("/EWS/Exchange.asmx", "/service/extension/zimbraews"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            if int(r.status_code) in (200, 401, 403, 405):
                body = (r.text or "").lower()
                if "exchange" in body or "ews" in body or "soap" in body:
                    self.set_info(
                        severity="medium",
                        cve="CVE-2026-10631",
                        reason="Zimbra EWS endpoint exposed",
                        path=path,
                    )
                    return True
        return False