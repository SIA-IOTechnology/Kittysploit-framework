#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe ColdFusion 8 CVE-2009-2265 FCKeditor upload surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Adobe ColdFusion CVE-2009-2265 FCKeditor Detect",
        "description": "Detects CFIDE FCKeditor upload.cfm connector (null-byte upload class).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2009-2265"],
        "tags": ["web", "scanner", "coldfusion", "fckeditor", "cve-2009-2265"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2009-2265"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/coldfusion_cve_2009_2265_rce"],
            },
        },
    }

    port = OptPort(8500, "ColdFusion HTTP port", required=False)

    def run(self):
        paths = [
            "/CFIDE/administrator/",
            "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm",
        ]
        hit = False
        for path in paths:
            r = self.http_request("GET", path, allow_redirects=True)
            if not r:
                continue
            blob = f"{r.status_code} {(r.text or '')[:300]}".lower()
            if "coldfusion" in blob or "cfide" in blob or "fckeditor" in blob:
                hit = True
        if not hit:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2009-2265",
            reason="ColdFusion CFIDE / FCKeditor upload surface",
            confidence="medium",
        )
        return True
