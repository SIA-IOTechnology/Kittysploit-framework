#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-47884 — Spring XsltView path limitation."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.spring_xslt import Spring_xslt


class Module(Scanner, Http_client, Spring_xslt):
    __info__ = {
        "name": "Spring XsltView CVE-2026-47884 detect",
        "description": "Probes catch-all mapping for XsltView transformer errors.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-47884"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-47884"],
        "tags": ["spring", "xslt", "ssrf", "cve-2026-47884"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/spring_xslt_cve_2026_47884_probe",
                ],
            },
        },
    }

    xslt_endpoint = OptString("/xslt/", "XsltView URL prefix", required=False)

    def run(self):
        ep = str(self.xslt_endpoint or "/xslt/")
        hit, code, _ = self.xslt_probe(ep)
        if not hit:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-47884",
            reason="XsltView indicators",
            probe_http=code,
        )
        return True