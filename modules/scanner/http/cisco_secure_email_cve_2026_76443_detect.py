#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Secure Email Gateway CVE-2026-76443 S/MIME SQLi surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cisco ESA CVE-2026-76443 detect",
        "description": "Detects Cisco Secure Email Gateway for S/MIME SQLi RCE advisories.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-76443"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-76443"],
        "tags": ["cisco", "esa", "asyncos", "sqli", "cve-2026-76443"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/unix/smtp/cisco_secure_email_cve_2026_76443_smime_sqli_rce",
                    "exploits/multi/tcp/cisco_secure_email_cve_2026_76443_smime_rce",
                    "exploits/multi/http/cisco_secure_email_cve_2026_76461_rce",
                ],
            },
        },
    }

    _VERSION_RE = re.compile(r"AsyncOS\s+(\d+\.\d+\.\d+[-\w.]*)", re.I)

    def run(self):
        r = self.http_request(method="GET", path="/login", allow_redirects=True)
        if not r or int(r.status_code) != 200:
            return False
        body = r.text or ""
        if "Email Security" not in body and "IronPort" not in body:
            return False
        ver = self._VERSION_RE.search(body)
        self.set_info(
            severity="critical",
            cve="CVE-2026-76443",
            reason="Cisco ESA — S/MIME parsing SQLi (SMTP vector)",
            version=ver.group(1) if ver else "unknown",
        )
        return True