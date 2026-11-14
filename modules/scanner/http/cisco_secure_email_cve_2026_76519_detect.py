#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Secure Email Gateway CVE-2026-76519 AMP file write surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cisco ESA CVE-2026-76519 detect",
        "description": "Detects AsyncOS Cisco Secure Email Gateway for AMP arbitrary file write advisories.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-76519"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-76519"],
        "tags": ["cisco", "esa", "asyncos", "cve-2026-76519"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/tcp/cisco_secure_email_cve_2026_76519_amp_rce",
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
        if not any(x in body for x in ("Email Security Appliance", "AsyncOS", "IronPort")):
            return False
        ver = self._VERSION_RE.search(body)
        self.set_info(
            severity="critical",
            cve="CVE-2026-76519",
            reason="Cisco ESA management UI — verify AMP file-write patch level",
            version=ver.group(1) if ver else "unknown",
        )
        return True