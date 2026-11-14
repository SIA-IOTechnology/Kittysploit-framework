#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123270 — Redpanda Connect streams API exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Redpanda Connect CVE-2026-123270 detect",
        "description": "Checks /version and unauthenticated GET /streams on port 4195.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-123270"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-123270"],
        "tags": ["redpanda", "scanner", "cve-2026-123270"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/redpanda_connect_cve_2026_123270_rce",
                ],
            },
        },
    }

    port = OptPort(4195, "Streams management port", required=False)
    _VERSION_RE = re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"', re.I)

    def run(self):
        ver = self.http_request(method="GET", path="/version")
        body = (ver.text or "") if ver else ""
        m = self._VERSION_RE.search(body)
        version = m.group(1) if m else ""
        if version:
            parts = [int(x) for x in version.split(".")]
            while len(parts) < 3:
                parts.append(0)
            if parts >= [4, 111, 0] or parts < [4, 39, 0]:
                return False
        streams = self.http_request(method="GET", path="/streams")
        if not streams or int(streams.status_code or 0) != 200:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-123270",
            reason=f"Unauthenticated streams API (version {version or 'unknown'})",
            version=version or "unknown",
        )
        return True