#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Core 6.9-7.0.1 batch route confusion (CVE-2026-63030)."""

from __future__ import annotations

import json
import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

CVE_ID = "CVE-2026-63030"
_BATCH_BODY = {
    "requests": [
        {"method": "POST", "path": "///"},
        {"method": "POST", "path": "/wp/v2/posts"},
        {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
        {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
    ]
}


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Core CVE-2026-63030 batch route confusion detect",
        "description": (
            "Safe Nuclei-style detection for wp2shell batch confusion (6.9.0-6.9.4, 7.0.0-7.0.1)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": [CVE_ID],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-63030",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-63030.yaml",
        ],
        "modules": ["exploits/multi/http/wp2shell_cve_2026_63030"],
        "tags": ["web", "scanner", "wordpress", "wp-core", "batch-api", "cve-2026-63030"],
        "agent": {
            "chain": {"suggested_followups": ["exploits/multi/http/wp2shell_cve_2026_63030"]},
        },
    }

    active_probe = OptBool(
        False,
        "POST safe batch confusion probe (no SQLi)",
        required=False,
    )

    def _discover_version(self) -> Optional[Tuple[int, int, int]]:
        for path in ("/wp-json/", "/feed/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            text = (response.text or "") if response else ""
            for pattern in (
                r'"generator":"[^"]*?(\d+\.\d+(?:\.\d+)?)"',
                r"WordPress\s+(\d+\.\d+(?:\.\d+)?)",
            ):
                match = re.search(pattern, text, re.I)
                if match:
                    parts = [int(x) for x in match.group(1).split(".")[:3]]
                    while len(parts) < 3:
                        parts.append(0)
                    return tuple(parts[:3])
        return None

    @staticmethod
    def _affected(version: Tuple[int, int, int]) -> bool:
        vuln = frozenset((6, 9, n) for n in range(5)) | frozenset(((7, 0, 0), (7, 0, 1)))
        if version in vuln:
            return True
        return False

    def _batch_probe(self, use_query_route: bool) -> bool:
        path = "/?rest_route=/batch/v1" if use_query_route else "/wp-json/batch/v1"
        resp = self.http_request(
            method="POST",
            path=path,
            data=json.dumps(_BATCH_BODY),
            headers={"Content-Type": "application/json"},
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 207:
            return False
        body = resp.text or ""
        ctype = str((resp.headers or {}).get("Content-Type") or "")
        markers = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
        return "application/json" in ctype and all(m in body for m in markers)

    def run(self):
        version_t = self._discover_version()
        version_s = ".".join(map(str, version_t)) if version_t else ""
        if version_t and not self._affected(version_t):
            return False
        if not self.active_probe:
            if version_t and self._affected(version_t):
                self.set_info(
                    severity="high",
                    cve=CVE_ID,
                    reason=f"WordPress {version_s} in affected range; batch probe not run",
                    version=version_s,
                )
                return True
            return False
        ok = self._batch_probe(False) or self._batch_probe(True)
        if not ok:
            return False
        if version_t and not self._affected(version_t):
            self.set_info(
                severity="medium",
                cve=CVE_ID,
                reason="Batch confusion markers matched but Core version outside known ranges",
                confidence="low",
            )
            return True
        self.set_info(
            severity="critical",
            cve=CVE_ID,
            reason="Pre-auth REST batch route confusion confirmed (Nuclei oracle)",
            version=version_s or "unknown",
            confidence="high",
        )
        return True
