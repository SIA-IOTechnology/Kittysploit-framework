#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect HTTP wrappers around vulnerable image-downloader (< 4.3.1)."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_DOWNLOAD_HINTS = (
    "missing 'url' query parameter",
    "image-downloader",
    "cve-2026-103648",
    "download endpoint: get /download",
)
_PROBE_PATHS = ("/download", "/api/download", "/image/download", "/fetch-image")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "image-downloader CVE-2026-103648 wrapper detect",
        "description": (
            "Detects Node.js apps exposing a user-controlled image URL fetch endpoint "
            "pattern associated with CVE-2026-103648 (image-downloader < 4.3.1 path traversal)."
        ),
        "author": ["Amirhossein Roustaei", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-103648"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-103648",
            "https://github.com/EterNullSec/CVE-2026-103648",
        ],
        "tags": ["scanner", "nodejs", "path-traversal", "cve-2026-103648"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/image_downloader_cve_2026_103648_path_traversal",
                ],
            },
        },
    }

    port = OptPort(3000, "Application HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)
    download_path = OptString(
        "",
        "Override download endpoint path (auto-probe if empty)",
        required=False,
    )

    def _body_matches(self, body: str, status: int) -> bool:
        low = (body or "").lower()
        if any(h in low for h in _DOWNLOAD_HINTS):
            return True
        if status == 400 and "url" in low and "parameter" in low:
            return True
        try:
            data = json.loads(body or "{}")
        except json.JSONDecodeError:
            return False
        err = str(data.get("error") or "").lower()
        return "url" in err and "parameter" in err

    def run(self):
        paths = [str(self.download_path or "").strip()] if str(self.download_path or "").strip() else []
        paths.extend(list(_PROBE_PATHS))

        seen = set()
        for path in paths:
            if not path or path in seen:
                continue
            seen.add(path)

            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            status = int(response.status_code or 0)
            body = response.text or ""
            if status not in (200, 400, 422) and not self._body_matches(body, status):
                continue
            if not self._body_matches(body, status):
                if status == 404:
                    continue
                if status == 200 and "download" not in body.lower():
                    continue

            self.set_info(
                severity="critical",
                reason="User-supplied image URL download endpoint detected",
                path=path,
                status=status,
            )
            return True

        health = self.http_request(method="GET", path="/health", allow_redirects=False)
        if health and int(health.status_code or 0) == 200:
            body = health.text or ""
            if self._body_matches(body, 200):
                self.set_info(
                    severity="critical",
                    reason="image-downloader lab/health banner",
                    path="/health",
                )
                return True
        return False
