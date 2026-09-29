#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SharePoint CVE-2026-65660 ToolPane Register directive injection surface."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_SP_HEADER = "microsoftsharepointteamservices"
_BUILD_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SharePoint CVE-2026-65660 ToolPane Detect",
        "description": (
            "Detects on-prem SharePoint farms exposed to CVE-2026-65660: ToolPane "
            "Register directive quote injection on AddGallery/ToolPane endpoints. "
            "Fingerprints MicrosoftSharePointTeamServices build and reachable "
            "_layouts/15/* gallery edit surfaces without sending exploit markup."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-65660"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-65660",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65660",
        ],
        "tags": [
            "web",
            "scanner",
            "sharepoint",
            "microsoft",
            "toolpane",
            "code-injection",
            "rce",
            "cve-2026-65660",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.25,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["sharepoint", "microsoft"],
                "endpoint_pattern_any": ["/_layouts/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "ToolPane MSOTlPn_DWP"},
                ],
                "suggested_followups": [
                    "exploits/windows/http/sharepoint_cve_2026_26114_rce",
                    "scanner/http/sharepoint_detect",
                ],
            },
        },
    }

    gallery_paths = OptString(
        "/_layouts/15/AddGallery.aspx,/_layouts/15/designgallery.aspx,/_layouts/15/ToolPane.aspx",
        "Comma-separated SharePoint gallery/ToolPane paths",
        False,
        advanced=True,
    )

    @staticmethod
    def _parse_build(headers: dict, body: str) -> str:
        for key, value in (headers or {}).items():
            if key.lower() == _SP_HEADER:
                match = _BUILD_RE.search(str(value))
                if match:
                    return match.group(1)
        match = _BUILD_RE.search(body or "")
        return match.group(1) if match else ""

    @staticmethod
    def _build_affected(build: str) -> Optional[bool]:
        if not build:
            return None
        parts = build.split(".")
        if len(parts) < 4:
            return None
        try:
            major, minor, patch, rev = (int(x) for x in parts[:4])
        except ValueError:
            return None
        if major != 16:
            return None
        # Pre-August 2026 Subscription Edition builds such as 16.0.0.19725 are affected.
        if minor == 0 and patch == 0 and rev < 19800:
            return True
        return None

    def _sharepoint_markers(self, response) -> bool:
        if not response:
            return False
        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        if _SP_HEADER in headers:
            return True
        body = (response.text or "")[:20000].lower()
        return any(token in body for token in ("sharepoint", "_layouts/15", "sp.js", "msotlpn_"))

    def _probe_gallery(self, path: str) -> Tuple[bool, str]:
        query = f"{path}?DisplayMode=Edit"
        if "?" in path:
            query = f"{path}&DisplayMode=Edit"
        response = self.http_request(method="GET", path=query, allow_redirects=False)
        if not response:
            return False, ""
        code = int(response.status_code or 0)
        body = response.text or ""
        if code not in (200, 302):
            return False, body
        markers = ("MSOTlPn", "ToolPane", "AddGallery", "Web Part Gallery", "DisplayMode")
        return any(marker.lower() in body.lower() for marker in markers), body

    def run(self):
        root = self.http_request(method="GET", path="/", allow_redirects=True)
        layouts = self.http_request(method="GET", path="/_layouts/15/start.aspx", allow_redirects=True)
        candidate = layouts or root
        if not self._sharepoint_markers(candidate):
            return False

        build = self._parse_build(getattr(candidate, "headers", {}) or {}, candidate.text or "")
        affected = self._build_affected(build)
        exposed = False
        hit_path = ""
        for raw in str(self.gallery_paths or "").split(","):
            path = raw.strip().replace(" ", "")
            if not path:
                continue
            ok, _ = self._probe_gallery(path)
            if ok:
                exposed = True
                hit_path = path
                break

        if affected is False and not exposed:
            return False
        if exposed or affected is True:
            self.set_info(
                severity="critical",
                cve="CVE-2026-65660",
                reason=(
                    "SharePoint ToolPane/AddGallery edit surface reachable"
                    if exposed
                    else "SharePoint build appears pre-August 2026 fix"
                ),
                build=build or "unknown",
                path=hit_path or "/_layouts/15/",
            )
            return True
        if exposed:
            self.set_info(
                severity="high",
                cve="CVE-2026-65660",
                reason="SharePoint gallery edit endpoint exposed (build unknown)",
                build=build or "unknown",
                path=hit_path,
            )
            return True
        return False
