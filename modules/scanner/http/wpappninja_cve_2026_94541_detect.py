#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect WPMobile.App (wpappninja) CVE-2026-94541 exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN_SLUGS = ("wpappninja", "wpmobileapp")
_VULN_MAX = (11, 82, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress WPMobile.App CVE-2026-94541 detect",
        "description": (
            "Detects WPMobile.App plugin <= 11.82 (CVE-2026-94541): unauthenticated "
            "wpapp_category subscription updates when mail-to-push mirrors wp_mail."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-94541"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-94541",
            "https://github.com/MRdark-ops/WPMobileApp-AuthBypass-exploit",
        ],
        "tags": ["wordpress", "wpappninja", "auth-bypass", "scanner", "cve-2026-94541"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wpappninja_cve_2026_94541_push_category",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    active_probe = OptBool(
        False,
        "POST test category to /?wpapppushconfig=1 (intrusive)",
        required=False,
    )

    def _readme_version(self, slug: str) -> str:
        base = self.wp_normalize_base_path(self.path)
        readme = self.wp_plugin_path(base, slug, "readme.txt")
        response = self.http_request(method="GET", path=readme, allow_redirects=True)
        if not response or int(response.status_code or 0) != 200:
            return ""
        text = response.text or ""
        if "WPMobile.App" not in text and "wpappninja" not in text.lower():
            return ""
        match = re.search(r"Stable tag:\s*([0-9.]+)", text, re.I)
        return match.group(1).strip() if match else ""

    def run(self):
        version = ""
        slug = ""
        for candidate in _PLUGIN_SLUGS:
            version = self._readme_version(candidate)
            if version:
                slug = candidate
                break
        if not version:
            home = self.http_request(method="GET", path="/", allow_redirects=True)
            if home and ("wpappninja" in (home.text or "").lower() or "wpmobile.app" in (home.text or "").lower()):
                match = re.search(r"ver=([0-9.]+)", home.text or "")
                version = match.group(1) if match else "unknown"
                slug = "wpappninja"
            else:
                return False

        if version != "unknown" and self.wp_version_to_tuple(version) > _VULN_MAX:
            return False

        if self.active_probe:
            device = f"ks_probe_{self.random_text(8)}"
            headers = {"Cookie": f"HTTP_X_WPAPPNINJA_ID={device}"}
            root = self.wp_normalize_base_path(self.path)
            cfg = "/?wpapppushconfig=1" if root == "/" else f"{root.rstrip('/')}/?wpapppushconfig=1"
            response = self.http_request(
                method="POST",
                path=cfg,
                data={"enablewpapppush": "1", "wpapp_category[]": "audit_test_category"},
                headers=headers,
                allow_redirects=True,
            )
            if not response or int(response.status_code or 0) != 200:
                return False

        self.set_info(
            severity="critical",
            reason="WPMobile.App plugin in affected version range",
            version=version,
            plugin=slug or "wpappninja",
        )
        return True
