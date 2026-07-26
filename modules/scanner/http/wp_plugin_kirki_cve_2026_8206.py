#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-8206 — Kirki forgot-password account takeover detection."""

import re
from typing import Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Kirki CVE-2026-8206 detection",
        "description": (
            "Detects Kirki (Freeform Page Builder) and flags versions 6.0.0–6.0.6 "
            "affected by CVE-2026-8206: CompLibFormHandler accepts an attacker-controlled "
            "email on POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password, "
            "redirecting password-reset links. Fixed in 6.0.7+."
        ),
        "author": ["Wordfence", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8206",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-8206",
            "https://orca.security/resources/blog/kirki-wordpress-plugin-vulnerability-cve-2026-8206/",
            "https://github.com/rootdirective-sec/CVE-2026-8206-Lab",
            "https://wordpress.org/plugins/kirki/",
        ],
        "modules": [
            "auxiliary/admin/http/wp_plugin_kirki_cve_2026_8206",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "kirki",
            "account-takeover",
            "privilege-escalation",
            "cve-2026-8206",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["wordpress", "kirki"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [
                    "/wp-json/KirkiComponentLibrary/",
                    "/wp-content/plugins/kirki/",
                ],
                "param_any": ["username", "email"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "wordpress"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/wp_plugin_kirki_cve_2026_8206",
                ],
            },
        },
    }

    _PLUGIN_SLUG = "kirki"
    _AFFECTED_MIN = (6, 0, 0)
    _AFFECTED_MAX = (6, 0, 6)

    path = OptString("/", "WordPress base path", required=False)
    probe_paths = OptString(
        "/,/login/,/account/,/forgot-password/,/wp-login.php",
        "Comma-separated paths to scan for KirkiComponentLibrary",
        required=False,
        advanced=True,
    )

    def _base(self) -> str:
        return self.wp_normalize_base_path(str(self.path or "/"))

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if root == "/":
            return suffix
        return root.rstrip("/") + suffix

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _is_affected(self, version: str) -> Optional[bool]:
        vt = self.wp_version_to_tuple(version)
        if not vt:
            return None
        if self._AFFECTED_MIN <= vt[:3] <= self._AFFECTED_MAX:
            return True
        return False

    def _route_exposed(self) -> bool:
        for path in (
            "/wp-json/KirkiComponentLibrary/v1",
            "/?rest_route=/KirkiComponentLibrary/v1",
        ):
            response = self.http_request(
                method="GET",
                path=self._join(path) if not path.startswith("/?") else path,
                allow_redirects=True,
                timeout=self._timeout(),
            )
            if not response:
                continue
            text = (response.text or "").lower()
            if response.status_code in (200, 401, 403) and (
                "kirki" in text or "forgot" in text or "namespace" in text
            ):
                return True
            if response.status_code == 200 and "KirkiComponentLibrary" in (response.text or ""):
                return True
        return False

    def run(self):
        version = self.wp_plugin_version(self._PLUGIN_SLUG, self._base())
        surface = False
        nonce_hint = False

        paths = []
        for part in str(self.probe_paths or "/").split(","):
            part = part.strip()
            if part and part not in paths:
                paths.append(part)

        for path in paths:
            response = self.http_request(
                method="GET",
                path=self._join(path),
                allow_redirects=True,
                timeout=self._timeout(),
            )
            if not response or response.status_code != 200:
                continue
            text = response.text or ""
            lower = text.lower()
            if "kirkicomponentlibrary" in lower or "kirki-forgot-password" in lower:
                surface = True
                print_info(f"Kirki Component Library markers at {path}")
            if re.search(r'"nonce"\s*:\s*"[a-f0-9]+"', text, re.I) and "kirki" in lower:
                nonce_hint = True

        if self._route_exposed():
            surface = True
            print_info("KirkiComponentLibrary REST namespace reachable")

        if not version:
            readme = self.http_request(
                method="GET",
                path=self._join(f"/wp-content/plugins/{self._PLUGIN_SLUG}/readme.txt"),
                allow_redirects=True,
                timeout=self._timeout(),
            )
            if readme and readme.status_code == 200:
                surface = True
                version = self.wp_extract_version_from_readme(readme.text or "") or version

        if not surface and not version:
            print_error("Kirki plugin not detected")
            return False

        print_success("Kirki surface detected")
        if version:
            print_info(f"Version: {version}")
            affected = self._is_affected(version)
            if affected is True:
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-8206",
                    reason=(
                        f"Kirki {version} in 6.0.0–6.0.6 range "
                        f"(nonce_hint={'yes' if nonce_hint else 'no'})"
                    ),
                )
                print_warning("Version affected by CVE-2026-8206")
                return True
            if affected is False:
                self.set_info(
                    severity="info",
                    reason=f"Kirki {version} appears outside vulnerable window / patched",
                )
                print_success("Version appears not affected (need 6.0.7+ for the fix)")
                return True

        self.set_info(
            severity="high",
            cve="CVE-2026-8206",
            reason=(
                "Kirki Component Library present; version unknown — "
                "confirm with auxiliary"
            ),
            confidence="medium",
        )
        print_warning("Kirki present; version unknown")
        return True
