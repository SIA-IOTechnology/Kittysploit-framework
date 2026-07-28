#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress User Registration Membership CVE-2026-1492 detection",
        "description": (
            "Detects the User Registration & Membership plugin and flags versions "
            "<= 5.1.2 as affected by CVE-2026-1492 (unauthenticated administrator "
            "creation via membership register_member role injection)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-1492",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1492",
            "https://www.cve.org/CVERecord?id=CVE-2026-1492",
            "https://github.com/Nxploited/CVE-2026-1492",
            "https://wordpress.org/plugins/user-registration/",
        ],
        "modules": [
            "auxiliary/admin/http/wp_plugin_user_registration_membership_cve_2026_1492",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "user-registration",
            "membership",
            "privilege-escalation",
            "cve-2026-1492",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["wordpress"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/wp-content/plugins/user-registration/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "wordpress"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/wp_plugin_user_registration_membership_cve_2026_1492",
                ],
            },
        },
    }

    _PLUGIN_SLUG = "user-registration"
    _MAX_AFFECTED = (5, 1, 2)

    path = OptString("/", "WordPress base path", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(str(self.path or "/"))

    def run(self):
        version = self.wp_plugin_version(self._PLUGIN_SLUG, self._base())
        if not version:
            # Fallback: probe common registration pages for plugin markers
            for slug in ("/membership-pricing/", "/registration/", "/registration-form/"):
                root = self._base()
                path = slug if root == "/" else root.rstrip("/") + slug
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=max(int(self.timeout or 10), 10),
                )
                if not response or response.status_code != 200:
                    continue
                text = response.text or ""
                if "user-registration" in text or "ur_frontend_form_nonce" in text:
                    self.set_info(
                        severity="high",
                        cve="CVE-2026-1492",
                        reason=(
                            f"User Registration membership forms at {path}; "
                            "readme version unavailable (active exploit required)"
                        ),
                    )
                    return True
            print_error("User Registration plugin not detected")
            return False

        if self.wp_version_to_tuple(version) <= self._MAX_AFFECTED:
            self.set_info(
                severity="critical",
                cve="CVE-2026-1492",
                reason=f"User Registration {version} is within CVE-2026-1492 affected range (<= 5.1.2)",
            )
            print_success(f"Vulnerable version detected: {version}")
            return True

        self.set_info(
            severity="info",
            reason=f"User Registration {version} appears patched for CVE-2026-1492",
        )
        print_info(f"Patched / not affected: {version}")
        return False
