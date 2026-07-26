#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Splunk Enterprise versions affected by CVE-2022-43571 (dashboard PDF RCE)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.splunk import Splunk


class Module(Scanner, Http_client, Splunk):

    __info__ = {
        "name": "Splunk CVE-2022-43571 (SimpleXML PDF RCE) detection",
        "description": (
            "Detects Splunk Enterprise instances in the CVE-2022-43571 affected version "
            "ranges (< 8.1.12, 8.2.0–8.2.8, 9.0.0–9.0.1). Reads the version from the "
            "login page by default; optional credentials refine the check via the "
            "authenticated home page. Does not exploit."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2022-43571",
        "references": [
            "https://advisory.splunk.com/advisories/SVD-2022-1111",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-43571",
        ],
        "modules": [
            "exploits/multi/http/splunk_auth_rce_cve_2022_43571",
            "scanner/http/splunk_detect",
        ],
        "tags": [
            "web",
            "scanner",
            "splunk",
            "siem",
            "rce",
            "authenticated",
            "cve-2022-43571",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["splunk"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [
                    "/en-US/account/login",
                    "/services/server/info",
                ],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "devops_panel", "from_detail": ""},
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/splunk_auth_rce_cve_2022_43571",
                ],
            },
        },
    }

    port = OptPort(8000, "Splunk web port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=False)
    path = OptString("/", "Base path to Splunk web", required=False)
    username = OptString(
        "",
        "Optional username for a more accurate authenticated version check",
        required=False,
    )
    password = OptString("", "Optional password", required=False)

    def _is_vulnerable_version(self, version: str) -> bool:
        return (
            self.splunk_version_between(version, "8.1.0", "8.1.11")
            or self.splunk_version_between(version, "8.2.0", "8.2.8")
            or self.splunk_version_between(version, "9.0.0", "9.0.1")
        )

    def run(self):
        version = None
        source = "login page"

        user = str(self.username or "").strip()
        passwd = str(self.password or "")
        if user and passwd:
            print_status(f"Authenticating as {user!r} for version check")
            if self.splunk_login(user, passwd):
                version = self.splunk_home_version()
                if not version:
                    version = self.splunk_version_authenticated(user)
                source = "authenticated session"
            else:
                print_warning("Login failed — falling back to unauthenticated version")

        if not version:
            version = self.splunk_login_version()
            source = "login page"

        if not version:
            print_error("Splunk version not found (is this Splunk?)")
            return False

        print_status(f"Splunk {version} ({source})")

        if self._is_vulnerable_version(version):
            self.set_info(
                severity="critical",
                cve="CVE-2022-43571",
                reason=(
                    f"Splunk {version} is in the CVE-2022-43571 affected range "
                    "(authenticated SimpleXML dashboard PDF RCE)"
                ),
                version=version,
            )
            return True

        print_info(f"Splunk {version} is outside the known vulnerable ranges")
        return False
