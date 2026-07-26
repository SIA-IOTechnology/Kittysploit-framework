#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "ninja-forms-uploads"
_VULN_HIGH = (3, 3, 26)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Ninja Forms File Uploads CVE-2026-0740 detection",
        "description": (
            "Detects Ninja Forms File Uploads <= 3.3.26 with unauthenticated arbitrary "
            "file upload via nf_fu_upload admin-ajax action (CVE-2026-0740)."
        ),
        "author": ["Sélim Lanouar (@whattheslime)", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-0740",
        "references": [
            "https://blog.lexfo.fr/ninja-forms-uploads_rce.html",
            "https://www.cve.org/CVERecord?id=CVE-2026-0740",
            "https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves/2026/CVE-2026-0740.yaml",
        ],
        "modules": [
            "exploits/multi/http/ninja_forms_uploads_cve_2026_0740_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "ninja-forms",
            "ninja-forms-uploads",
            "file-upload",
            "rce",
            "unauthenticated",
            "cve-2026-0740",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {"wordpress": 0.3},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_upload", "from_detail": ""},
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch_plugin_version(self) -> Tuple[str, str]:
        wp_base = self._wp_base()
        version = self.wp_plugin_version(_PLUGIN, wp_base)
        if version:
            return version, self.wp_plugin_path(wp_base, _PLUGIN, "readme.txt")

        response = self.http_request(method="GET", path=self._path("/"), allow_redirects=True)
        if response and response.status_code == 200:
            body = response.text or ""
            if "nfpluginsettings.js" in body:
                match = re.search(
                    r"nfpluginsettings\.js\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                    body,
                    re.IGNORECASE,
                )
                if match:
                    return match.group(1).strip(), "nfpluginsettings.js"
                return "", "nfpluginsettings.js"

        candidates = [
            self.wp_plugin_path(wp_base, _PLUGIN, "readme.txt"),
            self.wp_plugin_path(wp_base, _PLUGIN, "file-uploads.php"),
        ]
        for path in candidates:
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            for pattern in (
                r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            ):
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1).strip(), path
            if "ninja-forms-uploads" in body.lower():
                return "", path
        return "", ""

    def run(self):
        version, evidence_path = self._fetch_plugin_version()
        if not evidence_path:
            self.set_info(
                severity="info",
                reason="Ninja Forms File Uploads extension was not detected",
            )
            return False

        if version:
            in_range = self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH)
            if in_range:
                self.set_info(
                    severity="critical",
                    reason=(
                        f"Ninja Forms File Uploads {version} detected at {evidence_path}; "
                        f"<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}.{_VULN_HIGH[2]} is affected by "
                        "CVE-2026-0740 (unauthenticated arbitrary file upload)"
                    ),
                    cve="CVE-2026-0740",
                    service="wordpress",
                    endpoint="/wp-admin/admin-ajax.php",
                )
                return True
            self.set_info(
                severity="info",
                reason=(
                    f"Ninja Forms File Uploads {version} detected at {evidence_path}; "
                    "version is above the patched threshold (3.3.27+)"
                ),
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            reason=(
                f"Ninja Forms File Uploads detected at {evidence_path}, "
                "but version could not be extracted"
            ),
            cve="CVE-2026-0740",
            service="wordpress",
            endpoint="/wp-admin/admin-ajax.php",
        )
        return True
