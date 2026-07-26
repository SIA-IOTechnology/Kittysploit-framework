#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-5118 — Divi Form Builder unauthenticated privilege escalation detection."""

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Divi Form Builder CVE-2026-5118 detection",
        "description": (
            "Detects Divi Engine Divi Form Builder and flags versions <= 5.1.2 "
            "affected by CVE-2026-5118 (unauthenticated admin creation via "
            "de_fb_ajax_submit_ajax_handler role=administrator). Looks for "
            "fb_nonce / de_fb_obj markers and plugin assets. Fixed in 5.1.3+."
        ),
        "author": ["0xd4rk5id3", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-5118",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5118",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/divi-form-builder/divi-form-builder-512-unauthenticated-privilege-escalation-via-role",
            "https://diviengine.com/divi-form-builder-changelog/",
            "https://nefariousplan.com/posts/divi-form-builder-cve-2026-5118-administrator-existed",
        ],
        "modules": [
            "auxiliary/admin/http/wp_plugin_divi_form_builder_cve_2026_5118",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "divi",
            "divi-form-builder",
            "privilege-escalation",
            "cve-2026-5118",
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
                "tech_hints_any": ["wordpress", "divi"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [
                    "/wp-admin/admin-ajax.php",
                    "/wp-content/plugins/divi-form-builder/",
                ],
                "param_any": ["fb_nonce", "role"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "wordpress"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/wp_plugin_divi_form_builder_cve_2026_5118",
                ],
            },
        },
    }

    _PLUGIN_SLUG = "divi-form-builder"
    _MAX_AFFECTED = (5, 1, 2)
    _NONCE_RES = (
        re.compile(r'fb_nonce["\']?\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'name=["\']fb_nonce["\'][^>]*value=["\']([^"\']+)', re.I),
        re.compile(r'"fb_nonce"\s*:\s*"([a-f0-9]+)"', re.I),
    )

    path = OptString("/", "WordPress base path", required=False)
    probe_paths = OptString(
        "/",
        "Comma-separated paths to scan for fb_nonce (in addition to /)",
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

    def _find_nonce(self, html: str) -> Optional[str]:
        for pattern in self._NONCE_RES:
            match = pattern.search(html or "")
            if match:
                return match.group(1)
        return None

    def _looks_like_dfb(self, html: str) -> bool:
        text = (html or "").lower()
        markers = (
            "fb_nonce",
            "de_fb_obj",
            "de_fb_ajax",
            "divi-form-builder",
            "divi_form_builder",
            "de-fb-",
        )
        return any(m in text for m in markers)

    def run(self):
        version = self.wp_plugin_version(self._PLUGIN_SLUG, self._base())
        nonce_found = False
        dfb_surface = False

        paths = ["/"]
        extra = str(self.probe_paths or "").strip()
        if extra:
            for part in extra.split(","):
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
            html = response.text or ""
            if self._looks_like_dfb(html):
                dfb_surface = True
                print_info(f"Divi Form Builder markers at {path}")
            if self._find_nonce(html):
                nonce_found = True
                print_success(f"fb_nonce present at {path}")

        # Asset probe
        asset = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/plugins/{self._PLUGIN_SLUG}/readme.txt"),
            allow_redirects=True,
            timeout=self._timeout(),
        )
        if asset and asset.status_code == 200 and "divi" in (asset.text or "").lower():
            dfb_surface = True
            if not version:
                version = self.wp_extract_version_from_readme(asset.text or "") or version

        if not dfb_surface and not version:
            print_error("Divi Form Builder not detected")
            return False

        print_success("Divi Form Builder surface detected")
        if version:
            print_info(f"Version: {version}")
            vt = self.wp_version_to_tuple(version)
            if vt and vt <= self._MAX_AFFECTED:
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-5118",
                    reason=(
                        f"Divi Form Builder {version} <= 5.1.2 "
                        f"(fb_nonce={'yes' if nonce_found else 'no'})"
                    ),
                )
                print_warning("Version in CVE-2026-5118 affected range")
                return True
            self.set_info(
                severity="info",
                reason=f"Divi Form Builder {version} appears patched (>= 5.1.3)",
            )
            print_success("Version appears patched for CVE-2026-5118")
            return True

        # No version — nonce alone is enough to suggest active exploit path
        if nonce_found:
            self.set_info(
                severity="high",
                cve="CVE-2026-5118",
                reason=(
                    "fb_nonce / Divi Form Builder present; version unknown "
                    "(confirm with auxiliary)"
                ),
                confidence="medium",
            )
            print_warning("Plugin markers + fb_nonce — version unknown")
            return True

        self.set_info(
            severity="medium",
            cve="CVE-2026-5118",
            reason="Divi Form Builder likely present; fb_nonce not found on probed paths",
            confidence="low",
        )
        print_info("Plugin likely present; try more probe_paths or run the auxiliary")
        return True
