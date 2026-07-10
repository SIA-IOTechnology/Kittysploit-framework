#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_AJAX_ACTION = "wppb_request_users_pins"
_VULN_HIGH = (3, 14, 5)
_PATCHED = (3, 14, 6)
_PLUGIN_SLUGS = ("profile-builder-pro", "profile-builder")
_POI_PROBE = 'O:8:"stdClass":1:{s:4:"test";s:10:"nuclei-poi";}'


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Profile Builder Pro PHP object injection detection",
        "description": (
            "Detects Profile Builder Pro <= 3.14.5 unauthenticated PHP object injection "
            "via wppb_request_users_pins admin-ajax (args parameter). Optionally sends "
            "a safe stdClass probe; HTTP 500 indicates deserialization of attacker input."
        ),
        "author": ["Mattia Brollo (0xbro)", "KittySploit Team"],
        "severity": "high",
        "references": [
            "https://www.core-jmp.org/blog/exploiting-a-php-object-injection-in-profile-builder-pro-in-the-era-of-ai",
        ],
        "modules": [
            "exploits/multi/http/wp_profile_builder_poi_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "profile-builder",
            "wppb",
            "php-object-injection",
            "deserialization",
            "unauthenticated",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
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
                    {"capability": "ssrf_primitive", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    active_probe = OptBool(
        True,
        "Send stdClass deserialization probe to admin-ajax (HTTP 500 = likely vulnerable)",
        required=False,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch_plugin_info(self) -> Tuple[str, str, str]:
        wp_base = self._wp_base()
        for slug in _PLUGIN_SLUGS:
            version = self.wp_plugin_version(slug, wp_base)
            if version:
                return version, slug, self.wp_plugin_path(wp_base, slug, "readme.txt")

            candidates = [
                self.wp_plugin_path(wp_base, slug, "readme.txt"),
                self.wp_plugin_path(wp_base, slug, f"{slug}.php"),
                self.wp_plugin_path(
                    wp_base,
                    slug,
                    "add-ons/user-listing/one-map-listing.php",
                ),
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
                        return match.group(1).strip(), slug, path
                markers = ("Profile Builder", "profile-builder", "wppb")
                if any(marker.lower() in body.lower() for marker in markers):
                    return "", slug, path
        return "", "", ""

    def _probe_poi(self) -> bool:
        response = self.http_request(
            method="POST",
            path=self._path("/wp-admin/admin-ajax.php"),
            data={
                "action": _AJAX_ACTION,
                "formid": "42",
                "page": "1",
                "totalpages": "3",
                "ititems": "50",
                "args": _POI_PROBE,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            timeout=15,
        )
        if not response:
            return False
        return response.status_code == 500

    def run(self):
        version, slug, evidence_path = self._fetch_plugin_info()
        if not evidence_path:
            self.set_info(severity="info", reason="Profile Builder plugin was not detected")
            return False

        in_range = self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH) if version else None
        poi_positive = self._probe_poi() if self.active_probe else None

        if poi_positive:
            self.set_info(
                severity="critical",
                reason=(
                    f"Profile Builder {version or 'unknown'} ({slug}) at {evidence_path}; "
                    "active POI probe returned HTTP 500 on wppb_request_users_pins"
                ),
                service="wordpress",
                endpoint="/wp-admin/admin-ajax.php",
            )
            return True

        if in_range is True:
            self.set_info(
                severity="high",
                reason=(
                    f"Profile Builder {version} ({slug}) detected at {evidence_path}; "
                    f"<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}.{_VULN_HIGH[2]} is affected by "
                    "unauthenticated PHP object injection (args via admin-ajax)"
                ),
                service="wordpress",
                endpoint="/wp-admin/admin-ajax.php",
            )
            return True

        if in_range is False:
            self.set_info(
                severity="info",
                reason=(
                    f"Profile Builder {version} ({slug}) detected at {evidence_path}; "
                    f"version is above patched threshold ({_PATCHED[0]}.{_PATCHED[1]}.{_PATCHED[2]}+)"
                ),
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            reason=(
                f"Profile Builder plugin detected at {evidence_path} ({slug}), "
                "but version could not be extracted — may be affected"
            ),
            service="wordpress",
            endpoint="/wp-admin/admin-ajax.php",
        )
        return True
