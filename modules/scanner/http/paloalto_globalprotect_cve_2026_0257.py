#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Palo Alto GlobalProtect CVE-2026-0257 detection",
        "description": (
            "Fingerprints Palo Alto GlobalProtect and flags PAN-OS versions affected by "
            "CVE-2026-0257 (authentication override cookie forgery). Actual exploitability "
            "also requires authentication override cookies to be enabled and certificate "
            "reuse with the HTTPS service."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-0257",
        "references": [
            "https://security.paloaltonetworks.com/CVE-2026-0257",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0257",
        ],
        "modules": [
            "auxiliary/admin/http/paloalto_globalprotect_cve_2026_0257_auth_bypass",
        ],
        "tags": [
            "web",
            "scanner",
            "paloalto",
            "pan-os",
            "globalprotect",
            "vpn",
            "auth-bypass",
            "cve-2026-0257",
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
                "tech_hints_any": ["globalprotect", "paloalto", "pan-os"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/ssl-vpn/login.esp", "/global-protect/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "globalprotect_cookie"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/paloalto_globalprotect_cve_2026_0257_auth_bypass",
                ],
            },
        },
    }

    port = OptPort(443, "GlobalProtect HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    _PROBE_PATHS = (
        "/ssl-vpn/login.esp",
        "/global-protect/login.esp",
        "/global-protect/portal/portal.esp",
        "/",
    )

    _VERSION_PATTERNS = (
        re.compile(r"PAN-OS\s+([\d.]+(?:-h\d+)?)", re.I),
        re.compile(r'"panos[_-]?version"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"pan-os[^0-9]{0,16}([\d]+\.[\d]+\.[\d]+(?:-h\d+)?)", re.I),
        re.compile(r"globalprotect[^0-9]{0,24}([\d]+\.[\d]+\.[\d]+(?:-h\d+)?)", re.I),
    )

    _FIXED_VERSIONS: Tuple[Tuple[int, int, int, int], ...] = (
        (12, 1, 4, 6),
        (12, 1, 7, 0),
        (11, 2, 4, 17),
        (11, 2, 7, 14),
        (11, 2, 10, 7),
        (11, 2, 12, 0),
        (11, 1, 4, 33),
        (11, 1, 6, 32),
        (11, 1, 7, 6),
        (11, 1, 10, 25),
        (11, 1, 13, 5),
        (11, 1, 15, 0),
        (10, 2, 7, 34),
        (10, 2, 10, 36),
        (10, 2, 13, 21),
        (10, 2, 16, 7),
        (10, 2, 18, 6),
    )

    def _parse_panos_version(self, value: str) -> Optional[Tuple[int, int, int, int]]:
        match = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?", str(value or "").strip(), re.I)
        if not match:
            return None
        return (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4) or 0),
        )

    def _panos_version_patched(self, version: str) -> Optional[bool]:
        parsed = self._parse_panos_version(version)
        if not parsed:
            return None
        major, minor, _, _ = parsed
        if (major, minor) not in {(10, 2), (11, 1), (11, 2), (12, 1)}:
            return None
        return any(
            parsed >= fixed for fixed in self._FIXED_VERSIONS if fixed[0:2] == (major, minor)
        )

    def _extract_panos_version(self, text: str) -> str:
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return match.group(1).strip()
        return ""

    def _looks_like_globalprotect(self, body: str, headers: dict) -> bool:
        text = (body or "").lower()
        markers = (
            "globalprotect",
            "global-protect",
            "ssl-vpn/login.esp",
            "portal-userauthcookie",
            "pan-os",
            "palo alto networks",
        )
        if any(marker in text for marker in markers):
            return True
        blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        return "globalprotect" in blob or "palo alto" in blob

    def run(self):
        detected = False
        version = ""
        evidence_path = ""

        for path in self._PROBE_PATHS:
            response = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=max(int(self.timeout or 10), 10),
            )
            if not response:
                continue

            body = response.text or ""
            headers = dict(response.headers)
            if self._looks_like_globalprotect(body, headers):
                detected = True
                evidence_path = evidence_path or path

            parsed = self._extract_panos_version(body)
            if not parsed:
                parsed = self._extract_panos_version(" ".join(f"{k}: {v}" for k, v in headers.items()))
            if parsed:
                version = parsed
                evidence_path = evidence_path or path

            if detected and version:
                break

        if not detected:
            print_error("GlobalProtect was not detected on the target")
            return False

        patched: Optional[bool] = self._panos_version_patched(version) if version else None
        if patched is True:
            label = version or "detected build"
            self.set_info(
                severity="info",
                reason=f"GlobalProtect detected; PAN-OS {label} appears patched for CVE-2026-0257",
            )
            return False

        reason = f"GlobalProtect detected at {evidence_path or 'HTTPS service'}"
        if version:
            reason = f"GlobalProtect / PAN-OS {version} detected at {evidence_path}"
            if patched is False:
                reason += "; version within CVE-2026-0257 affected range"
            else:
                reason += "; PAN-OS version not mapped to a fixed release"
        else:
            reason += "; PAN-OS version not exposed (active cookie test required)"

        self.set_info(
            severity="critical",
            reason=reason + "; requires auth override cookies + certificate reuse",
        )
        return True
