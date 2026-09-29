#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Acronis Backup plugin CVE-2026-87886 exposure on hosting panels."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Acronis Backup CVE-2026-87886 Detect",
        "description": (
            "Detects Acronis Backup integrations on cPanel/WHM, Plesk, or "
            "DirectAdmin that may be affected by CVE-2026-87886 (insecure file "
            "permissions enabling local privilege escalation). Fingerprints the "
            "plugin surface and parses build numbers against fixed releases "
            "(cPanel < 1.9.3.1021, Plesk < 1.8.11.638, DirectAdmin < 1.2.3.238)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-87886"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-87886",
            "https://security-advisory.acronis.com/advisories/SEC-10986",
        ],
        "tags": [
            "web",
            "scanner",
            "acronis",
            "cpanel",
            "whm",
            "plesk",
            "directadmin",
            "hosting",
            "lpe",
            "cve-2026-87886",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["cpanel", "whm", "plesk", "directadmin", "hosting"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "lpe_surface", "from_detail": "Acronis plugin build"},
                ],
                "suggested_followups": [
                    "scanner/http/whm_login_detect",
                    "scanner/http/plesk_onyx_detect",
                    "scanner/http/directadmin_detect",
                ],
            },
        },
    }

    _BUILD_RE = re.compile(
        r"(?:build|version|release)[^\d]{0,24}(\d+\.\d+\.\d+(?:\.\d+)?)",
        re.IGNORECASE,
    )
    _FIXED = {
        "cpanel": (1, 9, 3, 1021),
        "plesk": (1, 8, 11, 638),
        "directadmin": (1, 2, 3, 238),
    }
    _PROBE_PATHS = (
        ("/cgi/AcronisBackup/index.cgi", "cpanel"),
        ("/3rdparty/acronis/", "cpanel"),
        ("/cgi/acronisbackup/", "cpanel"),
        ("/modules/acronis-backup/", "plesk"),
        ("/smb/web/view/ext/acronis-backup/", "plesk"),
        ("/modules/acronis/", "plesk"),
        ("/CMD_PLUGIN?plugin=acronis", "directadmin"),
        ("/CMD_PLUGINS/acronis/", "directadmin"),
    )

    @staticmethod
    def _parse_build(text: str) -> str:
        match = Module._BUILD_RE.search(text or "")
        return match.group(1) if match else ""

    @staticmethod
    def _build_tuple(build: str) -> tuple[int, ...]:
        parts = re.findall(r"\d+", build or "")
        return tuple(int(p) for p in parts)

    @staticmethod
    def _build_vulnerable(build: str, platform: str) -> bool | None:
        fixed = Module._FIXED.get(platform)
        if not fixed or not build:
            return None
        parsed = Module._build_tuple(build)
        if len(parsed) < len(fixed):
            return None
        return parsed[: len(fixed)] < fixed

    def _panel_kind(self) -> str:
        for path, _ in (("/", "whm"), ("/login_up.php", "plesk"), ("/", "directadmin")):
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            body = (response.text or "").lower()
            if "whm login" in body or "cpanel" in body:
                return "cpanel"
            if "plesk" in body:
                return "plesk"
            if "directadmin login" in body:
                return "directadmin"
        return ""

    def run(self):
        panel = self._panel_kind()
        acronis_hit = ""
        build = ""
        platform = ""

        for path, hint in self._PROBE_PATHS:
            if panel and hint != panel and panel != "cpanel" and hint == "cpanel":
                continue
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) not in (200, 301, 302, 403):
                continue
            body = response.text or ""
            blob = body.lower()
            if "acronis" not in blob and "acronis" not in (response.headers or {}).get(
                "Server", ""
            ).lower():
                continue
            acronis_hit = path
            platform = hint
            build = self._parse_build(body)
            break

        if not acronis_hit:
            for path in ("/", "/login_up.php"):
                response = self.http_request(method="GET", path=path, allow_redirects=True)
                if not response:
                    continue
                body = response.text or ""
                if "acronis" not in body.lower():
                    continue
                acronis_hit = path
                platform = panel or "unknown"
                build = self._parse_build(body)
                break

        if not acronis_hit:
            return False

        affected = self._build_vulnerable(build, platform) if platform in self._FIXED else None
        if affected is False:
            return False

        reason = (
            f"Acronis Backup plugin detected on {platform or 'hosting panel'}"
            + (f" (build {build} appears pre-patch)" if affected else "")
            + "; CVE-2026-87886 requires local low-privilege access to exploit"
        )
        self.set_info(
            severity="high" if affected else "medium",
            cve="CVE-2026-87886",
            reason=reason,
            platform=platform or "unknown",
            build=build or "unknown",
            path=acronis_hit,
        )
        return True
