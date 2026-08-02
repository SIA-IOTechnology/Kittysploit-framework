#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ZoneMinder CVE-2026-27470 detection",
        "description": (
            "Detects ZoneMinder and flags versions affected by CVE-2026-27470 "
            "(second-order SQLi in getNearEvents via stored Event Name/Cause). "
            "Affected: <= 1.36.37 and 1.37.61–1.38.0. Fixed: 1.36.38 / 1.38.1. "
            "Optional credentials enable a light auth probe for Events API access."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-27470",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27470",
            "https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-r6gm-478g-f2c4",
            "https://github.com/d3vn0mi/CVE-2026-27470-POC"],
        "modules": [
            "auxiliary/scanner/http/zoneminder_cve_2026_27470_sqli"],
        "tags": [
            "web",
            "scanner",
            "zoneminder",
            "cctv",
            "sqli",
            "authenticated",
            "cve-2026-27470"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["zoneminder"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/index.php", "/zm/"],
                "param_any": ["request", "entity"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/zoneminder_cve_2026_27470_sqli"],
            },
        },
    }

    port = OptPort(80, "ZoneMinder HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/zm", "ZoneMinder base path (often /zm or /)", required=False)
    username = OptString("", "Optional username for Events API probe", required=False)
    password = OptString("", "Optional password", required=False)

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/")

    def _path(self, suffix: str = "/") -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if base in ("", "/"):
            return suffix
        if suffix == "/":
            return base + "/"
        return base + suffix

    @staticmethod
    def _version_tuple(value: str) -> Optional[Tuple[int, int, int]]:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(value or ""))
        if not match:
            return None
        return int(match.group(1)), int(match.group(2)), int(match.group(3))

    def _is_affected(self, version: str) -> Optional[bool]:
        parsed = self._version_tuple(version)
        if not parsed:
            return None
        # <= 1.36.37
        if parsed[0] == 1 and parsed[1] == 36:
            return parsed[2] <= 37
        if parsed < (1, 36, 0):
            return True
        # 1.37.61 – 1.38.0
        if parsed >= (1, 37, 61) and parsed <= (1, 38, 0):
            return True
        # 1.36.38+ (before 1.37.61) and >= 1.38.1 patched
        return False

    def _looks_like_zoneminder(self, text: str, headers: dict) -> bool:
        lower = (text or "").lower()
        powered = (headers.get("x-powered-by") or "").lower()
        server = (headers.get("server") or "").lower()
        markers = (
            "zoneminder",
            "zmview",
            "zm_version",
            "csrfmagictoken",
            "view=login",
            "zm-login",
        )
        if any(m in lower for m in markers):
            return True
        return "zoneminder" in powered or "zoneminder" in server

    def _extract_version(self, text: str) -> str:
        patterns = (
            r"ZoneMinder\s+(?:v(?:ersion)?\s*)?([\d]+\.[\d]+\.[\d]+)",
            r"ZM_VERSION['\"]?\s*[:=]\s*['\"]?([\d]+\.[\d]+\.[\d]+)",
            r'"version"\s*:\s*"([\d]+\.[\d]+\.[\d]+)"',
            r"v([\d]+\.[\d]+\.[\d]+)\s*—\s*ZoneMinder",
        )
        for pattern in patterns:
            match = re.search(pattern, text or "", re.I)
            if match:
                return match.group(1)
        return ""

    def _extract_csrf(self, text: str) -> str:
        match = re.search(r'csrfMagicToken\s*=\s*["\']([^"\']+)["\']', text or "")
        if match:
            return match.group(1)
        match = re.search(
            r'name=["\']__csrf_magic["\'][^>]*value=["\']([^"\']+)["\']',
            text or "",
            re.I,
        )
        return match.group(1) if match else ""

    def run(self):
        print_status(f"Probing ZoneMinder at {self._path('/')}")

        response = self.http_request(
            method="GET",
            path=self._path("/"),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response:
            # Try /index.php
            response = self.http_request(
                method="GET",
                path=self._path("/index.php"),
                timeout=self._timeout(),
                allow_redirects=True,
            )
        if not response:
            print_info("No HTTP response")
            return False

        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        text = response.text or ""
        if not self._looks_like_zoneminder(text, headers):
            print_info("ZoneMinder fingerprint not found")
            return False

        print_success("ZoneMinder fingerprint matched")
        version = self._extract_version(text)
        if version:
            affected = self._is_affected(version)
            tag = (
                "affected"
                if affected is True
                else "likely patched"
                if affected is False
                else "unknown"
            )
            print_status(f"Version: {version} [{tag}]")
        else:
            print_status("Version unknown")
            affected = None

        username = str(self.username or "").strip()
        password = str(self.password or "")
        events_ok = False
        if username and password:
            csrf = self._extract_csrf(text)
            data = {
                "view": "login",
                "action": "login",
                "username": username,
                "password": password,
            }
            if csrf:
                data["__csrf_magic"] = csrf
            login = self.http_request(
                method="POST",
                path=self._path("/index.php"),
                data=data,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if login and (
                "logout" in (login.text or "").lower()
                or "console" in (getattr(login, "url", "") or "")
            ):
                print_success("Authenticated")
                probe = self.http_request(
                    method="GET",
                    path=self._path("/index.php"),
                    params={
                        "request": "status",
                        "entity": "events",
                        "sort_field": "Id",
                        "sort_asc": "1",
                        "limit": "1",
                    },
                    timeout=self._timeout(),
                )
                if probe and probe.status_code == 200:
                    events_ok = True
                    print_info("Events status API reachable (SQLi carrier possible)")
            else:
                print_warning("Login failed or inconclusive")

        if affected is True:
            reason = (
                f"ZoneMinder {version} in CVE-2026-27470 affected range "
                "(second-order SQLi in getNearEvents)"
            )
            print_warning(reason)
            self.set_info(
                severity="high",
                cve="CVE-2026-27470",
                reason=reason,
                confidence="high" if events_ok else "medium",
                version=version,
                endpoint=self._path("/index.php"),
            )
            return True

        if events_ok:
            self.set_info(
                severity="medium",
                cve="CVE-2026-27470",
                reason=(
                    "ZoneMinder Events API accessible; version not confirmed affected "
                    f"({version or 'unknown'})"
                ),
                confidence="low",
                version=version,
            )
            return True

        self.set_info(
            severity="info",
            cve="CVE-2026-27470",
            reason=f"ZoneMinder detected (version={version or 'unknown'})",
            confidence="low",
            version=version,
        )
        return True
