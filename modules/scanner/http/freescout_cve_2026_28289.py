#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_AFFECTED_MAX = "1.8.206"
_FIXED_VERSION = "1.8.207"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "FreeScout CVE-2026-28289 detection",
        "description": (
            "Fingerprints FreeScout and compares the reported version against "
            f"CVE-2026-28289 (<= {_AFFECTED_MAX}, fixed in {_FIXED_VERSION}). "
            "Optional admin credentials can be used only to read the version from "
            "the authenticated footer. Version check only — no exploitation."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-28289",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-28289",
            "https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-5gpc-65p8-ffwp",
            "https://github.com/freescout-help-desk/freescout/releases/tag/1.8.207",
        ],
        "modules": [],
        "tags": [
            "web",
            "scanner",
            "freescout",
            "laravel",
            "version",
            "cve-2026-28289",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
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
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/login"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(80, "HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "URL path prefix if FreeScout is not at site root", required=False)
    version = OptString(
        "",
        "Known FreeScout version override (e.g. 1.8.206) when auto-detection fails",
        required=False,
        advanced=True,
    )
    email = OptString("", "Optional FreeScout admin email to read footer version", required=False)
    password = OptString("", "Optional FreeScout admin password", required=False)

    _PROBE_REL = ("/", "/login")
    _VERSION_RES = (
        re.compile(
            r"(?:freescout|app\.version|help\s*desk)[^0-9]{0,40}(\d+\.\d+\.\d+)",
            re.I,
        ),
        re.compile(r'["\']version["\']\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']', re.I),
        re.compile(r">\s*(\d+\.\d+\.\d+)\s*<"),
    )
    _FINGERPRINT_MARKERS = (
        "freescout",
        "free open source help desk",
        "shared mailbox",
        "shared inbox",
        "/css/style.css",
        "/js/main.js",
        "/storage/js/vars.js",
        "csrf-token",
    )

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for token in re.findall(r"\d+", value or ""):
            parts.append(int(token))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _version_lte(self, value: str, limit: str) -> bool:
        return self._version_tuple(value) <= self._version_tuple(limit)

    def _normalize_base(self) -> str:
        path = str(self.base_path or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/")

    def _path(self, suffix: str) -> str:
        base = self._normalize_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def _is_vulnerable(self, version: str) -> bool:
        return self._version_lte(version, _AFFECTED_MAX)

    def _looks_like_freescout(self, body: str) -> bool:
        low = (body or "").lower()
        if not low:
            return False
        hits = sum(1 for marker in self._FINGERPRINT_MARKERS if marker in low)
        return hits >= 2 or "freescout" in low

    def _extract_version(self, body: str) -> str:
        text = body or ""
        for pattern in self._VERSION_RES:
            match = pattern.search(text)
            if match:
                return match.group(1).strip()
        return ""

    def _extract_csrf(self, body: str) -> str:
        patterns = (
            re.compile(r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']', re.I),
            re.compile(r'name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.I),
            re.compile(r'content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']', re.I),
        )
        for pattern in patterns:
            match = pattern.search(body or "")
            if match:
                return match.group(1).strip()
        return ""

    def _login_still_on_login(self, response) -> bool:
        if not response:
            return True
        final = urlparse(str(getattr(response, "url", "") or "")).path.rstrip("/")
        return final.endswith("/login") or final.endswith("login")

    def _fetch_authenticated_version(self, timeout: int) -> Optional[str]:
        email = str(self.email or "").strip()
        password = str(self.password or "")
        if not email or not password:
            return None

        login_path = self._path("/login")
        login_page = self.http_request(
            method="GET",
            path=login_path,
            allow_redirects=True,
            timeout=timeout,
        )
        if not login_page or not login_page.text:
            print_warning("Could not load FreeScout login page for authenticated version check")
            return None

        csrf = self._extract_csrf(login_page.text)
        if not csrf:
            print_warning("CSRF token not found on FreeScout login page")
            return None

        login_resp = self.http_request(
            method="POST",
            path=login_path,
            data={"_token": csrf, "email": email, "password": password},
            headers={"Referer": urljoin(str(getattr(login_page, "url", "") or ""), login_path)},
            allow_redirects=True,
            timeout=timeout,
        )
        if not login_resp or self._login_still_on_login(login_resp):
            print_warning("FreeScout login failed; cannot read authenticated version")
            return None

        body = login_resp.text or ""
        # Prefer a second authenticated page where the admin footer is rendered.
        for rel in ("/", "/system/status", "/users/profile"):
            page = self.http_request(
                method="GET",
                path=self._path(rel),
                allow_redirects=True,
                timeout=timeout,
            )
            if page and page.text:
                body += "\n" + page.text

        version = self._extract_version(body)
        if version:
            print_info(f"Authenticated FreeScout version: {version}")
        else:
            print_warning(
                "Login succeeded but version was not found "
                "(admin account required for footer version)"
            )
        return version or None

    def run(self):
        try:
            timeout = max(int(self.timeout or 10), 10)
            detected = False
            evidence_path = ""
            combined = ""

            for rel in self._PROBE_REL:
                path = self._path(rel)
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=timeout,
                )
                if not response or not response.text:
                    continue
                body = response.text
                combined += "\n" + body
                if self._looks_like_freescout(body):
                    detected = True
                    evidence_path = path
                    break

            if not detected:
                return False

            print_success(f"FreeScout detected at {evidence_path}")

            version = str(self.version or "").strip()
            source = "option" if version else ""
            if not version:
                version = self._extract_version(combined)
                if version:
                    source = "public"

            if not version:
                auth_version = self._fetch_authenticated_version(timeout)
                if auth_version:
                    version = auth_version
                    source = "authenticated"

            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-28289",
                    reason=(
                        "FreeScout detected but version could not be extracted; "
                        f"set VERSION or admin EMAIL/PASSWORD to compare against "
                        f"<= {_AFFECTED_MAX}"
                    ),
                    path=evidence_path,
                    confidence="low",
                )
                return True

            print_info(f"FreeScout version {version} ({source})")
            if self._is_vulnerable(version):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-28289",
                    reason=(
                        f"FreeScout {version} is within CVE-2026-28289 range "
                        f"(<= {_AFFECTED_MAX}, fixed in {_FIXED_VERSION})"
                    ),
                    version=version,
                    path=evidence_path,
                    confidence="high" if source in ("option", "authenticated", "public") else "medium",
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"FreeScout {version} detected; appears patched for "
                    f"CVE-2026-28289 (>= {_FIXED_VERSION})"
                ),
                version=version,
                path=evidence_path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
